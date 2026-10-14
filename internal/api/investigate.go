package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/investigate"
	"github.com/jrsamsanchez/signalith/internal/respond"
)

// maxInvestigations is how many Investigate with AI runs one server
// takes at once; each holds a few searches and a model conversation.
const maxInvestigations = 3

// investigateTimeout bounds one investigation, model turns included.
const investigateTimeout = 6 * time.Minute

// investigations counts the runs in progress on this server.
var investigations atomic.Int32

func (s *Server) routeInvestigate(api *router) {
	// Investigate with AI sends event data to a paid or outside model,
	// so it is for analysts, and only once an admin turns it on.
	api.analyst("GET /api/investigate", s.handleInvestigateInfo)
	api.analyst("POST /api/findings/{id}/investigate/preview", s.handleInvestigatePreview)
	api.analyst("POST /api/findings/{id}/investigate", s.handleInvestigate)
}

// investigateState says whether Investigate with AI can run, and if not,
// why, in words for the page.
func (s *Server) investigateState() (ok bool, code, why string) {
	switch {
	case s.model() == nil:
		return false, "no_model", "No AI model is set up. An admin sets one up in Settings, under AI assistant."
	case !s.conf().Assistant.Investigate:
		return false, "off", "Investigate with AI is off. An admin turns it on in Settings, under AI assistant."
	case s.Engine == nil:
		return false, "no_search", "Search is not available on this server."
	}
	return true, "", ""
}

func (s *Server) handleInvestigateInfo(w http.ResponseWriter, r *http.Request) {
	ok, code, why := s.investigateState()
	c := s.conf()
	resp := map[string]any{"enabled": ok, "code": code, "reason": why,
		"masked": investigate.NewMasker(c.Assistant.MaskFields).Fields(),
		"limits": map[string]int{"rounds": investigate.MaxRounds, "searches": investigate.MaxSearches, "rows": investigate.RowsSent}}
	if m := s.model(); m != nil {
		resp["model"] = m.Name()
		resp["sent_to"] = config.Origin(m.URL)
		resp["local"] = isLocalModel(m.URL)
	}
	writeJSON(w, http.StatusOK, resp)
}

// isLocalModel reports whether the model runs on a private or loopback
// address, so event data stays on the network.
func isLocalModel(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || h == "host.docker.internal" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && (a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast())
}

// investigator builds an Investigator for a request, or answers the
// request with why it cannot run.
func (s *Server) investigator(w http.ResponseWriter, r *http.Request) (*investigate.Investigator, *findings.Finding, bool) {
	if !s.detectionsReady(w) {
		return nil, nil, false
	}
	if ok, code, why := s.investigateState(); !ok {
		writeJSON(w, http.StatusConflict, map[string]any{"error": why, "code": code})
		return nil, nil, false
	}
	f, err := s.Findings.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, findings.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return nil, nil, false
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return nil, nil, false
	}
	m := s.model()
	if m == nil { // turned off a moment ago
		writeJSON(w, http.StatusConflict, map[string]any{"error": "No AI model is set up.", "code": "no_model"})
		return nil, nil, false
	}
	inv := &investigate.Investigator{Model: m, Search: s.Engine, Findings: s.Findings, Intel: s.Intel,
		Mask: s.conf().Assistant.MaskFields}
	if s.Respond != nil {
		var list []respond.Info
		if list, err = s.Respond.Infos(); err == nil {
			inv.Actions = list
		}
	}
	return inv, f, true
}

// handleInvestigatePreview gathers the evidence and returns the first
// message exactly as it would be sent, without sending anything.
func (s *Server) handleInvestigatePreview(w http.ResponseWriter, r *http.Request) {
	inv, f, ok := s.investigator(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	p, err := inv.Preview(ctx, f)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"preview": p})
}

// handleInvestigate runs an investigation, streaming its progress as
// one JSON object per line: status and step events while it works, then
// a result or an error.
func (s *Server) handleInvestigate(w http.ResponseWriter, r *http.Request) {
	inv, f, ok := s.investigator(w, r)
	if !ok {
		return
	}
	if investigations.Add(1) > maxInvestigations {
		investigations.Add(-1)
		writeError(w, http.StatusTooManyRequests, errors.New("too many investigations are running on this server; try again in a minute"))
		return
	}
	defer investigations.Add(-1)

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // let progress through nginx as it happens
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	enc := json.NewEncoder(w)
	send := func(e investigate.Event) {
		_ = enc.Encode(e)
		_ = rc.Flush()
	}

	ctx, cancel := context.WithTimeout(r.Context(), investigateTimeout)
	defer cancel()
	var sentTo string
	if c, ok := inv.Model.(*assistant.Client); ok {
		sentTo = config.Origin(c.URL)
	}
	res, err := inv.Run(ctx, f, send)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			err = errors.New("the investigation took too long and was stopped; try again, or use a faster model")
		}
		s.Log.Warn("Investigate with AI failed", "audit", true, "by", userOf(r), "finding", f.ID, "model", inv.Model.Name(), "sent_to", sentTo, "err", err)
		send(investigate.Event{Type: "error", Text: err.Error()})
		return
	}
	searches := 0
	for _, st := range res.Steps {
		if st.By == "ai" {
			searches++
		}
	}
	s.Log.Info("finding investigated with AI", "audit", true, "by", userOf(r), "finding", f.ID, "model", res.Model, "sent_to", sentTo,
		"chars_sent", res.Sent, "ai_searches", searches, "verdict", res.Verdict)
	send(investigate.Event{Type: "result", Result: res})
}
