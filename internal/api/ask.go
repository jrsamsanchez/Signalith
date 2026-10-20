// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/nlq"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// aiThreshold is the translator confidence below which "auto" asks the AI
// model, when one is configured.
const aiThreshold = 0.8

// askExamples are shown under the Ask box.
var askExamples = []string{
	"failed logins in the last 24 hours",
	"top 10 users with failed logins",
	"users who logged in to more than 3 hosts today",
	"powershell executed on any host this week",
	"blocked connections by source ip",
	"accounts created yesterday",
	"which hosts have the highest risk score",
}

func (s *Server) routeAsk(api *router) {
	api.viewer("GET /api/ask", s.handleAskInfo)
	// The Ask box can call a paid AI model, so it is for analysts.
	api.analyst("POST /api/ask", s.handleAsk)
}

func (s *Server) handleAskInfo(w http.ResponseWriter, r *http.Request) {
	ai := s.model()
	resp := map[string]any{"ai_available": ai != nil, "examples": askExamples}
	if ai != nil {
		resp["ai_model"] = ai.Name()
	}
	writeJSON(w, http.StatusOK, resp)
}

type askRequest struct {
	Question string `json:"question"`
	// Mode is "auto" (default: the built-in translator, then the AI model
	// when it is unsure), "rules" or "ai".
	Mode string `json:"mode"`
}

// handleAsk turns a plain-English question into a query without running it,
// so the analyst sees and can edit the query first.
func (s *Server) handleAsk(w http.ResponseWriter, r *http.Request) {
	var req askRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Question = strings.TrimSpace(req.Question)
	if len(req.Question) > 1000 {
		writeError(w, http.StatusBadRequest, errors.New("keep the question under 1000 characters"))
		return
	}
	switch req.Mode {
	case "", "auto", "rules", "ai":
	default:
		writeError(w, http.StatusBadRequest, errors.New("mode must be auto, rules or ai"))
		return
	}
	ai := s.model()
	if req.Mode == "ai" && ai == nil {
		writeError(w, http.StatusBadRequest, errors.New("no AI model is configured; set one up on the Settings page"))
		return
	}
	var hints nlq.Hints
	if s.Assets != nil {
		hints = AssetHints{A: s.Assets}
	}
	res, err := nlq.Translate(req.Question, hints)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	resp := map[string]any{
		"query": res.Query, "source": "rules", "steps": res.Steps, "unknown": res.Unknown,
		"confidence": res.Confidence, "ai_available": ai != nil,
	}
	useAI := ai != nil && (req.Mode == "ai" || (req.Mode != "rules" && res.Confidence < aiThreshold))
	if useAI {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		q, err := ai.Translate(ctx, req.Question, res.Query)
		sentTo := config.Origin(ai.URL)
		if err != nil {
			s.Log.Warn("AI query translation failed", "audit", true, "by", userOf(r), "model", ai.Name(), "sent_to", sentTo, "err", err)
			resp["ai_error"] = err.Error()
		} else {
			resp["query"], resp["source"], resp["ai_model"] = q, "ai", ai.Name()
			s.Log.Info("question translated with AI", "audit", true, "by", userOf(r), "model", ai.Name(), "sent_to", sentTo, "chars_sent", len(req.Question)+len(res.Query))
		}
	}
	if q, err := query.Parse(resp["query"].(string)); err == nil {
		resp["query"] = q.String()
		resp["explanation"] = Explain(q)
	}
	writeJSON(w, http.StatusOK, resp)
}

// AssetHints lets the translator recognize bare user and host names from
// the asset and identity lists.
type AssetHints struct{ A *assets.Store }

func (h AssetHints) KnownUser(v string) bool {
	c, ok := h.A.Lookup("user", v)
	return ok && c.Kind == "identity"
}

func (h AssetHints) KnownHost(v string) bool {
	c, ok := h.A.Lookup("dest", v)
	return ok && c.Kind == "asset"
}
