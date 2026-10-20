// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// Senders built for Splunk's HTTP Event Collector (HEC) send to these
// routes on the agent port, with an agent token, once ingest.hec is on.
// The paths and answers are HEC's, so such a sender only needs this
// server's address and a token. See docs/hec.md.
var (
	hecEventRoutes  = []string{"POST /services/collector", "POST /services/collector/event", "POST /services/collector/event/1.0"}
	hecRawRoutes    = []string{"POST /services/collector/raw", "POST /services/collector/raw/1.0"}
	hecHealthRoutes = []string{"GET /services/collector/health", "GET /services/collector/health/1.0"}
	hecAckRoutes    = []string{"POST /services/collector/ack", "POST /services/collector/ack/1.0"}
	hecRoutes       = append(append(append(append([]string{}, hecEventRoutes...), hecRawRoutes...), hecHealthRoutes...), hecAckRoutes...)
)

func (s *Server) routeHEC(mux *http.ServeMux) {
	for _, p := range hecEventRoutes {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { s.handleHEC(w, r, false) })
	}
	for _, p := range hecRawRoutes {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { s.handleHEC(w, r, true) })
	}
	for _, p := range hecHealthRoutes {
		mux.HandleFunc(p, s.handleHECHealth)
	}
	for _, p := range hecAckRoutes {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			if !s.hecOn(w) {
				return
			}
			writeHEC(w, http.StatusBadRequest, ingest.HECAckDisabled, "ACK is disabled", -1)
		})
	}
}

// writeHEC answers as HEC does: {"text": ..., "code": ...}.
func writeHEC(w http.ResponseWriter, status, code int, text string, event int) {
	v := map[string]any{"text": text, "code": code}
	if event >= 0 {
		v["invalid-event-number"] = event
	}
	writeJSON(w, status, v)
}

// hecOn answers a request while the intake is off.
func (s *Server) hecOn(w http.ResponseWriter) bool {
	if s.conf().Ingest.HEC {
		return true
	}
	writeHEC(w, http.StatusForbidden, ingest.HECTokenDisabled,
		"the HTTP Event Collector intake is turned off on this server; an admin turns it on in Settings > General (Splunk HEC senders)", -1)
	return false
}

// hecToken is the agent token of a HEC request: Authorization: Splunk
// <token>, as HEC senders send it, or Bearer <token>.
func hecToken(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !(strings.EqualFold(scheme, "Splunk") || strings.EqualFold(scheme, "Bearer")) {
		return ""
	}
	return strings.TrimSpace(tok)
}

func (s *Server) handleHECHealth(w http.ResponseWriter, r *http.Request) {
	if !s.hecOn(w) {
		return
	}
	writeHEC(w, http.StatusOK, ingest.HECHealthy, "HEC is healthy", -1)
}

// handleHEC takes an /event request (JSON events) or, with raw, a /raw
// one (lines of text, with their metadata in the query string). Like the
// other agent routes it takes the whole body, within the ingest limits,
// before waiting its turn among the senders. Failures a sender should
// retry are 503 with Retry-After; others are 4xx, which HEC senders do not
// send again.
func (s *Server) handleHEC(w http.ResponseWriter, r *http.Request, raw bool) {
	if !s.hecOn(w) {
		return
	}
	from := clientaddr.Parse(r.RemoteAddr)
	if r.URL.Query().Has("token") {
		// A token in the address ends up in proxy and access logs.
		s.Pipeline.NoteRefused(from, ingest.RefusedToken)
		writeHEC(w, http.StatusBadRequest, ingest.HECQueryAuth, "Query string authorization is not enabled; send the token as Authorization: Splunk <token>", -1)
		return
	}
	tok := hecToken(r)
	if tok == "" {
		code, text := ingest.HECTokenRequired, "Token is required"
		if r.Header.Get("Authorization") != "" {
			code, text = ingest.HECInvalidAuth, "Invalid authorization; send Authorization: Splunk <token>"
		}
		s.Pipeline.NoteRefused(from, ingest.RefusedToken)
		writeHEC(w, http.StatusUnauthorized, code, text, -1)
		return
	}
	if t, wait := s.tokenTenant(tok); wait {
		w.Header().Set("Retry-After", tenantAgentRetry)
		writeHEC(w, http.StatusServiceUnavailable, ingest.HECServerBusy, tenantAgentWait, -1)
		return
	} else if t != nil {
		t.handleHEC(w, r, raw)
		return
	}
	who, checked := s.tokens().Check(tok)
	switch checked {
	case agenttokens.Valid:
	case agenttokens.NotLoaded:
		w.Header().Set("Retry-After", "30")
		writeHEC(w, http.StatusServiceUnavailable, ingest.HECServerBusy, msgTokenLoading, -1)
		return
	case agenttokens.Revoked, agenttokens.Refused:
		s.Pipeline.NoteRefused(from, ingest.RefusedRevoked)
		writeHEC(w, http.StatusForbidden, ingest.HECTokenDisabled, "Token disabled", -1)
		return
	default:
		s.Pipeline.NoteRefused(from, ingest.RefusedToken)
		writeHEC(w, http.StatusForbidden, ingest.HECInvalidToken, "Invalid token", -1)
		return
	}
	enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	if enc != "" && enc != "identity" && enc != "gzip" {
		writeHEC(w, http.StatusUnsupportedMediaType, ingest.HECInvalidFormat, "Content-Encoding "+enc+" is not supported; use gzip or none", -1)
		return
	}
	var meta ingest.HECMeta
	if raw {
		q := r.URL.Query()
		meta = ingest.HECMeta{Host: q.Get("host"), Source: q.Get("source"), Sourcetype: q.Get("sourcetype"), Index: q.Get("index")}
	}
	s.noteName(r)
	body, release, err := s.readBatch(w, r)
	if err != nil {
		s.hecFailure(w, r, err)
		return
	}
	defer release()
	if enc == "gzip" {
		sender := netip.Addr{}
		if !clientaddr.Shared(from, s.Config.Server.SharedList()) {
			sender = clientaddr.Key(from)
		}
		var releaseRaw func()
		body, releaseRaw, err = gunzip(s.Pipeline, body, sender)
		if err != nil {
			s.hecFailure(w, r, err)
			return
		}
		defer releaseRaw()
	}
	slot, err := s.Pipeline.Admit(r.Context(), ingestQueueWait, "token:"+who.ID)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		writeHEC(w, http.StatusServiceUnavailable, ingest.HECServerBusy, "Server is busy", -1)
		return
	}
	defer slot()
	ctx := withOrigin(r, ingest.IntakeHEC, who)
	var res *ingest.Result
	if raw {
		res, err = s.Pipeline.IngestHECRaw(ctx, body, meta)
	} else {
		res, err = s.Pipeline.IngestHEC(ctx, body)
	}
	if res != nil {
		s.tokens().Note(who.ID, from.String(), res.Indexed+res.Duplicates)
		s.noteAgent(r, ingest.IntakeHEC, "", who, res.Indexed+res.Duplicates, res.Hosts, nil)
	}
	if err != nil {
		var he *ingest.HECError
		if errors.As(err, &he) {
			writeHEC(w, he.Status, he.Code, he.Text, he.Event)
			return
		}
		s.Log.Error("HEC ingest failed", "err", err, "bytes", len(body))
		w.Header().Set("Retry-After", "5")
		writeHEC(w, http.StatusServiceUnavailable, ingest.HECServerBusy, "Server is busy; events could not be stored right now, send them again later", -1)
		return
	}
	if len(res.Errors) > 0 {
		s.Log.Warn("some HEC events were rejected", "rejected", res.Rejected, "temporary", res.Temporary, "first", res.Errors[0].Reason)
	}
	if res.Temporary > 0 {
		// Sent again, the events already stored count as duplicates.
		w.Header().Set("Retry-After", "30")
		writeHEC(w, http.StatusServiceUnavailable, ingest.HECServerBusy, "Server is busy; some events could not be stored right now, send them again later", -1)
		return
	}
	writeHEC(w, http.StatusOK, ingest.HECSuccess, "Success", -1)
}

// hecFailure answers a body that could not be read or unpacked, as
// batchFailure does for OTLP.
func (s *Server) hecFailure(w http.ResponseWriter, r *http.Request, err error) {
	status, retry, e := s.batchFailure(r, err)
	if retry != "" {
		w.Header().Set("Retry-After", retry)
	}
	code := ingest.HECInvalidFormat
	if status == http.StatusServiceUnavailable {
		code = ingest.HECServerBusy
	}
	writeHEC(w, status, code, e.Error(), -1)
}
