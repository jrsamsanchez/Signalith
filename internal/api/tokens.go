// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/security"
)

// Agent tokens: each agent or group of agents sends with a token of its
// own, made on the Add data page (see internal/agenttokens). The shared
// tokens of the configuration (ingest.tokens, SIGNALITH_INGEST_TOKEN)
// still work.

func (s *Server) routeTokens(api *router) {
	// Analysts see which tokens exist and how they are used; no response
	// holds a token except the one that creates it.
	api.analyst("GET /api/agent-tokens", s.handleListTokens)
	api.sensitive("POST /api/agent-tokens", s.handleCreateToken)
	api.admin("PATCH /api/agent-tokens/{id}", s.handleRenameToken)
	api.admin("POST /api/agent-tokens/{id}/revoke", s.handleRevokeToken)
	api.sensitive("PUT /api/agent-tokens/{id}/collect", s.handleSetCollect)
	api.admin("POST /api/agent-tokens/legacy/{id}/refuse", s.handleRefuseLegacy)
	api.sensitive("POST /api/agent-tokens/legacy/{id}/accept", s.handleAcceptLegacy)
}

// tokens returns the agent tokens in use. Without a registry from the
// caller (tests), one with no OpenSearch is made: only the shared tokens
// of the configuration work then.
func (s *Server) tokens() *agenttokens.Registry {
	s.tokensOnce.Do(func() {
		if s.Tokens == nil {
			s.Tokens = &agenttokens.Registry{Log: s.Log}
		}
		if s.Tokens.Legacy == nil {
			s.Tokens.Legacy = s.legacyTokens
		}
	})
	return s.Tokens
}

// legacyTokens are the shared tokens of the configuration in use.
func (s *Server) legacyTokens() []agenttokens.Legacy {
	return LegacyTokens(s.conf())
}

// LegacyTokens lists the shared agent tokens of c.
func LegacyTokens(c *config.Config) []agenttokens.Legacy {
	out := make([]agenttokens.Legacy, 0, len(c.Ingest.Tokens))
	for i, t := range c.Ingest.Tokens {
		out = append(out, agenttokens.Legacy{Secret: t, Source: c.IngestTokenSource(i), Public: config.IsPublicIngestToken(t)})
	}
	return out
}

// EnrollToken checks an osquery enroll secret: an active agent token, or
// an accepted shared one, gives its ID. A sensor token is refused: it is
// for a network sensor only.
func (s *Server) EnrollToken(secret string) (tokenID string, ok bool) {
	id, res := s.tokens().Check(strings.TrimSpace(secret))
	if res != agenttokens.Valid || id.Purpose == agenttokens.PurposeSensor {
		return "", false
	}
	if id.HostKey != "" {
		// Revoking the computer's key removes its osquery host too.
		return id.HostKey, true
	}
	return id.ID, true
}

// TokenActive reports whether an osquery host enrolled with the token
// tokenID may still send: the token is an active agent token or an
// accepted shared one. Until the tokens are first read from OpenSearch,
// hosts with an agent token are let in, so a restart doesn't make every
// host enroll again.
func (s *Server) TokenActive(tokenID string) bool {
	t := s.tokens()
	return t.Active(tokenID) || !t.Loaded() && t.Name(tokenID) == ""
}

// oldExample is who sends with the example token an older Docker quick
// start gave every agent, while it is accepted (see retiredTokenAccepted).
var oldExample = agenttokens.Identity{ID: agenttokens.IDOf("change-this-ingest-token"), Name: agenttokens.OldExampleName, Legacy: true, Public: true}

// Answers to agents whose token is no longer accepted.
const (
	msgTokenRevoked = "this agent token was revoked; give the agent a new configuration from the Add data page"
	msgTokenRefused = "this shared agent token is no longer accepted; give the agent a new configuration from the Add data page"
	msgTokenLoading = "agent tokens are still loading from OpenSearch; the agent keeps its events and sends them again"
)

// agentRefusal is how to answer an agent token Check did not accept:
// the status, code, message and Retry-After ("" for none). ok is false
// for a token that is simply unknown.
func agentRefusal(res agenttokens.Result) (status int, code, msg, retry string, ok bool) {
	switch res {
	case agenttokens.Revoked:
		return http.StatusUnauthorized, "token_revoked", msgTokenRevoked, "", true
	case agenttokens.Refused:
		return http.StatusUnauthorized, "token_refused", msgTokenRefused, "", true
	case agenttokens.NotLoaded:
		// Never 4xx: Fluent Bit and the Collector drop a batch refused so.
		return http.StatusServiceUnavailable, agenttokens.CodeLoading, msgTokenLoading, "30", true
	}
	return 0, "", "", "", false
}

// agentIdentity checks the token of an agent's request (POST /api/ingest)
// and answers the request when it is refused.
func (s *Server) agentIdentity(w http.ResponseWriter, r *http.Request) (agenttokens.Identity, bool) {
	id, res := s.tokens().Check(bearerToken(r))
	if res == agenttokens.Valid {
		return id, true
	}
	if status, code, msg, retry, ok := agentRefusal(res); ok {
		if res != agenttokens.NotLoaded {
			s.Pipeline.NoteRefused(clientaddr.Parse(r.RemoteAddr), ingest.RefusedRevoked)
		}
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		writeJSON(w, status, map[string]any{"error": msg, "code": code})
		return id, false
	}
	if !s.retiredTokenAccepted(w, r) {
		return id, false
	}
	return oldExample, true
}

// tokenAccepted reports whether r carries a token this server accepts
// (or will, once the tokens are read), for the plain-HTTP handler.
func (s *Server) tokenAccepted(r *http.Request) bool {
	_, res := s.tokens().Check(bearerToken(r))
	return res == agenttokens.Valid || res == agenttokens.NotLoaded
}

// withOrigin returns the context of an agent's request with where its
// events come from.
func withOrigin(r *http.Request, intake string, id agenttokens.Identity) context.Context {
	o := ingest.Origin{Intake: intake, TokenID: id.ID, TokenName: id.Name, Sender: clientaddr.Parse(r.RemoteAddr).String()}
	if !id.Legacy {
		o.Purpose = id.Purpose
	}
	return ingest.WithOrigin(r.Context(), o)
}

// TokenFacts are the agent tokens for the Security page's checks.
func TokenFacts(ctx context.Context, t *agenttokens.Registry) *security.AgentTokenFacts {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l := t.List(ctx)
	f := &security.AgentTokenFacts{Loaded: l.Loaded}
	for _, tok := range l.Tokens {
		if tok.Status == agenttokens.StateActive {
			f.Active++
		}
	}
	for _, lt := range l.Legacy {
		lf := security.LegacyTokenFact{ID: lt.ID, Name: lt.Name, Source: lt.Source, Public: lt.Public, Refused: lt.Status == "refused", Length: lt.Length}
		if lt.LastUsedAt != nil {
			lf.LastUsed = *lt.LastUsedAt
		}
		f.Legacy = append(f.Legacy, lf)
	}
	return f
}

// ---- admin routes ----

// writeTokenError answers a refused change to the tokens.
func (s *Server) writeTokenError(w http.ResponseWriter, err error) {
	var e *agenttokens.Error
	if !errors.As(err, &e) {
		s.Log.Error("agent token change failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "the agent tokens could not be changed; see the server log"})
		return
	}
	if e.Err != nil {
		s.Log.Warn("agent token change failed", "code", e.Code, "err", e.Err)
	}
	body := map[string]any{"error": e.Msg, "code": e.Code}
	if e.Field != "" {
		body["field"] = e.Field
	}
	if e.Status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "5")
	}
	writeJSON(w, e.Status, body)
}

// maxTokenBody caps the body of a token change.
const maxTokenBody = 4 << 10

// readTokenBody reads a small JSON body into v, answering 413 or 400.
func readTokenBody(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTokenBody))
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "the request is larger than 4 KB"})
		return false
	case err != nil:
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return true
	}
	if err := json.Unmarshal(b, v); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("request body must be JSON: "+err.Error()))
		return false
	}
	return true
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.tokens().List(ctx))
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Purpose string `json:"purpose"`
	}
	if !readTokenBody(w, r, &req) {
		return
	}
	if wait := s.tokenRate.take(userOf(r), time.Now()); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "Too many tokens created just now. Try again in a minute.", "code": "rate_limited"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	tok, secret, err := s.tokens().Create(ctx, req.Name, req.Purpose, userOf(r))
	if err != nil {
		s.writeTokenError(w, err)
		return
	}
	s.audit(r, "agent token created", "token_id", tok.ID, "token_name", tok.Name, "purpose", tok.Purpose)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "secret": secret})
}

func (s *Server) handleRenameToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !readTokenBody(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	tok, old, err := s.tokens().Rename(ctx, r.PathValue("id"), req.Name, userOf(r))
	if err != nil {
		s.writeTokenError(w, err)
		return
	}
	if old != tok.Name {
		s.audit(r, "agent token renamed", "token_id", tok.ID, "old_name", old, "token_name", tok.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if !readTokenBody(w, r, &struct{}{}) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	tok, hosts, err := s.tokens().Revoke(ctx, r.PathValue("id"), userOf(r))
	if err != nil {
		s.writeTokenError(w, err)
		return
	}
	s.audit(r, "agent token revoked", "token_id", tok.ID, "token_name", tok.Name, "hosts_removed", hosts)
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "hosts_removed": hosts})
}

// handleSetCollect sets what the Signalith Agents of an install line
// collect (the Endpoints page's agent settings).
func (s *Server) handleSetCollect(w http.ResponseWriter, r *http.Request) {
	var req agenttokens.Collect
	if !readStrictTokenBody(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	tok, old, err := s.tokens().SetCollect(ctx, r.PathValue("id"), req, userOf(r))
	if err != nil {
		s.writeTokenError(w, err)
		return
	}
	if tok.Collect != nil && old != *tok.Collect {
		s.audit(r, "agent collection settings changed", "token_id", tok.ID, "token_name", tok.Name,
			"old", collectSummary(old), "new", collectSummary(*tok.Collect))
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok})
}

// collectSummary is a Collect for the audit log, as on/off words.
func collectSummary(c agenttokens.Collect) string {
	onOff := func(v string) string {
		if v == agenttokens.CollectOff {
			return "off"
		}
		return "on"
	}
	linux := c.LinuxLog
	if linux == "" {
		linux = "auto"
	}
	share := c.UpdateShare
	if share == "" {
		share = "100"
	}
	silent := c.SilentAlert
	if silent == "" {
		silent = "1h"
	}
	return "osquery=" + onOff(c.Osquery) + " sysmon=" + onOff(c.Sysmon) + " powershell=" + onOff(c.PowerShell) +
		" linux_log=" + linux + " web_logs=" + onOff(c.WebLogs) + " audit_log=" + onOff(c.AuditLog) + " updates=" + onOff(c.Updates) +
		" update_share=" + share + " silent_alert=" + silent
}

// readStrictTokenBody is readTokenBody refusing fields v does not have,
// so a misspelt setting is not quietly left at its default.
func readStrictTokenBody(w http.ResponseWriter, r *http.Request, v any) bool {
	var raw json.RawMessage
	if !readTokenBody(w, r, &raw) {
		return false
	}
	if len(raw) == 0 {
		return true
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("request body: "+err.Error()))
		return false
	}
	return true
}

func (s *Server) handleRefuseLegacy(w http.ResponseWriter, r *http.Request) {
	if !readTokenBody(w, r, &struct{}{}) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	lt, hosts, err := s.tokens().Refuse(ctx, r.PathValue("id"), userOf(r))
	if err != nil {
		s.writeTokenError(w, err)
		return
	}
	s.audit(r, "shared agent token refused", "token_id", lt.ID, "token_name", lt.Name, "source", lt.Source, "hosts_removed", hosts)
	writeJSON(w, http.StatusOK, map[string]any{"legacy": lt, "hosts_removed": hosts})
}

func (s *Server) handleAcceptLegacy(w http.ResponseWriter, r *http.Request) {
	if !readTokenBody(w, r, &struct{}{}) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	lt, err := s.tokens().Accept(ctx, r.PathValue("id"), userOf(r))
	if err != nil {
		s.writeTokenError(w, err)
		return
	}
	s.audit(r, "shared agent token accepted again", "token_id", lt.ID, "token_name", lt.Name, "source", lt.Source)
	writeJSON(w, http.StatusOK, map[string]any{"legacy": lt})
}

// tokenRate limits token creation: 10 a minute per user, 200 an hour on
// this server. Each, Per, All and AllPer change those numbers when set;
// the demo's visitor sign-ins use them (see demoRate).
type tokenRate struct {
	// Each is how many one key may take within Per, and All how many
	// every key together may take within AllPer.
	Each, All   int
	Per, AllPer time.Duration

	mu     sync.Mutex
	byUser map[string][]time.Time
	all    []time.Time
}

// take counts one creation by user at now, or returns how long to wait.
// An empty user counts only toward the whole server's limit.
func (t *tokenRate) take(user string, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	each, per, all, allPer := cmp.Or(t.Each, 10), cmp.Or(t.Per, time.Minute), cmp.Or(t.All, 200), cmp.Or(t.AllPer, time.Hour)
	if t.byUser == nil {
		t.byUser = map[string][]time.Time{}
	}
	keep := func(ts []time.Time, window time.Duration) []time.Time {
		out := ts[:0]
		for _, x := range ts {
			if now.Sub(x) < window {
				out = append(out, x)
			}
		}
		return out
	}
	if len(t.byUser) > 2*all {
		// Keys not seen for a while go, so many keys never pile up.
		for k, ts := range t.byUser {
			if kept := keep(ts, per); len(kept) == 0 {
				delete(t.byUser, k)
			} else {
				t.byUser[k] = kept
			}
		}
	}
	mine := keep(t.byUser[user], per)
	t.all = keep(t.all, allPer)
	if len(mine) == 0 {
		delete(t.byUser, user)
	}
	switch {
	case user != "" && len(mine) >= each:
		t.byUser[user] = mine
		return per - now.Sub(mine[0])
	case len(t.all) >= all:
		return allPer - now.Sub(t.all[0])
	}
	if user == "" {
		t.all = append(t.all, now)
		return 0
	}
	t.byUser[user] = append(mine, now)
	t.all = append(t.all, now)
	return 0
}
