// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/security"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// API tokens (clusterauth.APITokenBody) sign a program in, such as the
// read-only AI tools server: Authorization: Bearer sgl_api_<52>. A
// request signed in with one reads as the token's role (viewer or
// analyst) but can only read, whatever the route allows that role: it
// may use only the routes of tokenRoutes.

// tokenRoutes are the only routes an API token may use, each checked to
// change nothing: the GET routes a viewer or an analyst may use, a
// search (which runs a query) and parse (which checks one). Every other
// route, including a new one, is refused to tokens until someone checks
// it only reads and lists it here; TestTokenRoutesOnlyRead fails until
// a new viewer or analyst GET route is listed here or in its list of
// routes kept from tokens. internal/mcp's client sends nothing else.
// Running a response action or approving a playbook step is not here:
// those need a person, who enters the password or code again.
var tokenRoutes = map[string]bool{
	"POST /api/search":                 true,
	"POST /api/parse":                  true,
	"GET /api/agent-hosts":             true,
	"GET /api/agent-tokens":            true,
	"GET /api/agents":                  true,
	"GET /api/ask":                     true,
	"GET /api/case-templates":          true,
	"GET /api/cases":                   true,
	"GET /api/cases/reports/keys":      true,
	"GET /api/cases/summary":           true,
	"GET /api/cases/{id}":              true,
	"GET /api/cases/{id}/files/{file}": true,
	"GET /api/cases/{id}/report":       true,
	"GET /api/cases/{id}/tickets":      true,
	"GET /api/chat/accounts":           true,
	"GET /api/cluster/features":        true,
	"GET /api/compliance":              true,
	"GET /api/compliance/export":       true,
	"GET /api/compliance/history":      true,
	"GET /api/compliance/history/{id}": true,
	"GET /api/coverage":                true,
	"GET /api/dashboards":              true,
	"GET /api/dashboards/{id}":         true,
	"GET /api/dashboards/{id}/yaml":    true,
	"GET /api/datamodels":              true,
	"GET /api/detections":              true,
	"GET /api/detections/content":      true,
	"GET /api/detections/exceptions":   true,
	"GET /api/detections/packs":        true,
	"GET /api/detections/{id}":         true,
	"GET /api/detections/{id}/yaml":    true,
	"GET /api/endpoints":               true,
	"GET /api/endpoints/checks":        true,
	"GET /api/endpoints/settings":      true,
	"GET /api/endpoints/{id}":          true,
	"GET /api/exception-requests":      true,
	"GET /api/fields":                  true,
	"GET /api/fields/values":           true,
	"GET /api/findings":                true,
	"GET /api/findings/summary":        true,
	"GET /api/findings/{id}":           true,
	"GET /api/health":                  true,
	"GET /api/intel":                   true,
	"GET /api/intel/catalog":           true,
	"GET /api/intel/feeds":             true,
	"GET /api/intel/indicators":        true,
	"GET /api/intel/lookup":            true,
	"GET /api/investigate":             true,
	"GET /api/language":                true,
	"GET /api/lookups/context":         true,
	"GET /api/lookups/{kind}":          true,
	"GET /api/lookuptables":            true,
	"GET /api/lookuptables/{name}":     true,
	"GET /api/me":                      true,
	"GET /api/me/finding-views":        true,
	"GET /api/me/mfa":                  true,
	"GET /api/me/setup":                true,
	"GET /api/notebooks":               true,
	"GET /api/notebooks/{id}":          true,
	"GET /api/notebooks/{id}/markdown": true,
	"GET /api/playbooks/runs":          true,
	"GET /api/posture":                 true,
	"GET /api/respond/actions":         true,
	"GET /api/respond/runs":            true,
	"GET /api/risk":                    true,
	"GET /api/risk/object":             true,
	"GET /api/storyline":               true,
	"GET /api/tenants":                 true,
	"GET /api/vulns":                   true,
	"GET /api/vulns/hosts/{id}":        true,
}

// apiTokenUser is the name requests signed in with the token named name
// run as, in the audit log and the search slots. Usernames hold no colon,
// so it is never a user's.
func apiTokenUser(name string) string { return "api-token:" + name }

// tokenMayUse reports whether a request signed in with an API token may
// use route rt. A "GET" route also answers HEAD.
func tokenMayUse(rt route) bool { return tokenRoutes[rt.Pattern] }

// bearerAPIToken returns the API token of the Authorization header, ""
// when it carries none.
func bearerAPIToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return ""
	}
	tok = strings.TrimSpace(tok)
	if !strings.HasPrefix(tok, clusterauth.APITokenPrefix) {
		return ""
	}
	return tok
}

// apiTokenPrincipal signs in the request r with the API token tok, or
// returns nil. A revoked or expired token is logged for the audit, once
// an hour per token on each server, so a forgotten program does not fill
// the log. An accepted one has its last use recorded (see
// clusterauth.NoteAPITokenUse), off the request's path.
func (s *Server) apiTokenPrincipal(r *http.Request, tok string) *principal {
	if s.SharedUsers == nil || s.SharedUsers.Docs == nil {
		return nil
	}
	docs, now := s.SharedUsers.Docs, time.Now()
	b, ok := docs.LookupAPIToken(tok, now)
	if !ok {
		if b.ID != "" {
			s.tokenRefused(r, b, now)
		}
		return nil
	}
	if docs.APITokenUseDue(&b, now) {
		s.background.Add(1)
		go func() {
			defer s.background.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := docs.NoteAPITokenUse(ctx, b.ID, now); err != nil {
				s.Log.Warn("could not record when an API token was last used", "token", b.Name, "token_id", b.ID, "err", err)
			}
		}()
	}
	return &principal{Username: apiTokenUser(b.Name), Name: b.Name, Role: b.Role, Source: "api_token", Method: "token",
		tokenID: b.ID, shared: true}
}

// tokensMadeBy lists the API tokens user made that still work. A token is
// an account of its own and keeps working when the admin who made it is
// turned off or deleted (AUTHRT-09): the audit record and the answer of
// that change name them, so another admin can revoke them.
func (s *Server) tokensMadeBy(user string) []map[string]any {
	if s.SharedUsers == nil || s.SharedUsers.Docs == nil || user == "" {
		return nil
	}
	now := time.Now()
	var out []map[string]any
	for _, b := range s.SharedUsers.Docs.APITokens() {
		if b.Active(now) && strings.EqualFold(b.CreatedBy, user) {
			out = append(out, map[string]any{"id": b.ID, "name": b.Name, "role": b.Role})
		}
	}
	return out
}

// noteTokensKept adds to a "user disabled" or "user deleted" answer, and
// writes in the audit log, the API tokens user made that keep working.
func (s *Server) noteTokensKept(r *http.Request, user string, out map[string]any) {
	list := s.tokensMadeBy(user)
	if len(list) == 0 {
		return
	}
	names := make([]string, 0, len(list))
	for _, t := range list {
		names = append(names, t["name"].(string))
	}
	s.audit(r, "api_token.kept: API tokens this user made keep working; revoke them on the API tokens tab if they should stop",
		"user", user, "tokens", strings.Join(names, ","), "count", len(list))
	out["api_tokens"] = list
}

// tokenRefused logs that the revoked or expired token b was sent.
func (s *Server) tokenRefused(r *http.Request, b clusterauth.APITokenBody, now time.Time) {
	s.refusedMu.Lock()
	if s.refused == nil {
		s.refused = map[string]time.Time{}
	}
	last, seen := s.refused[b.ID]
	if seen && now.Sub(last) < time.Hour {
		s.refusedMu.Unlock()
		return
	}
	for id, t := range s.refused {
		if now.Sub(t) >= time.Hour {
			delete(s.refused, id)
		}
	}
	s.refused[b.ID] = now
	s.refusedMu.Unlock()
	reason := "revoked"
	if b.Revoked == nil {
		reason = "expired"
	}
	s.Log.Warn("api_token.refused: a "+reason+" API token was used", slices.Concat([]any{"audit", true, "token", b.Name, "token_id", b.ID,
		"reason", reason, "user", apiTokenUser(b.Name)}, s.client(r).logAttrs())...)
}

func (s *Server) routeAPITokens(api *router) {
	api.admin("GET /api/api-tokens", s.handleListAPITokens)
	api.sensitive("POST /api/api-tokens", s.handleCreateAPIToken)
	api.admin("POST /api/api-tokens/{id}/revoke", s.handleRevokeAPIToken)
}

// apiTokensOff says why API tokens cannot be made on this server now, ""
// when they can.
func (s *Server) apiTokensOff() string {
	if s.SharedUsers == nil || s.SharedUsers.Docs == nil {
		return "API tokens are kept in the shared settings in OpenSearch, so every server accepts them. This server doesn't use them now: check the Servers tab."
	}
	if s.SharedUsers.APITokens != nil {
		return s.SharedUsers.APITokens()
	}
	return ""
}

// apiTokenView is a token as the API shows it: never its secret or
// fingerprint.
func apiTokenView(b clusterauth.APITokenBody) map[string]any {
	now := time.Now()
	v := map[string]any{"id": b.ID, "name": b.Name, "role": b.Role, "role_label": b.Role.Label(), "hint": b.Hint,
		"created_by": b.CreatedBy, "created": b.Created, "active": b.Active(now), "user": apiTokenUser(b.Name),
		"expires": b.Expires, "expired": b.Expired(now), "last_used": b.LastUsed}
	if b.Revoked != nil {
		v["revoked"], v["revoked_by"] = b.Revoked, b.RevokedBy
	}
	return v
}

// apiTokenFacts are the API tokens for the security checks, nil without
// shared users.
func (s *Server) apiTokenFacts(now time.Time) *security.APITokenFacts {
	if s.SharedUsers == nil || s.SharedUsers.Docs == nil {
		return nil
	}
	f := &security.APITokenFacts{}
	for _, b := range s.SharedUsers.Docs.APITokens() {
		if !b.Active(now) {
			continue
		}
		f.Active++
		if b.Expires == nil {
			f.NeverExpire = append(f.NeverExpire, b.Name)
		}
	}
	return f
}

func (s *Server) handleListAPITokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	off := s.apiTokensOff()
	out := []map[string]any{}
	if s.SharedUsers != nil && s.SharedUsers.Docs != nil {
		for _, b := range s.SharedUsers.Docs.APITokens() {
			out = append(out, apiTokenView(b))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"on": off == "", "off": off, "tokens": out,
		"roles": []users.Role{users.Viewer, users.Analyst}, "default_days": clusterauth.DefaultAPITokenDays, "max_days": clusterauth.MaxAPITokenDays})
}

func (s *Server) handleCreateAPIToken(w http.ResponseWriter, r *http.Request) {
	// ExpiresInDays is how long the token lasts, DefaultAPITokenDays when
	// left out; Never makes one that never expires, which must be asked
	// for on its own.
	var req struct {
		Name          string     `json:"name"`
		Role          users.Role `json:"role"`
		ExpiresInDays *int       `json:"expires_in_days"`
		Never         bool       `json:"never"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if off := s.apiTokensOff(); off != "" {
		writeError(w, http.StatusServiceUnavailable, errors.New(off))
		return
	}
	if req.Role == "" {
		req.Role = users.Viewer
	}
	req.Name = strings.TrimSpace(req.Name)
	days := clusterauth.DefaultAPITokenDays
	switch {
	case req.Never && req.ExpiresInDays != nil && *req.ExpiresInDays != 0:
		writeError(w, http.StatusBadRequest, errors.New("choose a number of days or never, not both"))
		return
	case req.Never:
		days = 0
	case req.ExpiresInDays != nil:
		// 0 days would mean never: that is asked for with never.
		if days = *req.ExpiresInDays; days == 0 {
			writeError(w, http.StatusBadRequest, clusterauth.ErrAPITokenExpiry)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	b, secret, err := s.SharedUsers.Docs.CreateAPIToken(ctx, userOf(r), req.Name, req.Role, days, time.Now())
	switch {
	case errors.Is(err, clusterauth.ErrAPITokenName), errors.Is(err, clusterauth.ErrAPITokenRole), errors.Is(err, clusterauth.ErrAPITokenExpiry):
		writeError(w, http.StatusBadRequest, err)
		return
	case errors.Is(err, clusterauth.ErrAPITokenTaken), errors.Is(err, clusterauth.ErrAPITokenMany), errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, err)
		return
	case err != nil:
		if !sharedError(w, err) {
			writeError(w, http.StatusServiceUnavailable, err)
		}
		return
	}
	expires := "never"
	if b.Expires != nil {
		expires = b.Expires.Format(time.RFC3339)
	}
	s.audit(r, "api_token.create: API token created", "token", b.Name, "token_id", b.ID, "role", b.Role, "expires", expires)
	w.Header().Set("Cache-Control", "no-store")
	v := apiTokenView(b)
	v["token"] = secret
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) handleRevokeAPIToken(w http.ResponseWriter, r *http.Request) {
	if s.SharedUsers == nil || s.SharedUsers.Docs == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New(s.apiTokensOff()))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	b, err := s.SharedUsers.Docs.RevokeAPIToken(ctx, userOf(r), r.PathValue("id"), time.Now())
	switch {
	case errors.Is(err, clusterauth.ErrAPITokenMissing):
		writeError(w, http.StatusNotFound, err)
		return
	case err != nil:
		if !sharedError(w, err) {
			writeError(w, http.StatusServiceUnavailable, err)
		}
		return
	}
	s.audit(r, "api_token.revoke: API token revoked", "token", b.Name, "token_id", b.ID)
	writeJSON(w, http.StatusOK, apiTokenView(b))
}
