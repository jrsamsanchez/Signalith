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
// request signed in with one reads as the token's role but can only
// read, whatever the route allows that role: GET and HEAD, and POST only
// to tokenPosts.

// tokenPosts are the only POST routes an API token may use; each only
// reads (a search runs a query, parse checks one). internal/mcp's client
// sends nothing else.
var tokenPosts = map[string]bool{
	"POST /api/search": true,
	"POST /api/parse":  true,
}

// apiTokenUser is the name requests signed in with the token named name
// run as, in the audit log and the search slots. Usernames hold no colon,
// so it is never a user's.
func apiTokenUser(name string) string { return "api-token:" + name }

// tokenMayUse reports whether a request signed in with an API token may
// do what r asks.
func tokenMayUse(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return true
	case http.MethodPost:
		return tokenPosts[r.Method+" "+r.URL.Path]
	}
	return false
}

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
