package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
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

// apiTokenPrincipal signs in the request with the API token tok, or
// returns nil.
func (s *Server) apiTokenPrincipal(tok string) *principal {
	if s.SharedUsers == nil || s.SharedUsers.Docs == nil {
		return nil
	}
	b, ok := s.SharedUsers.Docs.LookupAPIToken(tok)
	if !ok {
		return nil
	}
	return &principal{Username: apiTokenUser(b.Name), Name: b.Name, Role: b.Role, Source: "api_token", Method: "token",
		tokenID: b.ID, shared: true}
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
	v := map[string]any{"id": b.ID, "name": b.Name, "role": b.Role, "role_label": b.Role.Label(), "hint": b.Hint,
		"created_by": b.CreatedBy, "created": b.Created, "active": b.Active(), "user": apiTokenUser(b.Name)}
	if b.Revoked != nil {
		v["revoked"], v["revoked_by"] = b.Revoked, b.RevokedBy
	}
	return v
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
		"roles": []users.Role{users.Viewer, users.Analyst}})
}

func (s *Server) handleCreateAPIToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string     `json:"name"`
		Role users.Role `json:"role"`
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
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	b, secret, err := s.SharedUsers.Docs.CreateAPIToken(ctx, userOf(r), req.Name, req.Role, time.Now())
	switch {
	case errors.Is(err, clusterauth.ErrAPITokenName), errors.Is(err, clusterauth.ErrAPITokenRole):
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
	s.audit(r, "api_token.create: API token created", "token", b.Name, "token_id", b.ID, "role", b.Role)
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
