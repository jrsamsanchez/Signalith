// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// The signed-in user's own sessions, and an admin's way to end every
// session of another user without disabling them. A session is named by
// a hash (auth.Info.ID), never by its token.
func (s *Server) routeSessions(api *router) {
	api.self("GET /api/me/sessions", s.handleListMySessions)
	api.self("DELETE /api/me/sessions", s.handleEndMyOtherSessions)
	api.self("DELETE /api/me/sessions/{id}", s.handleEndMySession)
	api.sensitive("DELETE /api/users/{username}/sessions", s.handleEndUserSessions)
}

// currentToken is the session token of the request, "" when it did not
// sign in with a session (HTTP Basic auth, an API token).
func currentToken(p *principal) string {
	if p.Method != "session" {
		return ""
	}
	return p.token
}

func (s *Server) handleListMySessions(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	list, err := s.sessions().List(r.Context(), p.Username, currentToken(p))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

// handleEndMyOtherSessions signs the user out everywhere but here.
func (s *Server) handleEndMyOtherSessions(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	ended := s.sessions().EndUser(r.Context(), p.Username, currentToken(p))
	s.audit(r, "other sessions ended", "user", p.Username, "sessions_ended", ended)
	writeJSON(w, http.StatusOK, map[string]any{"ended": ended})
}

func (s *Server) handleEndMySession(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	id := r.PathValue("id")
	if cur := currentToken(p); cur != "" {
		list, _ := s.sessions().List(r.Context(), p.Username, cur)
		for _, ss := range list {
			if ss.Current && ss.ID == id {
				writeError(w, http.StatusConflict, errors.New("this is the session you are using; to end it, sign out"))
				return
			}
		}
	}
	ok, err := s.sessions().End(r.Context(), p.Username, id)
	if ok {
		// pending: OpenSearch could not be written, so it ends once it
		// can.
		s.audit(r, "session ended", "user", p.Username, "session", id, "pending", err != nil)
	}
	switch {
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, err)
	case !ok:
		writeError(w, http.StatusNotFound, errors.New("that session has ended already"))
	default:
		writeJSON(w, http.StatusOK, map[string]any{"ended": 1})
	}
}

// handleEndUserSessions signs another user out everywhere; they can sign
// in again.
func (s *Server) handleEndUserSessions(w http.ResponseWriter, r *http.Request) {
	name := targetName(r)
	if s.otherTenantsUser(w, name) {
		return
	}
	if strings.EqualFold(name, userOf(r)) {
		writeError(w, http.StatusConflict, errors.New("to end your own sessions, use Signed-in sessions in your account menu"))
		return
	}
	if s.isBuiltin(name) {
		name = s.builtinName()
	} else if u, ok := s.userStore().Get(name); ok {
		name = u.Username
	} else {
		writeUserError(w, users.ErrNotFound)
		return
	}
	ended := s.sessions().EndUser(r.Context(), name, "")
	s.audit(r, "user's sessions ended", "user", name, "sessions_ended", ended)
	writeJSON(w, http.StatusOK, map[string]any{"username": name, "ended": ended})
}
