// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
)

// Host keys (see internal/agenttokens/hosts.go): a Signalith Agent trades
// its line's token for a key of its own (POST /api/agent/enroll) and
// sends with it. Requests about a computer that has a key must come with
// that key: one made with the line's token is refused, or, for events,
// does not move the computer's row on the Agents page.

func (s *Server) routeAgentHosts(api *router) {
	api.analyst("GET /api/agent-hosts", s.handleListAgentHosts)
	api.admin("POST /api/agent-hosts/{host}/revoke", s.handleRevokeAgentHost)
	api.admin("POST /api/agent-hosts/{host}/release", s.handleReleaseAgentHost)
}

// agentHostName is the computer an agent's request is about: its key's,
// or the X-Signalith-Agent it sent with its line's token. ok is false for
// a line's token that names a computer with a key of its own.
func (s *Server) agentHostName(r *http.Request, who agenttokens.Identity) (name string, ok bool) {
	if who.Host != "" {
		return who.Host, true
	}
	name = r.Header.Get(agentproto.HeaderName)
	if n := agentinv.CleanName(name); n != "" && s.tokens().Enrolled(n) {
		return "", false
	}
	return name, true
}

// How many new computer keys one line, and the whole server, may hand out
// in an hour.
const (
	maxEnrollsPerLine = 1000
	maxEnrolls        = 5000
)

// codeHostKeysWait answers an enrollment while some server of the cluster
// is older than computer keys.
const codeHostKeysWait = "host_keys_unavailable"

// msgHostEnrolled answers a line's token that names a computer with a
// key of its own.
const msgHostEnrolled = "A computer with this name has its own key, so it must send with that key. If this computer was installed again, release the name on the Agents page and the agent enrolls by itself."

func (s *Server) handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	if s.agentManagedTenant(w, r, (*Server).handleAgentEnroll) {
		return
	}
	who, ok := s.agentManagedToken(w, r)
	if !ok {
		return
	}
	_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 4096))
	if who.Host != "" {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "This computer already sends with its own key.", "code": agenttokens.CodeHostEnrolled})
		return
	}
	if s.AgentHostKeys != nil && !s.AgentHostKeys() {
		// A server of an older version would refuse the key.
		writeJSON(w, http.StatusConflict, map[string]any{"error": "Computer keys need every Signalith server on a version that supports them; the agent keeps its line's token until then.", "code": codeHostKeysWait})
		return
	}
	name := agentinv.CleanName(r.Header.Get(agentproto.HeaderName))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "The agent sent no valid computer name (" + agentproto.HeaderName + ").", "code": agenttokens.CodeNameInvalid})
		return
	}
	from := clientaddr.Parse(r.RemoteAddr).String()
	// A line's token that leaked could otherwise take thousands of names
	// at once, and with them the names of computers not enrolled yet.
	s.enrollOnce.Do(func() {
		s.enrollRate.Each, s.enrollRate.Per, s.enrollRate.All, s.enrollRate.AllPer = maxEnrollsPerLine, time.Hour, maxEnrolls, time.Hour
	})
	if wait := s.enrollRate.take(who.ID, time.Now()); wait > 0 {
		s.Log.Warn("an agent line asked for too many computer keys; refused", "audit", true, "token_id", who.ID, "token_name", who.Name, "host", name, "client", from)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "Too many computers of this line asked for keys just now; the agent asks again later.", "code": "rate_limited"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	k, secret, err := s.tokens().Enroll(ctx, who.ID, name, from, r.Header.Get(agentproto.HeaderHostKey))
	if err != nil {
		if e, ok := err.(*agenttokens.Error); ok && (e.Code == agenttokens.CodeHostEnrolled || e.Code == agenttokens.CodeHostRevoked) {
			// Either a new install of that computer, or another computer
			// of the line trying to pass for it.
			s.Log.Warn("an agent asked for the key of a computer that has one; refused", "audit", true,
				"host", name, "token_id", who.ID, "token_name", who.Name, "client", from, "code", e.Code)
		}
		s.writeTokenError(w, err)
		return
	}
	s.Log.Info("agent host enrolled", "audit", true, "host", k.Host, "host_key", k.ID, "token_id", who.ID, "token_name", who.Name, "client", from)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"key": secret, "host": k.Host, "id": k.ID})
}

func (s *Server) handleListAgentHosts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"hosts": s.tokens().Hosts(), "max": agenttokens.MaxHosts})
}

func (s *Server) handleRevokeAgentHost(w http.ResponseWriter, r *http.Request) {
	s.changeAgentHost(w, r, "agent host key revoked", (*agenttokens.Registry).RevokeHost)
}

func (s *Server) handleReleaseAgentHost(w http.ResponseWriter, r *http.Request) {
	s.changeAgentHost(w, r, "agent host name released", (*agenttokens.Registry).ReleaseHost)
}

func (s *Server) changeAgentHost(w http.ResponseWriter, r *http.Request, what string,
	change func(*agenttokens.Registry, context.Context, string, string) (agenttokens.HostKey, int, error)) {
	if !readTokenBody(w, r, &struct{}{}) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	k, removed, err := change(s.tokens(), ctx, r.PathValue("host"), userOf(r))
	if err != nil {
		s.writeTokenError(w, err)
		return
	}
	s.audit(r, what, "host", k.Host, "host_key", k.ID, "token_id", k.TokenID, "token_name", k.TokenName, "hosts_removed", removed)
	writeJSON(w, http.StatusOK, map[string]any{"host": k, "hosts_removed": removed})
}
