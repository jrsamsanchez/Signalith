package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
	"github.com/jrsamsanchez/signalith/internal/clusterarchive"
)

// Audit backs the Audit page: the audit records of every server that
// shares this OpenSearch, once they are kept there.
type Audit struct {
	Client audit.Searcher
	Prefix string
	// Shared reports whether audit records, the retention history and
	// archive manifests are kept in OpenSearch now (shared.Runtime.
	// SharedAudit); until then the audit records are only in each
	// server's log, and restores run where they are asked for.
	Shared func() bool
}

func (a *Audit) on() bool { return a != nil && a.Shared != nil && a.Shared() }

// routeAudit adds the Audit page's API, for admins only.
func (s *Server) routeAudit(api *router) {
	api.admin("GET /api/audit", s.handleAudit)
	api.admin("GET /api/audit/servers", s.handleAuditServers)
}

// handleAudit searches the audit records, newest first:
// ?from=&to= (RFC 3339), server, user, action (a trailing dot matches
// every action that starts with it), q (words in the message), size and
// after (the next value of the page before).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.Audit.on() {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "events": []any{},
			"note": "Audit records are searched here once servers share one OpenSearch as a cluster. On a server of its own they are in the server's log, as lines with audit=true."})
		return
	}
	q := r.URL.Query()
	var aq audit.Query
	for _, f := range []struct {
		name string
		t    *time.Time
	}{{"from", &aq.From}, {"to", &aq.To}} {
		if v := q.Get(f.name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeError(w, http.StatusBadRequest, errors.New(f.name+" must be a time such as 2026-10-14T00:00:00Z"))
				return
			}
			*f.t = t
		}
	}
	aq.Server, aq.User, aq.Action, aq.Text = q.Get("server"), q.Get("user"), q.Get("action"), q.Get("q")
	if v := q.Get("size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > audit.MaxSize {
			writeError(w, http.StatusBadRequest, errors.New("size must be between 1 and "+strconv.Itoa(audit.MaxSize)))
			return
		}
		aq.Size = n
	}
	if v := q.Get("after"); v != "" {
		if err := json.Unmarshal([]byte(v), &aq.After); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("after must be the next value of the page before"))
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	page, err := audit.Search(ctx, s.Audit.Client, s.Audit.Prefix, aq)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	out := map[string]any{"enabled": true, "events": page.Events, "total": page.Total}
	if page.Next != nil {
		b, _ := json.Marshal(page.Next)
		out["next"] = string(b)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAuditServers names the servers with audit records, for the
// page's filter.
func (s *Server) handleAuditServers(w http.ResponseWriter, r *http.Request) {
	if !s.Audit.on() {
		writeJSON(w, http.StatusOK, map[string]any{"servers": []string{}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	list, err := audit.Servers(ctx, s.Audit.Client, s.Audit.Prefix)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": list})
}

// restoreQueued asks the server that runs the background jobs to restore
// archived days, when the archives are shared and another server runs
// them; it reports whether it answered.
func (s *Server) restoreQueued(w http.ResponseWriter, r *http.Request, req restoreRequest) bool {
	if !s.Audit.on() || s.Shared == nil || s.leads() {
		return false
	}
	if !req.Confirm {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		chk, err := s.Retention.CheckRestore(ctx, req.IDs, req.KeepDays)
		if err != nil {
			writeRetentionError(w, err)
			return true
		}
		if chk.NeedsConfirm {
			writeJSON(w, http.StatusConflict, map[string]any{"error": chk.Message, "check": chk})
			return true
		}
	}
	s.submit(w, r, clusterarchive.RequestArchiveRestore, clusterarchive.ArchiveRestoreArgs{IDs: req.IDs, KeepDays: req.KeepDays, Confirm: req.Confirm}, nil)
	return true
}

// handleRetentionJob returns the restores' progress, as the server that
// runs them shares it.
func (s *Server) handleRetentionJob(w http.ResponseWriter, r *http.Request) {
	if !s.retentionOK(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, map[string]any{"restores": s.Retention.RestoreStatuses(ctx)})
}
