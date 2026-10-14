package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/retention"
)

// routeRetention adds the Data retention page's API. Retention deletes
// data, so every route is for admins only.
func (s *Server) routeRetention(api *router) {
	api.admin("GET /api/retention", s.handleRetention)
	api.admin("PUT /api/retention/policies/{category}", s.handleRetentionSetPolicy)
	api.admin("DELETE /api/retention/policies/{category}", s.handleRetentionResetPolicy)
	api.admin("PUT /api/retention/default", s.handleRetentionSetDefault)
	api.admin("PUT /api/retention/guard", s.handleRetentionSetGuard)
	api.admin("POST /api/retention/policies/confirm", s.handleRetentionConfirm)
	api.admin("POST /api/retention/preview", s.handleRetentionPreview)
	api.admin("POST /api/retention/run", s.handleRetentionRun)
	api.admin("GET /api/retention/archive", s.handleRetentionArchive)
	api.admin("POST /api/retention/archive/preview", s.handleRetentionRestorePreview)
	api.admin("POST /api/retention/archive/restore", s.handleRetentionRestore)
	api.admin("GET /api/retention/job", s.handleRetentionJob)
}

var errRetentionOff = errors.New("data retention is not available on this server")

func (s *Server) retentionOK(w http.ResponseWriter) bool {
	if s.Retention == nil {
		writeError(w, http.StatusServiceUnavailable, errRetentionOff)
		return false
	}
	return true
}

// policyFields are the settings a problem message can start with, so the
// page can mark the right input.
var policyFields = []string{"keep_days", "max_size_gb", "compact_after_days", "archive", "max_disk_percent", "min_days"}

func writeRetentionError(w http.ResponseWriter, err error) {
	var pe *retention.PolicyError
	var ce *retention.ConfirmError
	if sharedError(w, err) {
		return
	}
	switch {
	case errors.As(err, &ce):
		// The restore needs confirming; check says what it would do.
		writeJSON(w, http.StatusConflict, map[string]any{"error": ce.Error(), "check": ce.Check})
	case errors.As(err, &pe):
		fields := []string{}
		for _, p := range pe.Problems {
			name, _, _ := strings.Cut(p, " ")
			for _, f := range policyFields {
				if name == f {
					fields = append(fields, f)
				}
			}
		}
		msg := pe.Error()
		if len(pe.Problems) > 0 {
			msg = strings.ToUpper(msg[:1]) + msg[1:]
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg, "problems": pe.Problems, "fields": fields})
	case errors.Is(err, retention.ErrUnknownCategory), errors.Is(err, retention.ErrArchiveNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, retention.ErrManaged):
		writeError(w, http.StatusBadRequest, err)
	case errors.Is(err, retention.ErrFromConfig), errors.Is(err, retention.ErrBusy), errors.Is(err, retention.ErrRestoring),
		errors.Is(err, retention.ErrReadOnly), errors.Is(err, retention.ErrNoHold):
		writeError(w, http.StatusConflict, err)
	case errors.Is(err, retention.ErrOpenSearch):
		writeError(w, http.StatusServiceUnavailable, err)
	default:
		writeError(w, http.StatusInternalServerError, err)
	}
}

// readStrict decodes a JSON body and rejects unknown fields, so a typo in
// a setting's name is an error rather than a setting that does nothing.
func readStrict(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("request body must be JSON with known settings: " + err.Error())
	}
	return nil
}

func (s *Server) handleRetention(w http.ResponseWriter, r *http.Request) {
	if !s.retentionOK(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ov := s.Retention.Overview(ctx)
	ov.RestoreQueued = s.Audit.on()
	if ov.ETag != "" {
		w.Header().Set("ETag", ov.ETag)
	}
	writeJSON(w, http.StatusOK, ov)
}

// retentionEditable refuses a change of shared policies while the shared
// settings cannot be changed on this server.
func (s *Server) retentionEditable(w http.ResponseWriter) bool {
	if !s.retentionOK(w) {
		return false
	}
	if s.sharedContent() {
		return s.sharedWritable(w)
	}
	return true
}

// changed logs a settings change and starts a run so it applies now, or
// queues one when a run or restore is going. Where the policies are
// shared and another server runs retention, that server is asked to.
func (s *Server) retentionChanged(w http.ResponseWriter, r *http.Request, what string, out map[string]any) {
	user := userOf(r)
	s.Log.Info("retention settings changed", "what", what, "by", user)
	if tag := s.Retention.ETag(); tag != "" {
		w.Header().Set("ETag", tag)
	}
	if s.sharedContent() && !s.leads() {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		req, err := s.Shared.Submit(ctx, clustercfg.RequestRetentionRun, clustercfg.RetentionRunArgs{Trigger: retention.TriggerChange}, user)
		// No run here: the other server is asked, and request_id follows
		// that.
		out["run_started"], out["run_queued"] = false, false
		if err == nil {
			out["request_id"] = req.ID
			if s.Cluster != nil {
				out["queued_on"] = s.Cluster.JobHolder()
			}
		} else {
			s.Log.Warn("could not ask the server that runs retention to apply the change now; its next run does", "err", err)
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	got, _ := s.Retention.ApplySoon(retention.TriggerChange, user)
	out["run_started"] = got == retention.ApplyStarted
	out["run_queued"] = got == retention.ApplyQueued
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRetentionSetPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.retentionEditable(w) {
		return
	}
	id := r.PathValue("category")
	var p retention.Policy
	if err := readStrict(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Retention.SetPolicyIf(id, &p, r.Header.Get("If-Match")); err != nil {
		writeRetentionError(w, err)
		return
	}
	s.retentionChanged(w, r, "policy "+id, map[string]any{"category": id, "policy": p, "source": retention.SourceUI})
}

func (s *Server) handleRetentionResetPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.retentionEditable(w) {
		return
	}
	id := r.PathValue("category")
	if err := s.Retention.SetPolicyIf(id, nil, r.Header.Get("If-Match")); err != nil {
		writeRetentionError(w, err)
		return
	}
	set, _ := s.Retention.Settings()
	p, src := set.For(id)
	s.retentionChanged(w, r, "policy "+id+" reset to the default", map[string]any{"category": id, "policy": p, "source": src})
}

func (s *Server) handleRetentionSetDefault(w http.ResponseWriter, r *http.Request) {
	if !s.retentionEditable(w) {
		return
	}
	var p retention.Policy
	if err := readStrict(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Retention.SetDefaultIf(p, r.Header.Get("If-Match")); err != nil {
		writeRetentionError(w, err)
		return
	}
	s.retentionChanged(w, r, "default policy", map[string]any{"policy": p, "source": retention.SourceUI})
}

func (s *Server) handleRetentionSetGuard(w http.ResponseWriter, r *http.Request) {
	if !s.retentionEditable(w) {
		return
	}
	var g retention.Guard
	if err := readStrict(r, &g); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Retention.SetGuardIf(g, r.Header.Get("If-Match")); err != nil {
		writeRetentionError(w, err)
		return
	}
	g = g.Normalized()
	s.retentionChanged(w, r, "disk guard", map[string]any{"enabled": g.IsEnabled(), "max_disk_percent": g.MaxDiskPercent,
		"min_days": g.MinDays, "source": retention.SourceUI})
}

// handleRetentionPreview shows what a change would do before it is saved.
// The body is {"category": "endpoint", "policy": {...}} (a null policy goes
// back to the default), {"default": {...}} or {"guard": {...}}.
func (s *Server) handleRetentionPreview(w http.ResponseWriter, r *http.Request) {
	if !s.retentionOK(w) {
		return
	}
	var ch retention.Change
	if err := readStrict(r, &ch); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	p, err := s.Retention.Preview(ctx, ch)
	if err != nil {
		writeRetentionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleRetentionRun(w http.ResponseWriter, r *http.Request) {
	if !s.retentionOK(w) {
		return
	}
	if s.sharedContent() && !s.leads() {
		// The server that runs the background jobs runs retention; the
		// page follows the request.
		s.submit(w, r, clustercfg.RequestRetentionRun, clustercfg.RetentionRunArgs{Trigger: retention.TriggerManual}, nil)
		return
	}
	user := userOf(r)
	if err := s.Retention.RunAsync(retention.TriggerManual, user); err != nil {
		writeRetentionError(w, err)
		return
	}
	s.Log.Info("retention run started by hand", "by", user)
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// handleRetentionConfirm confirms shared policies that wait to be
// confirmed (their import found that the servers' own policies
// differed), so runs enforce them in full again, starting now.
func (s *Server) handleRetentionConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.retentionEditable(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Retention.Confirm(ctx, userOf(r)); err != nil {
		writeRetentionError(w, err)
		return
	}
	s.retentionChanged(w, r, "shared policies confirmed", map[string]any{"confirmed": true})
}

func (s *Server) handleRetentionArchive(w http.ResponseWriter, r *http.Request) {
	if !s.retentionOK(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	list, err := s.Retention.Archives(ctx)
	if err != nil {
		writeRetentionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type restoreRequest struct {
	IDs      []string `json:"ids"`
	KeepDays int      `json:"keep_days"`
	// Confirm restores even when that makes the disk guard delete live
	// days or fills the disk; without it such a restore returns 409 with
	// the check.
	Confirm bool `json:"confirm"`
}

// handleRetentionRestorePreview says what restoring archived days does to
// the disk: {"ids": [...], "keep_days": 14}.
func (s *Server) handleRetentionRestorePreview(w http.ResponseWriter, r *http.Request) {
	if !s.retentionOK(w) {
		return
	}
	var req restoreRequest
	if err := readStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	chk, err := s.Retention.CheckRestore(ctx, req.IDs, req.KeepDays)
	if err != nil {
		writeRetentionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, chk)
}

// handleRetentionRestore queues archived days to be restored:
// {"ids": ["signalith-endpoint-2026.07.01"], "keep_days": 14}.
func (s *Server) handleRetentionRestore(w http.ResponseWriter, r *http.Request) {
	if !s.retentionOK(w) {
		return
	}
	var req restoreRequest
	if err := readStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.restoreQueued(w, r, req) {
		return
	}
	user := userOf(r)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	sts, err := s.Retention.Restore(ctx, req.IDs, req.KeepDays, user, req.Confirm)
	if err != nil {
		writeRetentionError(w, err)
		return
	}
	s.Log.Info("restore from the archive started", "days", len(sts), "by", user)
	writeJSON(w, http.StatusAccepted, map[string]any{"restores": sts})
}
