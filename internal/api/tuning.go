// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

// exceptionRequest adds an exception. For is a duration such as 24h or 7d
// from now (or from From); Until is an absolute end. Neither keeps it until
// it is removed.
type exceptionRequest struct {
	Match   map[string]string `json:"match"`
	From    *time.Time        `json:"from,omitempty"`
	Until   *time.Time        `json:"until,omitempty"`
	For     string            `json:"for,omitempty"`
	Comment string            `json:"comment,omitempty"`
}

func (req *exceptionRequest) exception(by, finding string, now time.Time) (detect.Exception, error) {
	e := detect.Exception{
		ID: detect.NewExceptionID(), Match: map[string]string{}, From: req.From, Until: req.Until,
		Comment: strings.TrimSpace(req.Comment), By: by, Added: now.UTC(), Finding: finding,
	}
	for f, v := range req.Match {
		e.Match[strings.TrimSpace(f)] = strings.TrimSpace(v)
	}
	if req.For != "" {
		if req.Until != nil {
			return e, errors.New("give for or until, not both")
		}
		d, err := detect.ParseDuration(req.For)
		if err != nil {
			return e, fmt.Errorf("for: %w", err)
		}
		start := now
		if req.From != nil {
			start = *req.From
		}
		until := start.Add(d).UTC()
		e.Until = &until
	}
	if e.Until != nil && !e.Until.After(now) {
		return e, errors.New("the exception would already have ended")
	}
	return e, nil
}

func (s *Server) handleAddException(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var req exceptionRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	e, err := req.exception(userOf(r), "", time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	d, err := s.Detections.UpdateExceptionsIf(r.Context(), userOf(r), r.PathValue("id"), ifMatch(r), func(es []detect.Exception) ([]detect.Exception, error) {
		return append(es, e), nil
	})
	if err != nil {
		writeDetectionError(w, err)
		return
	}
	s.Log.Info("detection exception added", "detection", d.ID, "exception", e.ID, "match", e.Describe(), "by", userOf(r))
	writeJSON(w, http.StatusOK, map[string]any{"detection": d, "exception": e})
}

func (s *Server) handleDeleteException(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	exID := r.PathValue("exception")
	d, err := s.Detections.UpdateExceptionsIf(r.Context(), userOf(r), r.PathValue("id"), ifMatch(r), func(es []detect.Exception) ([]detect.Exception, error) {
		i := slices.IndexFunc(es, func(e detect.Exception) bool { return e.ID == exID })
		if i < 0 {
			return nil, fmt.Errorf("%w: no exception %s", detect.ErrNotFound, exID)
		}
		return slices.Delete(es, i, i+1), nil
	})
	if err != nil {
		writeDetectionError(w, err)
		return
	}
	s.Log.Info("detection exception removed", "detection", d.ID, "exception", exID, "by", userOf(r))
	writeJSON(w, http.StatusOK, map[string]any{"detection": d})
}

// scopedExceptionsBody is the exceptions for many detections and their
// version, for If-Match on the next change.
func (s *Server) scopedExceptionsBody(es []detect.Exception) map[string]any {
	if es == nil {
		es = []detect.Exception{}
	}
	return map[string]any{"exceptions": es, "etag": s.Detections.ScopedETag()}
}

func (s *Server) handleListScopedExceptions(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.scopedExceptionsBody(s.Detections.ScopedExceptions()))
}

// handleAddScopedException adds an exception for many detections: a
// detection's exception with a scope, all, pack:<name> or tag:<tag>.
func (s *Server) handleAddScopedException(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var req struct {
		exceptionRequest
		Scope string `json:"scope"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	e, err := req.exception(userOf(r), "", time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	e.Scope = strings.TrimSpace(req.Scope)
	es, err := s.Detections.UpdateScopedExceptionsIf(r.Context(), userOf(r), ifMatch(r), func(es []detect.Exception) ([]detect.Exception, error) {
		return append(es, e), nil
	})
	if err != nil {
		writeDetectionError(w, err)
		return
	}
	s.Log.Info("scoped detection exception added", "scope", e.Scope, "exception", e.ID, "match", e.Describe(), "by", userOf(r))
	body := s.scopedExceptionsBody(es)
	body["exception"] = e
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleDeleteScopedException(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	exID := r.PathValue("exception")
	var scope string
	es, err := s.Detections.UpdateScopedExceptionsIf(r.Context(), userOf(r), ifMatch(r), func(es []detect.Exception) ([]detect.Exception, error) {
		i := slices.IndexFunc(es, func(e detect.Exception) bool { return e.ID == exID })
		if i < 0 {
			return nil, fmt.Errorf("%w: no exception %s", detect.ErrNotFound, exID)
		}
		scope = es[i].Scope
		return slices.Delete(es, i, i+1), nil
	})
	if err != nil {
		writeDetectionError(w, err)
		return
	}
	s.Log.Info("scoped detection exception removed", "scope", scope, "exception", exID, "by", userOf(r))
	writeJSON(w, http.StatusOK, s.scopedExceptionsBody(es))
}

// handleSuppressFinding is "don't alert on this again": it adds an
// exception to the finding's detection for the finding's values of the
// fields asked for (such as host or user), and can update the finding in
// the same step, for example closing it as a false positive. With a
// scope (all, pack:<name> or tag:<tag>) the exception is one for many
// detections instead, such as every rule for this host.
func (s *Server) handleSuppressFinding(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var req struct {
		Fields  []string         `json:"fields"`
		For     string           `json:"for,omitempty"`
		Comment string           `json:"comment,omitempty"`
		Scope   string           `json:"scope,omitempty"`
		Update  *findings.Update `json:"update,omitempty"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Fields) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("fields must name at least one field of the finding, such as host or user"))
		return
	}
	if req.Update != nil {
		if err := req.Update.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	f, err := s.Findings.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, findings.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	match := map[string]string{}
	for _, field := range req.Fields {
		v, ok := findingValue(f, field)
		if !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("the finding has no single value for %s", field))
			return
		}
		match[field] = v
	}
	er := exceptionRequest{Match: match, For: req.For, Comment: req.Comment}
	e, err := er.exception(userOf(r), f.ID, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// The values are the finding's, from the logs: a logged * or ? is a
	// character, not a wildcard that would silence every result.
	e.Exact = true
	var d *detect.Detection
	note := "Stopped alerting on " + e.Describe()
	if scope := strings.TrimSpace(req.Scope); scope != "" {
		e.Scope = scope
		if _, err := s.Detections.UpdateScopedExceptionsIf(r.Context(), userOf(r), "", func(es []detect.Exception) ([]detect.Exception, error) {
			return append(es, e), nil
		}); err != nil {
			writeDetectionError(w, err)
			return
		}
		s.Log.Info("scoped detection exception added from a finding", "scope", e.Scope, "exception", e.ID, "finding", f.ID,
			"match", e.Describe(), "by", userOf(r))
		note += " in " + scopeText(e.Scope)
		// The finding's detection as it is now, with the new exception.
		d, _ = s.Detections.Get(f.DetectionID)
	} else {
		d, err = s.Detections.UpdateExceptionsIf(r.Context(), userOf(r), f.DetectionID, "", func(es []detect.Exception) ([]detect.Exception, error) {
			return append(es, e), nil
		})
		if err != nil {
			writeDetectionError(w, err)
			return
		}
		s.Log.Info("detection exception added from a finding", "detection", d.ID, "exception", e.ID, "finding", f.ID,
			"match", e.Describe(), "by", userOf(r))
	}
	u := findings.Update{}
	if req.Update != nil {
		u = *req.Update
	}
	if e.Until != nil {
		note += " until " + e.Until.Format("2006-01-02 15:04 MST")
	}
	if e.Comment != "" {
		note += ": " + e.Comment
	}
	if u.Comment != "" {
		note += "\n\n" + u.Comment
	}
	u.Comment = note
	updated, err := s.updateFinding(r.Context(), f.ID, u, userOf(r))
	if err != nil {
		// The exception is saved; say so rather than failing the request.
		writeJSON(w, http.StatusOK, map[string]any{"detection": d, "exception": e, "finding": f, "warning": "the exception was saved, but the finding could not be updated: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"detection": d, "exception": e, "finding": updated})
}

// scopeText says which detections a scope covers, for a finding's note.
func scopeText(scope string) string {
	if name, ok := strings.CutPrefix(scope, "pack:"); ok {
		return "every detection of the " + name + " pack"
	}
	if tag, ok := strings.CutPrefix(scope, "tag:"); ok {
		return "every detection tagged " + tag
	}
	return "every detection"
}

// findingValue is a finding's value for a field: from the result row
// that raised it, else its entities. Only single values qualify.
func findingValue(f *findings.Finding, field string) (string, bool) {
	for _, m := range []map[string]any{f.Result, f.Entities} {
		switch v := m[field].(type) {
		case nil:
		case string:
			if strings.TrimSpace(v) != "" {
				return v, true
			}
		case []any:
			if len(v) == 1 {
				if s := fmt.Sprint(v[0]); s != "" {
					return s, true
				}
			}
		case map[string]any:
		default:
			return fmt.Sprint(v), true
		}
	}
	return "", false
}
