// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/exceptionreqs"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

// Analysts propose exceptions from a finding; admins approve or decline
// them on the Approvals page. Only an approval changes the detection.
func (s *Server) routeExceptionRequests(api *router) {
	api.analyst("POST /api/findings/{id}/propose-exception", s.handleProposeException)
	api.analyst("GET /api/exception-requests", s.handleListExceptionRequests)
	api.admin("POST /api/exception-requests/{id}/approve", s.handleApproveExceptionRequest)
	api.admin("POST /api/exception-requests/{id}/decline", s.handleDeclineExceptionRequest)
}

func (s *Server) exceptionRequests() exceptionreqs.Store {
	if s.ExceptionRequests != nil {
		return s.ExceptionRequests
	}
	return &s.exceptionRequestsMem
}

// modifyExceptionRequests changes the requests and audits those that
// expired since the last change (AW4-06): Tidy marks them expired, and
// the first change after stamps when, so each is audited once.
func (s *Server) modifyExceptionRequests(ctx context.Context, r *http.Request, fn func([]exceptionreqs.Request) ([]exceptionreqs.Request, error)) error {
	var expired []exceptionreqs.Request
	err := s.exceptionRequests().Modify(ctx, func(rs []exceptionreqs.Request) ([]exceptionreqs.Request, error) {
		expired = expired[:0]
		now := time.Now().UTC()
		for i := range rs {
			if rs[i].Status == exceptionreqs.Expired && rs[i].Decided == nil {
				rs[i].Decided = &now
				expired = append(expired, rs[i])
			}
		}
		return fn(rs)
	})
	if err == nil {
		for _, x := range expired {
			s.audit(r, "detection exception request expired", "detection", x.DetectionID, "request", x.ID, "proposed_by", x.By)
		}
	}
	return err
}

func (s *Server) handleProposeException(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var req struct {
		Fields  []string         `json:"fields"`
		For     string           `json:"for,omitempty"`
		Comment string           `json:"comment,omitempty"`
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
	if strings.TrimSpace(req.Comment) == "" {
		writeError(w, http.StatusBadRequest, errors.New("say why this is not worth alerting on, so the admin who approves it knows"))
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
	d, err := s.Detections.Get(f.DetectionID)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("this finding's detection is not in the library, so it cannot take an exception"))
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
	// The length comes from the analyst, so only a short, canonical one is
	// kept (AW4-02).
	if req.For != "" {
		if req.For, err = exceptionreqs.CanonicalFor(req.For); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	// Check now what the approval would add, so an admin is never asked
	// to approve an exception that cannot be saved.
	er := exceptionRequest{Match: match, For: req.For, Comment: req.Comment}
	e, err := er.exception(userOf(r), f.ID, time.Now())
	if err == nil {
		err = e.Validate()
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	pr := exceptionreqs.Request{
		ID: exceptionreqs.NewID(), DetectionID: d.ID, DetectionTitle: d.BaseTitle(), FindingID: f.ID, FindingTitle: f.Title,
		Match: e.Match, For: req.For, Comment: e.Comment, By: userOf(r), Created: time.Now().UTC(), Status: exceptionreqs.Pending,
	}
	if err := s.modifyExceptionRequests(r.Context(), r, func(rs []exceptionreqs.Request) ([]exceptionreqs.Request, error) {
		return exceptionreqs.Add(rs, pr)
	}); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	s.audit(r, "detection exception proposed", "detection", d.ID, "request", pr.ID, "finding", f.ID, "match", e.Describe())

	u := findings.Update{}
	if req.Update != nil {
		u = *req.Update
	}
	note := "Proposed an exception for an admin to approve: " + e.Describe()
	if req.For != "" {
		note += ", for " + req.For
	}
	note += ": " + e.Comment
	if u.Comment != "" {
		note += "\n\n" + u.Comment
	}
	u.Comment = note
	updated, err := s.triageFinding(r.Context(), f.ID, u, userOf(r))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"request": pr, "finding": f, "warning": "the request was saved, but the finding could not be updated: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"request": pr, "finding": updated})
}

func (s *Server) handleListExceptionRequests(w http.ResponseWriter, r *http.Request) {
	rs, err := s.exceptionRequests().List(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	pending := 0
	for _, x := range rs {
		if x.Status == exceptionreqs.Pending {
			pending++
		}
	}
	if rs == nil {
		rs = []exceptionreqs.Request{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": rs, "pending": pending, "expire_after_hours": int(exceptionreqs.ExpireAfter.Hours())})
}

// readDecisionNote reads the admin's note on a decision.
func readDecisionNote(r *http.Request) (string, error) {
	var req struct {
		Note string `json:"note,omitempty"`
	}
	if err := readJSON(r, &req); err != nil {
		return "", err
	}
	note := strings.TrimSpace(req.Note)
	if len(note) > exceptionreqs.MaxNote || strings.ContainsFunc(note, func(c rune) bool { return c < 0x20 && c != '\n' && c != '\t' }) {
		return "", fmt.Errorf("the note must be at most %d characters of text", exceptionreqs.MaxNote)
	}
	return note, nil
}

var (
	errSelfApproval = errors.New("you proposed this exception, so another admin approves it; or add the exception yourself on the detection")
	// errLookOnly ends a read of a detection's exceptions without saving.
	errLookOnly = errors.New("look only")
)

func writeRequestError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errSelfApproval):
		writeError(w, http.StatusForbidden, err)
	case errors.Is(err, exceptionreqs.ErrNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, exceptionreqs.ErrDecided):
		writeError(w, http.StatusConflict, err)
	default:
		writeError(w, http.StatusBadGateway, err)
	}
}

// handleApproveExceptionRequest adds the proposed exception. The request
// is marked approved first, with the exception's ID, so two admins
// approving at once add it once; if the exception then cannot be saved,
// the request waits again.
func (s *Server) handleApproveExceptionRequest(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	id := r.PathValue("id")
	if !exceptionreqs.ValidID(id) {
		writeError(w, http.StatusNotFound, exceptionreqs.ErrNotFound)
		return
	}
	note, err := readDecisionNote(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	now := time.Now()
	exID := detect.NewExceptionID()
	var pr *exceptionreqs.Request
	if err := s.modifyExceptionRequests(r.Context(), r, func(rs []exceptionreqs.Request) ([]exceptionreqs.Request, error) {
		// Approving one's own request would read as two people agreeing
		// (AW4-05); an admin adds the exception directly instead.
		if i := slices.IndexFunc(rs, func(x exceptionreqs.Request) bool { return x.ID == id }); i >= 0 && rs[i].Status == exceptionreqs.Pending && rs[i].By == userOf(r) {
			return nil, errSelfApproval
		}
		out, x, err := exceptionreqs.Decide(rs, id, exceptionreqs.Approved, userOf(r), note, exID, now)
		pr = x
		return out, err
	}); err != nil {
		writeRequestError(w, err)
		return
	}
	// The exception lasts its time from now, when it starts to apply.
	er := exceptionRequest{Match: pr.Match, For: pr.For, Comment: pr.Comment}
	e, err := er.exception(userOf(r), pr.FindingID, now)
	var d *detect.Detection
	hasIt := func(es []detect.Exception) bool {
		return slices.ContainsFunc(es, func(x detect.Exception) bool { return x.ID == exID })
	}
	if err == nil {
		// Values from a finding match literally: a logged "*" must not
		// silence the detection for everyone (AW4-01).
		e.ID, e.ProposedBy, e.Exact = exID, pr.By, true
		d, err = s.Detections.UpdateExceptionsIf(r.Context(), userOf(r), pr.DetectionID, "", func(es []detect.Exception) ([]detect.Exception, error) {
			if hasIt(es) {
				return es, nil
			}
			return append(es, e), nil
		})
	}
	if err != nil {
		// The save may have landed and only its answer been lost: look
		// again before putting the request back (AW4-03). The client may
		// be gone by now, so neither step uses its context.
		ctx := context.WithoutCancel(r.Context())
		landed := false
		_, perr := s.Detections.UpdateExceptionsIf(ctx, userOf(r), pr.DetectionID, "", func(es []detect.Exception) ([]detect.Exception, error) {
			landed = hasIt(es)
			return nil, errLookOnly
		})
		switch {
		case !errors.Is(perr, errLookOnly):
			// Unsure whether it landed: the request stays approved, which
			// at worst leaves the detection alerting, never silenced with
			// the request still waiting.
			s.Log.Warn("an exception request is marked approved and its exception may not be saved", "request", id, "exception", exID, "err", err)
			s.audit(r, "detection exception approval unconfirmed", "detection", pr.DetectionID, "request", id, "exception", exID, "err", err.Error())
			writeDetectionError(w, err)
			return
		case landed:
			d, err = s.Detections.Get(pr.DetectionID)
		}
		if !landed {
			if rerr := s.modifyExceptionRequests(ctx, r, func(rs []exceptionreqs.Request) ([]exceptionreqs.Request, error) {
				for i := range rs {
					if rs[i].ID == id && rs[i].ExceptionID == exID {
						rs[i].Status, rs[i].DecidedBy, rs[i].Decided, rs[i].Note, rs[i].ExceptionID = exceptionreqs.Pending, "", nil, "", ""
					}
				}
				return rs, nil
			}); rerr != nil {
				s.Log.Warn("an exception request is marked approved but its exception was not saved", "request", id, "err", rerr)
			}
			s.audit(r, "detection exception approval rolled back", "detection", pr.DetectionID, "request", id, "exception", exID, "err", err.Error())
			writeDetectionError(w, err)
			return
		}
		if err != nil {
			writeDetectionError(w, err)
			return
		}
	}
	s.audit(r, "detection exception approved", "detection", d.ID, "request", id, "exception", e.ID, "proposed_by", pr.By, "match", e.Describe(), "note", note)
	s.noteOnFinding(r, pr, "Approved the proposed exception on "+e.Describe(), note)
	writeJSON(w, http.StatusOK, map[string]any{"request": pr, "exception": e, "detection": d})
}

func (s *Server) handleDeclineExceptionRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !exceptionreqs.ValidID(id) {
		writeError(w, http.StatusNotFound, exceptionreqs.ErrNotFound)
		return
	}
	note, err := readDecisionNote(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var pr *exceptionreqs.Request
	if err := s.modifyExceptionRequests(r.Context(), r, func(rs []exceptionreqs.Request) ([]exceptionreqs.Request, error) {
		out, x, err := exceptionreqs.Decide(rs, id, exceptionreqs.Declined, userOf(r), note, "", time.Now())
		pr = x
		return out, err
	}); err != nil {
		writeRequestError(w, err)
		return
	}
	s.audit(r, "detection exception declined", "detection", pr.DetectionID, "request", id, "proposed_by", pr.By, "note", note)
	s.noteOnFinding(r, pr, "Declined the proposed exception; the detection still alerts on these values", note)
	writeJSON(w, http.StatusOK, map[string]any{"request": pr})
}

// noteOnFinding records a decision in the finding's history, so the
// analyst who asked sees the answer where they asked. A finding since
// deleted is no reason to fail the decision.
func (s *Server) noteOnFinding(r *http.Request, pr *exceptionreqs.Request, what, note string) {
	if pr.FindingID == "" || s.Findings == nil {
		return
	}
	if note != "" {
		what += ": " + note
	}
	if _, err := s.updateFinding(r.Context(), pr.FindingID, findings.Update{Comment: what}, userOf(r)); err != nil && !errors.Is(err, findings.ErrNotFound) {
		s.Log.Warn("could not note an exception decision on its finding", "finding", pr.FindingID, "err", err)
	}
}
