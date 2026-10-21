// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jrsamsanchez/signalith/internal/compliancehist"
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The compliance history: a signed record of every framework's control
// statuses, taken once a month by the server that runs the background
// jobs, and when an admin asks. Everyone who can read the Compliance page
// can read it, so an auditor with a Viewer account sees it too.
func (s *Server) routeComplianceHistory(api *router) {
	api.viewer("GET /api/compliance/history", s.handleComplianceHistory)
	api.viewer("GET /api/compliance/history/{id}", s.handleComplianceRecord)
	api.admin("POST /api/compliance/history", s.handleTakeComplianceRecord)
}

// manualGap is how long after a record taken by hand an admin may take
// another, so they cannot crowd out the monthly ones.
const manualGap = 10 * time.Minute

// historyKeys looks up the report keys, to check records with.
func (s *Server) historyKeys(ctx context.Context) (func(string) (*reportkeys.Key, bool), error) {
	if s.ReportKeys == nil {
		return func(string) (*reportkeys.Key, bool) { return nil, false }, nil
	}
	ks, err := s.ReportKeys.List(ctx)
	if err != nil {
		return nil, err
	}
	return reportkeys.Lookup(ks), nil
}

// historySummary is a record in the list: its frameworks without their
// controls.
type historySummary struct {
	*compliancehist.Checked
	Taken      time.Time                  `json:"taken"`
	Trigger    string                     `json:"trigger,omitempty"`
	By         string                     `json:"by,omitempty"`
	Frameworks []compliancehist.Framework `json:"frameworks,omitempty"`
}

func (s *Server) handleComplianceHistory(w http.ResponseWriter, r *http.Request) {
	if s.ComplianceHistory == nil {
		writeJSON(w, http.StatusOK, map[string]any{"records": []historySummary{}})
		return
	}
	list, err := s.ComplianceHistory.List(r.Context())
	keys, kerr := s.historyKeys(r.Context())
	if err == nil {
		err = kerr
	}
	if err != nil {
		s.Log.Warn("the compliance history could not be read", "err", err)
		writeError(w, http.StatusBadGateway, errors.New("the compliance history could not be read; try again"))
		return
	}
	out := make([]historySummary, 0, len(list))
	for _, rec := range list {
		c := compliancehist.Check(rec, keys)
		sum := historySummary{Taken: rec.Taken}
		if rec := c.Record; rec != nil {
			sum.Trigger, sum.By = rec.Trigger, rec.By
			for _, f := range rec.Frameworks {
				f.Controls = nil
				sum.Frameworks = append(sum.Frameworks, f)
			}
			c = &compliancehist.Checked{ID: c.ID, SHA256: c.SHA256, KeyID: c.KeyID, Check: c.Check, Problem: c.Problem}
		}
		sum.Checked = c
		out = append(out, sum)
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": out})
}

func (s *Server) handleComplianceRecord(w http.ResponseWriter, r *http.Request) {
	if s.ComplianceHistory == nil {
		writeError(w, http.StatusNotFound, compliancehist.ErrNotFound)
		return
	}
	rec, err := s.ComplianceHistory.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, compliancehist.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	keys, kerr := s.historyKeys(r.Context())
	if err == nil {
		err = kerr
	}
	if err != nil {
		s.Log.Warn("the compliance history could not be read", "err", err)
		writeError(w, http.StatusBadGateway, errors.New("the compliance history could not be read; try again"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"record": compliancehist.Check(rec, keys), "signed": rec})
}

func (s *Server) handleTakeComplianceRecord(w http.ResponseWriter, r *http.Request) {
	if s.ComplianceHistory == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("this server keeps no compliance history"))
		return
	}
	now := time.Now()
	list, err := s.ComplianceHistory.List(r.Context())
	if err != nil {
		s.Log.Warn("the compliance history could not be read", "err", err)
		writeError(w, http.StatusBadGateway, errors.New("the compliance history could not be read; try again"))
		return
	}
	for _, rec := range list {
		if rec.ID != compliancehist.MonthID(rec.Taken) && now.Sub(rec.Taken) < manualGap {
			writeError(w, http.StatusTooManyRequests, errors.New("a record was taken a few minutes ago; take another later"))
			return
		}
	}
	c, err := s.takeComplianceRecord(r.Context(), r, compliancehist.ManualID(now), compliancehist.Manual, userOf(r))
	switch {
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, errors.New("a record was taken this second; take another later"))
		return
	case err != nil:
		s.Log.Warn("a compliance history record could not be stored", "err", err)
		writeError(w, http.StatusBadGateway, errors.New("the record could not be stored; try again"))
		return
	}
	s.audit(r, "compliance.history: took a compliance evidence record", "record", c.ID, "sha256", c.SHA256, "key", c.KeyID)
	writeJSON(w, http.StatusCreated, map[string]any{"record": c})
}

// takeComplianceRecord records the compliance report now; r is nil for
// the monthly record.
func (s *Server) takeComplianceRecord(ctx context.Context, r *http.Request, id, trigger, by string) (*compliancehist.Checked, error) {
	rep := s.complianceReportAt(ctx, r, true)
	rec := compliancehist.FromReport(rep, id, trigger, by, s.serverName(), s.Version, s.conf().OpenSearch.IndexPrefix)
	key, why := s.reportKey(ctx)
	if key == nil {
		rec.Notes = append(rec.Notes, "This record is not signed: "+why)
	}
	signed, err := compliancehist.Sign(rec, key)
	if err != nil {
		return nil, err
	}
	if err := s.ComplianceHistory.Create(ctx, signed); err != nil {
		return nil, err
	}
	return &compliancehist.Checked{ID: signed.ID, SHA256: signed.SHA256, KeyID: signed.KeyID, Check: map[bool]string{true: compliancehist.Verified, false: compliancehist.Unsigned}[key != nil]}, nil
}

// historyCheckEvery is how often the server that runs the background
// jobs looks whether this month's record was taken.
var historyCheckEvery = time.Hour

// RunComplianceHistory takes the month's compliance record once the month
// has none, until ctx ends. Two servers taking it at once store one: the
// record's ID is the month.
// A tenant's server takes none: compliance is the provider's.
func (s *Server) RunComplianceHistory(ctx context.Context) {
	if s.ComplianceHistory == nil || s.TenantID != "" {
		return
	}
	t := time.NewTimer(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.complianceMonth(ctx, time.Now())
		t.Reset(historyCheckEvery)
	}
}

func (s *Server) complianceMonth(ctx context.Context, now time.Time) {
	due, err := compliancehist.Due(ctx, s.ComplianceHistory, now)
	if err != nil {
		s.Log.Warn("could not check the compliance history; trying again in an hour", "err", err)
		return
	}
	if !due {
		return
	}
	c, err := s.takeComplianceRecord(ctx, nil, compliancehist.MonthID(now), compliancehist.Monthly, "")
	switch {
	case errors.Is(err, store.ErrExists):
	case err != nil:
		s.Log.Warn("could not take this month's compliance record; trying again in an hour", "err", err)
	default:
		s.Log.Info("compliance.history: took this month's compliance evidence record", "audit", true, "record", c.ID, "sha256", c.SHA256, "key", c.KeyID)
	}
}
