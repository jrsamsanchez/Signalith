// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/storyline"
)

func (s *Server) routeStoryline(api *router) {
	// Reads only what a viewer can already see on Findings, Risk and
	// Search.
	api.viewer("GET /api/storyline", s.handleStoryline)
}

// storylineCaseFindings is how many of a case's findings seed its story.
const storylineCaseFindings = 50

// handleStoryline builds the attack story about a user, system or address
// (type and object, over since), a finding (finding) or a case (case); a
// finding's or case's story covers the days around it.
func (s *Server) handleStoryline(w http.ResponseWriter, r *http.Request) {
	if s.Findings == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("findings are not configured on this server"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	v := r.URL.Query()
	now := time.Now().UTC()
	req := storyline.Request{Latest: now}
	anchor := map[string]any{}
	switch {
	case v.Get("finding") != "":
		f, err := s.Findings.Get(ctx, v.Get("finding"))
		if err != nil {
			writeFindingError(w, err)
			return
		}
		req.Seeds = storyline.SeedsFromFinding(f)
		req.Earliest, req.Latest = storyline.WindowAround([]time.Time{f.Created}, now)
		anchor = map[string]any{"kind": "finding", "id": f.ID, "title": detect.ShowHidden(f.Title), "time": f.Created}
	case v.Get("case") != "":
		if !s.casesReady(w) {
			return
		}
		c, err := s.Cases.Get(ctx, v.Get("case"))
		if err != nil {
			writeCaseError(w, err)
			return
		}
		var fs []*findings.Finding
		times := []time.Time{c.Created}
		for _, id := range c.Findings[:min(len(c.Findings), storylineCaseFindings)] {
			if f, err := s.Findings.Get(ctx, id); err == nil {
				fs = append(fs, f)
				times = append(times, f.Created)
			}
		}
		if len(fs) > 0 {
			times = times[1:] // the findings say when it happened
		}
		req.Seeds = storyline.SeedsFromCase(c, fs)
		req.Earliest, req.Latest = storyline.WindowAround(times, now)
		anchor = map[string]any{"kind": "case", "id": c.ID, "title": c.Title}
	default:
		e, err := storyline.ParseSeed(v.Get("type"), v.Get("object"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		since, err := sinceParam(r, "7d")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		d, _ := detect.ParseDuration(since[1:])
		if d <= 0 || d > storyline.MaxWindow {
			writeError(w, http.StatusBadRequest, errors.New("since must be between 1 minute and 31 days"))
			return
		}
		req.Seeds = []storyline.Entity{e}
		req.Earliest = now.Add(-d)
		anchor = map[string]any{"kind": "entity", "type": e.Type, "value": e.Value, "since": since[1:]}
	}
	if len(req.Seeds) == 0 {
		writeError(w, http.StatusUnprocessableEntity, errors.New("this has no user, system or address to build a storyline from"))
		return
	}
	b := &storyline.Builder{Findings: s.Findings, Assets: s.Assets}
	if s.Engine != nil {
		b.Run = func(ctx context.Context, q *query.Query) ([]map[string]any, error) {
			res, err := s.Engine.Execute(ctx, q)
			if err != nil {
				return nil, err
			}
			rows := make([]map[string]any, len(res.Rows))
			for i, row := range res.Rows {
				rows[i] = row
			}
			return rows, nil
		}
	}
	st, err := b.Build(ctx, req)
	if err != nil {
		writeSearchError(w, err)
		return
	}
	// The matrix's tactics, so the page can show the ones not reached.
	writeJSON(w, http.StatusOK, map[string]any{"storyline": st, "anchor": anchor, "tactics": detect.ATTACK().Tactics})
}

func writeFindingError(w http.ResponseWriter, err error) {
	if errors.Is(err, findings.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeError(w, http.StatusBadGateway, err)
}
