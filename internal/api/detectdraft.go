// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/nlq"
	"github.com/jrsamsanchez/signalith/internal/ruledraft"
)

func (s *Server) routeDetectionDrafts(api *router) {
	// Drafting can call a paid AI model and leads to a new detection, and
	// a backtest runs up to 60 searches, so both are admin work like
	// writing and testing detections.
	api.admin("POST /api/detections/draft", s.handleDraftDetection)
	api.admin("POST /api/detections/backtest", s.handleBacktestDetection)
}

type draftRequest struct {
	Description string `json:"description"`
	// Mode is "auto" (default: the AI model when one is set up, else the
	// offline drafter), "rules" or "ai".
	Mode string `json:"mode"`
}

// handleDraftDetection drafts a detection from a plain-English
// description. Nothing is saved; the page opens the draft in the editor,
// turned off, for review and a backtest.
func (s *Server) handleDraftDetection(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var req draftRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Description = strings.TrimSpace(req.Description)
	switch req.Mode {
	case "", "auto", "rules", "ai":
	default:
		writeError(w, http.StatusBadRequest, errors.New("mode must be auto, rules or ai"))
		return
	}
	ai := s.model()
	if req.Mode == "ai" && ai == nil {
		writeError(w, http.StatusBadRequest, errors.New("no AI model is configured; set one up on the Settings page"))
		return
	}
	var hints nlq.Hints
	if s.Assets != nil {
		hints = AssetHints{A: s.Assets}
	}
	library := s.Detections.List()
	dr, err := ruledraft.Offline(req.Description, hints, library)
	if dr == nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err != nil {
		// The draft is still worth showing: the editor lists what to fix.
		dr.Warnings = append(dr.Warnings, err.Error())
	}
	resp := map[string]any{"ai_available": ai != nil}
	if ai != nil && req.Mode != "rules" {
		ctx, cancel := context.WithTimeout(r.Context(), s.conf().AssistantRequestTimeout())
		defer cancel()
		got, aerr := ruledraft.AI(ctx, ai, req.Description, dr)
		sentTo := config.Origin(ai.URL)
		if aerr != nil {
			s.Log.Warn("AI detection draft failed", "audit", true, "by", userOf(r), "model", ai.Name(), "sent_to", sentTo, "err", aerr)
			resp["ai_error"] = aerr.Error()
		} else {
			dr = got
			resp["ai_model"] = ai.Name()
			s.Log.Info("detection drafted with AI", "audit", true, "by", userOf(r), "model", ai.Name(), "sent_to", sentTo, "chars_sent", len(req.Description))
		}
	}
	dr.Detection.ID = s.freeDetectionID(dr.Detection.ID, library)
	resp["draft"] = dr
	writeJSON(w, http.StatusOK, resp)
}

// freeDetectionID returns id, or id with a number after it when a
// detection already has it.
func (s *Server) freeDetectionID(id string, library []*detect.Detection) string {
	taken := make(map[string]bool, len(library))
	for _, d := range library {
		taken[d.ID] = true
	}
	if !taken[id] {
		return id
	}
	base := id
	if len(base) > 60 {
		base = strings.TrimRight(base[:60], "-_")
	}
	for n := 2; n < 1000; n++ {
		if c := base + "-" + strconv.Itoa(n); !taken[c] {
			return c
		}
	}
	return id
}

type backtestRequest struct {
	Detection detect.Detection `json:"detection"`
	// Window is how far back to test, such as 7d or 30d (default 30d, at
	// most 90d).
	Window string `json:"window"`
}

// Backtests run many searches, so each person runs one at a time and the
// server at most maxBacktests at once.
const maxBacktests = 2

type backtestSlots struct {
	mu      sync.Mutex
	running map[string]bool
	n       int
}

// start claims a backtest slot for user; the returned function frees it.
// It returns nil, and why, when the user already runs one or the server
// is at maxBacktests.
func (b *backtestSlots) start(user string) (func(), string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.running[user] {
		return nil, "You already have a backtest running; wait for it to finish, then try again"
	}
	if b.n >= maxBacktests {
		return nil, "Other backtests are running; try again in a minute"
	}
	if b.running == nil {
		b.running = map[string]bool{}
	}
	b.running[user] = true
	b.n++
	return func() {
		b.mu.Lock()
		delete(b.running, user)
		b.n--
		b.mu.Unlock()
	}, ""
}

// backtestTimeout bounds one backtest; when it runs out, the searches done
// so far are returned as a partial result.
const backtestTimeout = 3 * time.Minute

// handleBacktestDetection runs an unsaved detection over a past window,
// the way its scheduled runs would have, and returns what it would have
// raised. Nothing is written.
func (s *Server) handleBacktestDetection(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var req backtestRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Window == "" {
		req.Window = "30d"
	}
	window, err := detect.ParseDuration(req.Window)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("window: "+err.Error()))
		return
	}
	if window < time.Hour || window > detect.MaxBacktestWindow {
		writeError(w, http.StatusBadRequest, errors.New("window must be between 1h and 90d"))
		return
	}
	d := req.Detection
	if d.ID == "" {
		d.ID = "unsaved"
	}
	if d.Title == "" {
		d.Title = "Test"
	}
	d.Defaults()
	if err := d.Validate(); err != nil {
		writeDetectionError(w, err)
		return
	}
	done, busy := s.backtests.start(userOf(r))
	if done == nil {
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusTooManyRequests, errors.New(busy))
		return
	}
	defer done()
	ctx, cancel := context.WithTimeout(r.Context(), backtestTimeout)
	defer cancel()
	bt, err := s.Scheduler.Backtest(ctx, &d, window)
	if err != nil {
		writeSearchError(w, err)
		return
	}
	s.Log.Info("detection backtested", "audit", true, "by", userOf(r), "detection", d.ID, "window", req.Window,
		"searches", bt.Searches, "results", bt.Results, "findings", bt.Findings, "partial", bt.Partial)
	writeJSON(w, http.StatusOK, map[string]any{"backtest": bt})
}
