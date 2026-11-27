// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/playbooks"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// flakyRuns is a playbook run store whose reads and writes fail while
// down is set.
type flakyRuns struct {
	playbooks.Runs
	down atomic.Bool
}

var errRunsDown = errors.New("runs down")

func (f *flakyRuns) List(ctx context.Context, flt playbooks.Filter) ([]playbooks.Run, int, error) {
	if f.down.Load() {
		return nil, 0, errRunsDown
	}
	return f.Runs.List(ctx, flt)
}

func (f *flakyRuns) Get(ctx context.Context, id string) (playbooks.Stored, error) {
	if f.down.Load() {
		return playbooks.Stored{}, errRunsDown
	}
	return f.Runs.Get(ctx, id)
}

func (f *flakyRuns) Update(ctx context.Context, r *playbooks.Run, v store.Version) (store.Version, error) {
	if f.down.Load() {
		return store.Version{}, errRunsDown
	}
	return f.Runs.Update(ctx, r, v)
}

// An approval checks its note and the run before it decides anything:
// malformed or too long notes are 400, unknown runs 404, and a store that
// fails 502, with the run still waiting after each.
func TestPlaybookDecisionChecks(t *testing.T) {
	runs := &flakyRuns{Runs: playbooks.NewMemory()}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Playbooks = &Playbooks{Manager: &playbooks.Manager{File: filepath.Join(t.TempDir(), "playbooks.yaml")}, Runs: runs}
	})
	now := time.Now().UTC()
	run := &playbooks.Run{ID: "run1", PlaybookName: "Brute force", FindingID: "f1", Status: playbooks.StatusWaiting, Created: now, Updated: now,
		Steps:    []playbooks.StepResult{{Step: 1, Kind: playbooks.StepAction, Status: playbooks.StepWaiting}},
		Approval: &playbooks.Approval{Step: 1, Action: "block", What: "Block 203.0.113.7.", Requested: now, Expires: now.Add(time.Hour)}}
	if _, err := runs.Claim(t.Context(), run); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path, body string
		status     int
	}{
		{"/api/playbooks/runs/run1/approve", `{`, http.StatusBadRequest},
		{"/api/playbooks/runs/run1/approve", `{"note":"` + strings.Repeat("n", playbooks.MaxNote+1) + `"}`, http.StatusBadRequest},
		{"/api/playbooks/runs/run1/reject", `{"note":"` + strings.Repeat("n", playbooks.MaxNote+1) + `"}`, http.StatusBadRequest},
		{"/api/playbooks/runs/nope/approve", `{}`, http.StatusNotFound},
	} {
		if code, out := do(t, ts, "POST", c.path, c.body, true); code != c.status {
			t.Errorf("%s %.30s: %d %v", c.path, c.body, code, out)
		}
	}
	if code, out := do(t, ts, "GET", "/api/playbooks/runs?limit=0", "", true); code != http.StatusBadRequest {
		t.Errorf("limit=0: %d %v", code, out)
	}
	runs.down.Store(true)
	if code, out := do(t, ts, "POST", "/api/playbooks/runs/run1/reject", `{"note":"no"}`, true); code != http.StatusBadGateway {
		t.Errorf("reject while down: %d %v", code, out)
	}
	if code, out := do(t, ts, "GET", "/api/playbooks/runs", "", true); code != http.StatusBadGateway || out["runs"] != nil {
		t.Errorf("runs while down: %d %v", code, out)
	}
	runs.down.Store(false)
	st, err := runs.Get(t.Context(), "run1")
	if err != nil || st.Run.Status != playbooks.StatusWaiting {
		t.Errorf("run after refused decisions: %+v %v", st.Run.Status, err)
	}
	code, out := do(t, ts, "GET", "/api/playbooks/runs", "", true)
	if code != http.StatusOK || out["waiting"] != float64(1) {
		t.Errorf("runs: %d %v", code, out)
	}
}
