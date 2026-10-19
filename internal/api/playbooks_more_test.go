// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/playbooks"
)

// Playbooks run where the background jobs do; elsewhere the page says
// which server to set them on, and saving is refused.
func TestPlaybooksElsewhere(t *testing.T) {
	cl := &fakeCluster{holder: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Config.Detections.Scheduler = true
		s.Cluster = cl
		s.Playbooks = &Playbooks{Manager: &playbooks.Manager{File: filepath.Join(t.TempDir(), "playbooks.yaml")}, Runs: playbooks.NewMemory()}
	})
	code, out := do(t, ts, "GET", "/api/playbooks", "", true)
	if code != http.StatusOK || out["manage"] != false || out["runs_on"] != "siem-a" || !strings.Contains(out["manage_why"].(string), "siem-a does") {
		t.Errorf("standby: %d %v", code, out)
	}
	if code, out := do(t, ts, "PUT", "/api/playbooks", `{"playbooks":[]}`, true); code != http.StatusConflict {
		t.Errorf("save on a standby: %d %v", code, out)
	}
	cl.mu.Lock()
	cl.holder = ""
	cl.mu.Unlock()
	if _, out := do(t, ts, "GET", "/api/playbooks", "", true); !strings.Contains(out["manage_why"].(string), "no server runs the background jobs") {
		t.Errorf("no holder: %v", out["manage_why"])
	}
	cl.mu.Lock()
	cl.runs = true
	cl.mu.Unlock()
	if code, out := do(t, ts, "PUT", "/api/playbooks", `{`, true); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d %v", code, out)
	}
	for _, q := range []string{"status=nonsense", "limit=0", "limit=x"} {
		if code, _ := do(t, ts, "GET", "/api/playbooks/runs?"+q, "", true); code != http.StatusBadRequest {
			t.Errorf("runs?%s: %d", q, code)
		}
	}
	if code, out := do(t, ts, "GET", "/api/playbooks/runs?status=waiting_approval,failed&limit=5", "", true); code != http.StatusOK || out["total"] != float64(0) {
		t.Errorf("runs: %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/playbooks/runs/nope/approve", `{`, true); code != http.StatusBadRequest {
		t.Errorf("approve with bad JSON: %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/playbooks/runs/nope/reject", "", true); code != http.StatusNotFound {
		t.Errorf("reject an unknown run: %d", code)
	}
}

// The desk playbooks change cases and findings through: without the
// stores it says so, and a case's state is read as open or not.
func TestPlaybookDesk(t *testing.T) {
	ctx := context.Background()
	off := playbookDesk{&Server{}}
	f := &findings.Finding{ID: "f1", Title: "x", Severity: "low", Status: findings.StatusNew}
	if _, err := off.OpenCase(ctx, f, "t", "", "playbook"); !errors.Is(err, errCasesOff) {
		t.Errorf("OpenCase: %v", err)
	}
	if err := off.AddToCase(ctx, "c", f, "playbook"); !errors.Is(err, errCasesOff) {
		t.Errorf("AddToCase: %v", err)
	}
	if _, err := off.CaseOpen(ctx, "c"); !errors.Is(err, errCasesOff) {
		t.Errorf("CaseOpen: %v", err)
	}
	if err := off.NoteOnCase(ctx, "c", "x", "playbook"); !errors.Is(err, errCasesOff) {
		t.Errorf("NoteOnCase: %v", err)
	}
	if err := off.UpdateFinding(ctx, "f1", findings.Update{}, "playbook"); !errors.Is(err, errDetectionsOff) {
		t.Errorf("UpdateFinding: %v", err)
	}

	store := &failCases{Store: cases.NewMemory()}
	var srv *Server
	newTestServerWith(t, func(s *Server) { s.Cases, srv = store, s })
	d := playbookDesk{srv}
	now := time.Now().UTC()
	for _, c := range []*cases.Case{
		{ID: "CASE-open", Title: "a", Severity: "low", Status: findings.StatusNew, Created: now, Updated: now},
		{ID: "CASE-done", Title: "b", Severity: "low", Status: findings.StatusClosed, Created: now, Updated: now},
	} {
		if err := store.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	for id, want := range map[string]bool{"CASE-open": true, "CASE-done": false, "CASE-none": false} {
		if open, err := d.CaseOpen(ctx, id); err != nil || open != want {
			t.Errorf("CaseOpen(%s) = %v, %v", id, open, err)
		}
	}
	if _, err := d.OpenCase(ctx, f, strings.Repeat("x", 10000), "", "playbook"); err == nil {
		t.Error("a title too long was taken")
	}
	// A finding that is not in the store: the case is made, the link
	// fails.
	if id, err := d.OpenCase(ctx, &findings.Finding{ID: "f-none", Severity: "critical"}, "From a playbook", "admin", "playbook"); id == "" || err == nil {
		t.Errorf("OpenCase with a missing finding: %q %v", id, err)
	}
	store.failing(errDown)
	if _, err := d.CaseOpen(ctx, "CASE-open"); !errors.Is(err, errDown) {
		t.Errorf("CaseOpen with the store down: %v", err)
	}
	store.failing(nil)
}
