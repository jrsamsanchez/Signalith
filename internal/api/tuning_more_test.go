// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

// Suppressing a finding checks the request first, takes a value from the
// finding's entities when its result has none, and needs the finding's
// detection to exist.
func TestSuppressFindingMore(t *testing.T) {
	store := &failFindings{}
	ts, _ := newTestServerWith(t, func(s *Server) {
		store.Store = s.Findings
		s.Findings = store
		s.Scheduler.Findings = store
	})
	now := time.Now()
	for _, f := range []*findings.Finding{
		{ID: "f-1", DetectionID: "auth-brute-force", Title: "Brute force", Severity: "medium", Status: findings.StatusNew,
			Result: map[string]any{"count": 40}, Entities: map[string]any{"user": []any{"bob"}, "src": []any{"a", "b"}},
			Created: now, Updated: now},
		{ID: "f-gone", DetectionID: "no-such-detection", Title: "Old", Severity: "low", Status: findings.StatusNew,
			Result: map[string]any{"user": "eve"}, Created: now, Updated: now},
	} {
		if err := store.Create(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		id, body string
		code     int
	}{
		{"f-1", `{`, 400},
		{"f-1", `{"fields":["user"],"update":{"status":"nonsense"}}`, 400},
		{"f-1", `{"fields":["src"]}`, 400}, // two values, not one
		{"f-1", `{"fields":["user"],"for":"soon"}`, 400},
		{"f-gone", `{"fields":["user"]}`, 404},
	} {
		if code, out := do(t, ts, "POST", "/api/findings/"+c.id+"/suppress", c.body, true); code != c.code {
			t.Errorf("%s %s: %d %v", c.id, c.body, code, out)
		}
	}
	code, out := do(t, ts, "POST", "/api/findings/f-1/suppress", `{"fields":["user"]}`, true)
	if code != http.StatusOK {
		t.Fatalf("suppress: %d %v", code, out)
	}
	if m := out["exception"].(map[string]any)["match"].(map[string]any); m["user"] != "bob" {
		t.Errorf("match %v", m)
	}
	store.failing(errDown)
	if code, _ := do(t, ts, "POST", "/api/findings/f-1/suppress", `{"fields":["user"]}`, true); code != http.StatusBadGateway {
		t.Errorf("store fails: %d", code)
	}
	store.failing(nil)
}
