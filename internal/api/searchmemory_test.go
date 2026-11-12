// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"testing"
)

// heavySearch is RT-203's search: 20 KB of text that asks for a
// 10,000-value field on each of 10,000 rows.
func heavySearch(t *testing.T) string {
	t.Helper()
	list := strings.Repeat("a,", 9999) + "a"
	body, err := json.Marshal(map[string]any{"query": `| makeresults count=10000 | eval a=split("` + list + `",",") | stats count`, "earliest": "-1h"})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestHeavyMultivalueSearchIsRefused: a viewer's 20 KB search that used to
// hold almost 4 GB is answered 400 with the limit it hit, after a bounded
// amount of memory (RT-203).
func TestHeavyMultivalueSearchIsRefused(t *testing.T) {
	ts, _ := newSensorServer(t)
	body := heavySearch(t)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	code, out, raw := call(t, ts, "POST", "/api/search", body, "vera", "role-password", nil)
	runtime.ReadMemStats(&after)
	if code != http.StatusBadRequest {
		t.Fatalf("search = %d %.200s, want 400", code, raw)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "multivalue fields hold more than a search may build") {
		t.Errorf("error = %q, want the multivalue budget named", msg)
	}
	// Everything allocated while it ran, kept or not; it was 3.8 GB held.
	// (Not under the race detector, where the regexp package allocates a
	// matcher for every call and the count says nothing.)
	if mb := (after.TotalAlloc - before.TotalAlloc) >> 20; mb > 768 && !raceOn {
		t.Errorf("the refused search allocated %d MB", mb)
	}
	t.Logf("allocated %d MB", (after.TotalAlloc-before.TotalAlloc)>>20)
}

// TestDemoVisitorHeavySearchIsRefused: an anonymous visitor of a public
// demo gets the same answer.
func TestDemoVisitorHeavySearchIsRefused(t *testing.T) {
	ts, _ := newDemoServer(t)
	c := demoVisit(t, ts)
	code, out, raw := call(t, ts, "POST", "/api/search", heavySearch(t), "", "", c)
	if code != http.StatusBadRequest {
		t.Fatalf("search = %d %.200s, want 400", code, raw)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "multivalue") {
		t.Errorf("error = %q, want the multivalue budget named", msg)
	}
}
