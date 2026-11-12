// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// bigResultSearch is RT-02's search: 25 KB of text that asks for a 250 MB
// result, built from one shared value in a few milliseconds.
func bigResultSearch(t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"query": `| makeresults count=10000 | eval a="` + strings.Repeat("a", 25_000) + `"`, "earliest": "-1h"})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestLargeSearchResultIsRefused reproduces RT-02 (SRCH-01): the search
// above passed every limit, and the API then built its 238 MB response in
// memory after the search had freed its slot. It is now refused with the
// limit it hit, for a viewer and for a demo visitor.
func TestLargeSearchResultIsRefused(t *testing.T) {
	ts, _ := newSensorServer(t)
	code, out, raw := call(t, ts, "POST", "/api/search", bigResultSearch(t), "vera", "role-password", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("search = %d %.200s, want 400", code, raw)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "MB a search may return") {
		t.Errorf("error = %q, want the result cap named", msg)
	}

	ts, _ = newDemoServer(t)
	code, out, raw = call(t, ts, "POST", "/api/search", bigResultSearch(t), "", "", demoVisit(t, ts))
	if code != http.StatusBadRequest {
		t.Fatalf("demo search = %d %.200s, want 400", code, raw)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "MB a search may return") {
		t.Errorf("demo error = %q, want the result cap named", msg)
	}
}

// TestSearchResultIsWrittenRowByRow: the Search page's result, written one
// row at a time, reads back as the same JSON writeJSON wrote.
func TestSearchResultIsWrittenRowByRow(t *testing.T) {
	for _, res := range []*search.Result{
		{Kind: "events", Columns: []string{"user", "n"}, Matched: 3, Sampled: 2, TookMS: 4,
			Rows:  []search.Row{{"user": "bob <b@x>", "n": int64(1)}, {"user": "amy", "tags": []any{"a", "b"}}},
			Drill: &query.Drill{}},
		{Kind: "table", Columns: []string{"count"}, Rows: []search.Row{}},
	} {
		want := httptest.NewRecorder()
		writeJSON(want, http.StatusOK, res)
		got := httptest.NewRecorder()
		writeSearchResult(got, res)
		var a, b any
		if err := json.Unmarshal(want.Body.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(got.Body.Bytes(), &b); err != nil {
			t.Fatalf("%v: %s", err, got.Body)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("streamed\n%s\nwant\n%s", got.Body, want.Body)
		}
		if got.Code != http.StatusOK || got.Header().Get("Content-Type") != "application/json" {
			t.Errorf("status %d, type %q", got.Code, got.Header().Get("Content-Type"))
		}
		if len(res.Rows) > 0 && !strings.Contains(got.Body.String(), `<b@x>`) {
			t.Errorf("HTML characters escaped: %s", got.Body)
		}
	}
}

// TestSearchesAreRateLimited: a user may start searchBurst searches at
// once, then one a second; the next is answered 429 with when to retry.
func TestSearchesAreRateLimited(t *testing.T) {
	ts, _ := newSensorServer(t)
	body := `{"query":"| makeresults","earliest":"-1h"}`
	for i := range searchBurst {
		if code, _, raw := call(t, ts, "POST", "/api/search", body, "vera", "role-password", nil); code != http.StatusOK {
			t.Fatalf("search %d = %d %.200s", i+1, code, raw)
		}
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/search", strings.NewReader(body))
	req.SetBasicAuth("vera", "role-password")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" || out["code"] != "search_rate" {
		t.Errorf("search %d = %d %v (Retry-After %q), want 429", searchBurst+1, resp.StatusCode, out, resp.Header.Get("Retry-After"))
	}
	// Routes that run no search are not counted.
	if code, _, raw := call(t, ts, "POST", "/api/explain", body, "vera", "role-password", nil); code != http.StatusOK {
		t.Errorf("explain = %d %.200s", code, raw)
	}
}

// TestSearchRateRefills: the bucket refills at one search a second, and
// keys that have refilled are forgotten once there are many.
func TestSearchRateRefills(t *testing.T) {
	var l searchLimits
	now := time.Now()
	for range searchBurst {
		if wait := l.take("u", now); wait != 0 {
			t.Fatalf("wait %v within the burst", wait)
		}
	}
	if wait := l.take("u", now); wait <= 0 || wait > searchEvery {
		t.Errorf("wait = %v, want up to %v", wait, searchEvery)
	}
	if wait := l.take("other", now); wait != 0 {
		t.Errorf("another user waits %v", wait)
	}
	if wait := l.take("u", now.Add(searchEvery)); wait != 0 {
		t.Errorf("after %v: wait %v", searchEvery, wait)
	}
	for i := range 5000 {
		l.take(fmt.Sprint("k", i), now)
	}
	l.take("last", now.Add(time.Hour))
	if n := len(l.buckets); n > 10 {
		t.Errorf("%d buckets kept after they all refilled", n)
	}
}

// TestSearchTurns: one user has at most searchesPerUser searches running
// or answering at once, the public demo's visitors together half of
// searchesInFlight, and nothing is kept for users with none.
func TestSearchTurns(t *testing.T) {
	old := searchQueueWait
	searchQueueWait = 30 * time.Millisecond
	defer func() { searchQueueWait = old }()
	var l searchLimits
	r := httptest.NewRequest("POST", "/api/search", nil)
	var held []func()
	for range searchesPerUser {
		release, err := l.turn(r, "alice", false)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, release)
	}
	if _, err := l.turn(r, "alice", false); !errors.Is(err, search.ErrUserBusy) {
		t.Errorf("alice's extra search: %v, want ErrUserBusy", err)
	}
	for i := range searchesInFlight / 2 {
		release, err := l.turn(r, fmt.Sprint("demo@", i), true)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, release)
	}
	if _, err := l.turn(r, "demo@x", true); !errors.Is(err, search.ErrBusy) {
		t.Errorf("one more demo visitor: %v, want ErrBusy", err)
	}
	// Signed-in users still have room.
	release, err := l.turn(r, "bob", false)
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	held = append(held, release)
	for _, release := range held {
		release()
	}
	if len(l.users) != 0 || len(l.all) != 0 || len(l.demo) != 0 {
		t.Errorf("after every search: %d users, %d in flight, %d demo", len(l.users), len(l.all), len(l.demo))
	}
}

// deadlineRecorder records the write deadline a handler sets.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadline = t
	return nil
}

// TestSearchResponseHasAWriteDeadline: a client gets searchWriteTimeout to
// read a search's response from when it starts, not the server's 10
// minutes.
func TestSearchResponseHasAWriteDeadline(t *testing.T) {
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	w := &deadlineWriter{ResponseWriter: rec, d: searchWriteTimeout}
	if !rec.deadline.IsZero() {
		t.Fatal("deadline set before the response started")
	}
	start := time.Now()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	if d := rec.deadline.Sub(start); d < searchWriteTimeout-time.Second || d > searchWriteTimeout+time.Second {
		t.Errorf("deadline in %v, want %v", d, searchWriteTimeout)
	}
}
