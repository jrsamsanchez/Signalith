// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"strconv"
	"testing"
	"time"
)

// Each key has its own limit within Per, and every key together the
// server's within AllPer; the wait is until the oldest take ages out.
func TestTokenRateLimits(t *testing.T) {
	now := time.Now()
	r := &tokenRate{Each: 2, Per: time.Minute, All: 3, AllPer: time.Hour}
	for i := range 2 {
		if w := r.take("ana", now.Add(time.Duration(i)*time.Second)); w != 0 {
			t.Fatalf("take %d: wait %v", i, w)
		}
	}
	if w := r.take("ana", now.Add(2*time.Second)); w != time.Minute-2*time.Second {
		t.Errorf("ana's third: wait %v", w)
	}
	// Another key still may, until the server's limit.
	if w := r.take("bob", now.Add(3*time.Second)); w != 0 {
		t.Errorf("bob: wait %v", w)
	}
	if w := r.take("carol", now.Add(4*time.Second)); w != time.Hour-4*time.Second {
		t.Errorf("server limit: wait %v, want until the first take ages out", w)
	}
	// A minute on, ana's own window has passed but the server's has not.
	if w := r.take("ana", now.Add(2*time.Minute)); w <= 0 || w > time.Hour {
		t.Errorf("after a minute: wait %v", w)
	}
	// An hour on, every window has passed.
	if w := r.take("ana", now.Add(2*time.Hour)); w != 0 {
		t.Errorf("after an hour: wait %v", w)
	}
}

// The empty key counts only toward the server's limit, and a server
// limit of none answers the whole window.
func TestTokenRateEmptyKey(t *testing.T) {
	now := time.Now()
	r := &tokenRate{Each: 1, All: 2, AllPer: time.Hour}
	for i := range 2 {
		if w := r.take("", now); w != 0 {
			t.Fatalf("empty key %d: wait %v", i, w)
		}
	}
	if w := r.take("", now); w <= 0 {
		t.Errorf("empty key past the server's limit: wait %v", w)
	}
	// Fresh reserves all of All for keys never seen: the empty key and
	// keys seen before get none.
	z := &tokenRate{All: 2, Fresh: 2, AllPer: time.Hour}
	if w := z.take("", now); w != time.Hour {
		t.Errorf("no room for the empty key: wait %v", w)
	}
}

// Fresh keeps part of the server's limit for keys that took none
// within AllPer, so one sender taking again and again cannot keep new
// ones out; FreshKey counts a wider network as one key.
func TestTokenRateFresh(t *testing.T) {
	now := time.Now()
	wide := func(k string) string { return k[:1] }
	r := &tokenRate{Each: 100, Per: time.Minute, All: 3, AllPer: time.Hour, Fresh: 2, FreshKey: wide}
	if w := r.take("a1", now); w != 0 {
		t.Fatalf("first: %v", w)
	}
	// a2 is in the same wider network as a1, which took already: only
	// All-Fresh (1) is open to it, and that one is used.
	if w := r.take("a2", now.Add(time.Second)); w == 0 {
		t.Error("a2 took from the fresh room")
	}
	// A new network still gets in.
	if w := r.take("b1", now.Add(2*time.Second)); w != 0 {
		t.Errorf("b1: %v", w)
	}
}

// Keys and senders not seen for a while are dropped, so a flood of keys
// does not grow the maps without bound.
func TestTokenRatePrunesOldKeys(t *testing.T) {
	now := time.Now()
	r := &tokenRate{Each: 1, Per: time.Minute, All: 2, AllPer: time.Minute, Fresh: 1}
	for i := range 10 {
		r.take("k"+strconv.Itoa(i), now.Add(-time.Hour))
	}
	r.byUser["old"] = []time.Time{now.Add(-time.Hour)}
	r.byUser["recent"] = []time.Time{now.Add(-time.Second)}
	for i := range 6 {
		r.byUser["x"+strconv.Itoa(i)] = []time.Time{now.Add(-time.Hour)}
		r.seen["s"+strconv.Itoa(i)] = now.Add(-time.Hour)
	}
	r.take("new", now)
	if _, ok := r.byUser["old"]; ok {
		t.Error("an old key was kept")
	}
	if _, ok := r.byUser["recent"]; !ok {
		t.Error("a recent key was dropped")
	}
	if _, ok := r.seen["s0"]; ok {
		t.Error("an old sender was kept")
	}
}
