// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/search"
)

// epochServer is one server's scheduler over the shared run store, with
// its own view of the lease epoch and of the cluster level.
type epochServer struct {
	*Scheduler
	lease   atomic.Int64
	counter atomic.Bool
}

func newEpochServer(t *testing.T, lib *Library, run Runner, clock *fakeClock, rs RunStore, node string, lease int64, counter bool) *epochServer {
	t.Helper()
	e := &epochServer{Scheduler: newTestScheduler(lib, run, clock)}
	e.Runtime, e.NodeID = rs, node
	e.lease.Store(lease)
	e.counter.Store(counter)
	e.Epoch, e.Counter = e.lease.Load, e.counter.Load
	return e
}

func storedState(t *testing.T, s *Scheduler, id string) DetState {
	t.Helper()
	raw, _, found, err := s.Runtime.Get(context.Background(), s.runtimeIndex(), detStateID(id))
	if err != nil || !found {
		t.Fatalf("no stored state for %s: %v", id, err)
	}
	return decodeState(t, raw)
}

func storedEpoch(t *testing.T, s *Scheduler) epochDoc {
	t.Helper()
	raw, _, found, err := s.Runtime.Get(context.Background(), s.runtimeIndex(), detEpochID)
	if err != nil || !found {
		t.Fatalf("no detepoch document: %v", err)
	}
	var d epochDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestDetectionEpochCounter: with the counter on, the run state and the
// throttles carry numbers from the detepoch document, bigger than the
// lease epochs written before, ordered by lease epoch; a server whose
// lease is older can neither take a number nor write over the state, and
// one that has not seen the level yet stops rather than write.
func TestDetectionEpochCounter(t *testing.T) {
	d := &Detection{ID: "rule-n", Title: "N", Query: "user=n", Enabled: true, Schedule: "5m", Lookback: "5m",
		Throttle: Throttle{Window: "1h", Fields: []string{"user"}}}
	lib := OnlyRules(t, d)
	run := &recRunner{rows: map[string][]search.Row{"user=n": {{"user": "bob"}}}}
	clock := &fakeClock{t: t0}
	rs := NewMemoryRunStore()
	ctx := context.Background()

	// Before the level: the lease epoch, as before.
	a := newEpochServer(t, lib, run, clock, rs, "a", 5, false)
	a.RunDue(ctx)
	if st := storedState(t, a.Scheduler, "rule-n"); st.Epoch != 5 || st.DetEpoch != 0 {
		t.Fatalf("before the level: epoch %d/%d", st.Epoch, st.DetEpoch)
	}

	// The level rises: the same holder reads the state again under a
	// number from the counter, at least the lease epoch's first.
	a.counter.Store(true)
	clock.Add(5 * time.Minute)
	a.RunDue(ctx)
	st := storedState(t, a.Scheduler, "rule-n")
	if st.Epoch != 5 || st.DetEpoch != FirstEpoch(5) || st.Node != "a" {
		t.Fatalf("after the level: epoch %d/%d node %q, want 5/%d", st.Epoch, st.DetEpoch, st.Node, FirstEpoch(5))
	}
	if doc := storedEpoch(t, a.Scheduler); doc.Epoch != FirstEpoch(5) || doc.Lease != 5 || doc.Node != "a" {
		t.Errorf("detepoch %+v", doc)
	}
	raw, _, found, err := rs.Get(ctx, a.runtimeIndex(), throttleID("rule-n", GroupKey(d, map[string]any{"user": "bob"})))
	if err != nil || !found {
		t.Fatalf("no throttle: %v", err)
	}
	var th throttleDoc
	if err := json.Unmarshal(raw, &th); err != nil || th.Epoch != 5 || th.DetEpoch != FirstEpoch(5) {
		t.Errorf("throttle epoch %d/%d, %v", th.Epoch, th.DetEpoch, err)
	}

	// Taking another number under the same lease gives the next one.
	if n, err := a.claimEpoch(ctx, 5); err != nil || n != FirstEpoch(5)+1 {
		t.Errorf("second claim under lease 5: %d, %v", n, err)
	}

	// Server b takes the lease over (epoch 6).
	b := newEpochServer(t, lib, run, clock, rs, "b", 6, true)
	clock.Add(5 * time.Minute)
	b.RunDue(ctx)
	if st := storedState(t, b.Scheduler, "rule-n"); st.DetEpoch != FirstEpoch(6) || st.Node != "b" {
		t.Fatalf("after the takeover: epoch %d node %q", st.DetEpoch, st.Node)
	}

	// a, still thinking it holds lease 5, can neither take a number nor
	// write over b's state.
	if _, err := a.claimEpoch(ctx, 5); !errors.Is(err, errStaleEpoch) {
		t.Errorf("a claim under an older lease: %v", err)
	}
	e, ok := a.entry("rule-n")
	if !ok {
		t.Fatal("a has no copy")
	}
	e.doc.LastError = "stale"
	if _, err := a.writeState(ctx, e, 5); !errors.Is(err, errStaleEpoch) {
		t.Fatalf("a's write over b's state: %v", err)
	}
	if st := storedState(t, b.Scheduler, "rule-n"); st.Node != "b" || st.LastError != "" {
		t.Errorf("a wrote over b: %+v", st)
	}

	// A server with a newer lease that has not seen the level yet would
	// write plain lease epochs: it stops instead of writing.
	c := newEpochServer(t, lib, run, clock, rs, "c", 7, false)
	before := storedState(t, b.Scheduler, "rule-n")
	clock.Add(5 * time.Minute)
	c.RunDue(ctx)
	if st := storedState(t, c.Scheduler, "rule-n"); st.DetEpoch != before.DetEpoch || st.Node != "b" {
		t.Errorf("a server below the level wrote: %+v", st)
	}
	// Once it sees the level, it runs and catches up.
	c.counter.Store(true)
	c.RunDue(ctx)
	if st := storedState(t, c.Scheduler, "rule-n"); st.DetEpoch != FirstEpoch(7) || st.Node != "c" || !st.LastSlot.After(before.LastSlot) {
		t.Errorf("after c sees the level: %+v", st)
	}
}

// TestDetectionEpochLimits: lease epochs that cannot give a number are
// refused, and an unreadable detepoch document stops the schedule rather
// than starting the numbers again.
func TestDetectionEpochLimits(t *testing.T) {
	s := newTestScheduler(OnlyRules(t), &recRunner{}, &fakeClock{t: t0})
	s.Runtime = NewMemoryRunStore()
	ctx := context.Background()
	for _, lease := range []int64{0, -1, 1 << (62 - epochShift)} {
		if _, err := s.claimEpoch(ctx, lease); err == nil {
			t.Errorf("lease %d gave a number", lease)
		}
	}
	if _, err := s.Runtime.Create(ctx, s.runtimeIndex(), detEpochID, map[string]any{"kind": "other"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.claimEpoch(ctx, 1); err == nil {
		t.Error("an unreadable detepoch document was written over")
	}
}

// TestScheduledThrottleNeedsADetectionEpoch: with the counter on, a
// scheduled run whose copy was not read under the current lease cannot
// claim a throttle with the plain lease epoch; Run now still can.
func TestScheduledThrottleNeedsADetectionEpoch(t *testing.T) {
	d := &Detection{ID: "rule-t", Title: "T", Query: "user=t", Enabled: true, Schedule: "5m", Lookback: "5m",
		Throttle: Throttle{Window: "1h", Fields: []string{"user"}}}
	clock := &fakeClock{t: t0}
	s := newEpochServer(t, OnlyRules(t, d), &recRunner{}, clock, NewMemoryRunStore(), "a", 3, true)
	ctx := context.Background()
	if _, err := s.claim(ctx, d, "k", t0, t0, time.Hour, "f1", nil); !errors.Is(err, errStaleEpoch) {
		t.Errorf("a scheduled claim without a detection epoch: %v", err)
	}
	if ok, err := s.claim(ctx, d, "k", time.Time{}, t0, time.Hour, "f2", nil); err != nil || !ok {
		t.Errorf("a Run now claim: %v, %v", ok, err)
	}
}
