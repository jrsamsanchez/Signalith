// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package summary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// testClock is a settable clock for the builder.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newBuilder returns a builder over a fake whose clock stands 3 minutes
// past the hour, so one tick of a one-day range builds all of it.
func newBuilder(t *testing.T) (*Builder, *fakeClient, *testClock) {
	t.Helper()
	f := newFake("sig")
	clk := &testClock{t: time.Now().UTC().Truncate(time.Hour).Add(3 * time.Minute)}
	b := &Builder{
		Client:  f,
		Prefix:  "sig",
		Runtime: "sig_runtime",
		Days:    func() int { return 1 },
		Now:     clk.Now,
		Epoch:   func() int64 { return 1 },
		Node:    "node-a",
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return b, f, clk
}

// target is where a tick at clk's time builds up to.
func target(clk *testClock) time.Time { return clk.Now().Add(-Settle).Truncate(Slot) }

func mustTick(t *testing.T, b *Builder) {
	t.Helper()
	if err := b.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
}

func mustState(t *testing.T, f *fakeClient, model string) State {
	t.Helper()
	st, ok := f.state(model)
	if !ok {
		t.Fatalf("no state for %s", model)
	}
	return st
}

func TestTickBuildsRowsPerSlotAndDimensions(t *testing.T) {
	b, f, clk := newBuilder(t)
	now := clk.Now()
	a := now.Add(-90 * time.Minute)
	for range 3 {
		f.add("Authentication", a, map[string]any{"user": "alice", "action": "success"})
	}
	f.add("Authentication", a, map[string]any{"user": "bob", "action": "failure"})
	f.add("Authentication", now.Add(-40*time.Minute), map[string]any{"user": "alice", "action": "success"})
	f.add("Authentication", now.Add(-40*time.Minute), map[string]any{"user": "alice", "action": "success"})
	f.add("Network_Traffic", a, map[string]any{"src": "10.0.0.1", "bytes": 100})
	f.add("Network_Traffic", a, map[string]any{"src": "10.0.0.1", "bytes": 50})
	// An event that is not settled yet is left for a later tick.
	f.add("Authentication", now.Add(-time.Minute), map[string]any{"user": "carol"})

	mustTick(t, b)

	st := mustState(t, f, "Authentication")
	start := now.Add(-24 * time.Hour).Truncate(Slot)
	if !st.From.Equal(start) || !st.Through.Equal(target(clk)) {
		t.Errorf("state covers [%v, %v), want [%v, %v)", st.From, st.Through, start, target(clk))
	}
	if st.Rows != 3 || st.Epoch != 1 || st.Node != "node-a" || st.Layout != layout("Authentication") {
		t.Errorf("state = %+v", st)
	}
	if st.CheckedAll.IsZero() || st.CheckedRecent.IsZero() || st.LastBuild.IsZero() {
		t.Errorf("checks not recorded: %+v", st)
	}
	if rows, events := f.rowCount("Authentication"); rows != 3 || events != 6 {
		t.Errorf("Authentication rows = %d standing for %d events, want 3 and 6", rows, events)
	}
	// The network row sums its measure.
	var found bool
	for _, r := range f.rows {
		if r.Doc[ModelField] != "Network_Traffic" {
			continue
		}
		found = true
		if r.Doc["bytes"] != 150.0 || r.Doc["src"] != "10.0.0.1" || r.Doc[CountField] != 2.0 {
			t.Errorf("network row = %v", r.Doc)
		}
		if _, ok := r.Doc["bytes_in"]; ok {
			t.Errorf("a measure that sums to 0 is stored: %v", r.Doc)
		}
		if want := indexName("sig", a); r.Index != want {
			t.Errorf("row index %s, want %s", r.Index, want)
		}
	}
	if !found {
		t.Fatal("no Network_Traffic row")
	}
	// Every model has a state, even those without events.
	for _, m := range Models() {
		if _, ok := f.state(m); !ok {
			t.Errorf("no state for %s", m)
		}
	}

	// Coverage reads the states.
	c := &Coverage{Client: f, Runtime: "sig_runtime"}
	c.Refresh(context.Background())
	if got := c.Ranges("Authentication"); len(got) != 1 || !got[0].From.Equal(start) || !got[0].To.Equal(target(clk)) {
		t.Errorf("Coverage.Ranges = %v", got)
	}
	sts, read, err := c.Status()
	if err != nil || read.IsZero() || len(sts) != len(Models()) {
		t.Errorf("Status = %d states, %v, %v", len(sts), read, err)
	}

	// A second tick with nothing new writes no rows.
	before := len(f.rows)
	mustTick(t, b)
	if len(f.rows) != before {
		t.Errorf("rows went from %d to %d", before, len(f.rows))
	}
}

func TestTickRebuildsSlotsWhoseEventsChanged(t *testing.T) {
	b, f, clk := newBuilder(t)
	at := clk.Now().Add(-90 * time.Minute)
	f.add("Authentication", at, map[string]any{"user": "alice"})
	mustTick(t, b)

	// A late event lands in a slot already summarized.
	f.add("Authentication", at, map[string]any{"user": "alice"})
	f.add("Authentication", at, map[string]any{"user": "dave"})
	clk.Advance(recentEvery + time.Minute)
	mustTick(t, b)

	st := mustState(t, f, "Authentication")
	if st.Rebuilt != 1 {
		t.Errorf("Rebuilt = %d, want 1", st.Rebuilt)
	}
	if rows, events := f.rowCount("Authentication"); rows != 2 || events != 3 {
		t.Errorf("rows = %d for %d events, want 2 and 3", rows, events)
	}

	// An event that goes (sample data removed) makes its row go too.
	f.mu.Lock()
	f.events = slices.DeleteFunc(f.events, func(e fakeEvent) bool { return e.f["user"] == "dave" })
	f.mu.Unlock()
	clk.Advance(recentEvery + time.Minute)
	mustTick(t, b)
	if rows, events := f.rowCount("Authentication"); rows != 1 || events != 2 {
		t.Errorf("after the event went: rows = %d for %d events, want 1 and 2", rows, events)
	}
}

func TestVerifyRebuildsAtMostMaxRebuildsAtOnce(t *testing.T) {
	b, f, clk := newBuilder(t)
	now := clk.Now()
	f.add("Authentication", now.Add(-20*time.Hour), map[string]any{"user": "x"})
	mustTick(t, b)
	// maxRebuilds+5 separate slots change.
	base := now.Add(-15 * time.Hour).Truncate(Slot)
	for i := range maxRebuilds + 5 {
		f.add("Authentication", base.Add(time.Duration(i)*2*Slot), map[string]any{"user": "late"})
	}
	clk.Advance(recentEvery + time.Minute)
	mustTick(t, b)
	if st := mustState(t, f, "Authentication"); st.Rebuilt != maxRebuilds {
		t.Errorf("Rebuilt = %d, want %d", st.Rebuilt, maxRebuilds)
	}
	clk.Advance(recentEvery + time.Minute)
	mustTick(t, b)
	if st := mustState(t, f, "Authentication"); st.Rebuilt != maxRebuilds+5 {
		t.Errorf("Rebuilt = %d, want %d", st.Rebuilt, maxRebuilds+5)
	}
	if _, events := f.rowCount("Authentication"); events != maxRebuilds+6 {
		t.Errorf("rows stand for %d events, want %d", events, maxRebuilds+6)
	}
}

func TestVerifyFailureMakesAGap(t *testing.T) {
	b, f, clk := newBuilder(t)
	at := clk.Now().Add(-90 * time.Minute)
	f.add("Authentication", at, map[string]any{"user": "alice"})
	mustTick(t, b)
	f.add("Authentication", at, map[string]any{"user": "bob"})
	f.bulkErrs = []store.BulkItemError{{Index: "x", Reason: "mapper_parsing_exception"}}
	clk.Advance(recentEvery + time.Minute)
	mustTick(t, b)
	st := mustState(t, f, "Authentication")
	slot := at.Truncate(Slot)
	if len(st.Gaps) != 1 || !st.Gaps[0].From.Equal(slot) || !st.Gaps[0].To.Equal(slot.Add(Slot)) {
		t.Errorf("gaps = %v, want the slot at %v", st.Gaps, slot)
	}
	// Searches read that slot from the events.
	for _, r := range st.Covered() {
		if !slot.Before(r.From) && slot.Before(r.To) {
			t.Errorf("the failed slot is still covered by %v", r)
		}
	}
}

func TestCompositePages(t *testing.T) {
	b, f, clk := newBuilder(t)
	at := clk.Now().Add(-90 * time.Minute)
	n := firstPage + 50
	for i := range n {
		f.add("Authentication", at, map[string]any{"user": fmt.Sprintf("user%03d", i)})
	}
	mustTick(t, b)
	if f.pages < 2 {
		t.Errorf("%d composite pages read, want more than one", f.pages)
	}
	if rows, events := f.rowCount("Authentication"); rows != n || events != int64(n) {
		t.Errorf("rows = %d for %d events, want %d", rows, events, n)
	}
}

func TestTooManyRowsMakeAGap(t *testing.T) {
	b, f, clk := newBuilder(t)
	b.MaxRows = 2
	at := clk.Now().Add(-90 * time.Minute)
	keep := clk.Now().Add(-30 * time.Minute)
	for _, u := range []string{"a", "b", "c"} {
		f.add("Authentication", at, map[string]any{"user": u})
	}
	f.add("Authentication", keep, map[string]any{"user": "a"})
	mustTick(t, b)
	st := mustState(t, f, "Authentication")
	chunkStart := at.Truncate(chunk)
	if len(st.Gaps) != 1 || !st.Gaps[0].From.Equal(chunkStart) || !st.Gaps[0].To.Equal(chunkStart.Add(chunk)) {
		t.Errorf("gaps = %v, want the hour from %v", st.Gaps, chunkStart)
	}
	if rows, _ := f.rowCount("Authentication"); rows != 1 {
		t.Errorf("%d rows, want only the one of the small hour", rows)
	}
}

func TestResponseTooLargeMakesAGapAndMissingIndexIsEmpty(t *testing.T) {
	b, f, clk := newBuilder(t)
	at := clk.Now().Add(-90 * time.Minute)
	f.add("Authentication", at, map[string]any{"user": "a"})
	f.add("Network_Traffic", at, map[string]any{"src": "a"})
	f.fail = func(op, detail string) error {
		switch detail {
		case rawPattern("sig", "Authentication") + " g":
			return fmt.Errorf("read: %w", store.ErrResponseTooLarge)
		case rawPattern("sig", "Network_Traffic") + " g":
			return &store.Error{Status: http.StatusNotFound, Body: "{}"}
		}
		return nil
	}
	mustTick(t, b)
	if st := mustState(t, f, "Authentication"); len(st.Gaps) != 1 {
		t.Errorf("Authentication gaps = %v, want one", st.Gaps)
	}
	st := mustState(t, f, "Network_Traffic")
	if len(st.Gaps) != 0 || !st.Through.Equal(target(clk)) {
		t.Errorf("Network_Traffic state = %+v", st)
	}
}

func TestChunkThatKeepsFailingBecomesAGap(t *testing.T) {
	b, f, clk := newBuilder(t)
	at := clk.Now().Add(-90 * time.Minute)
	f.add("Authentication", at, map[string]any{"user": "a"})
	f.bulkErrs = []store.BulkItemError{{Index: "x", Reason: "refused for a test"}}
	for i := 1; i < maxFailures; i++ {
		err := b.Tick(context.Background())
		if err == nil || !strings.Contains(err.Error(), "refused for a test") || !strings.Contains(err.Error(), "Authentication") {
			t.Fatalf("tick %d: %v", i, err)
		}
		if st := mustState(t, f, "Authentication"); !strings.Contains(st.LastError, "refused for a test") {
			t.Errorf("tick %d: LastError = %q", i, st.LastError)
		}
	}
	mustTick(t, b)
	st := mustState(t, f, "Authentication")
	if len(st.Gaps) != 1 || st.LastError != "" || !st.Through.Equal(target(clk)) {
		t.Errorf("after %d failures: %+v", maxFailures, st)
	}
}

func TestBuildErrors(t *testing.T) {
	cases := []struct {
		name string
		fail func(op, detail string) error
		want string
	}{
		{"bulk", func(op, _ string) error {
			if op == "bulk" {
				return errors.New("bulk down")
			}
			return nil
		}, "bulk down"},
		{"create index", func(op, detail string) error {
			if op == "do" && strings.HasPrefix(detail, "PUT") {
				return errors.New("disk full")
			}
			return nil
		}, "could not create sig_summary-"},
		{"refresh", func(op, detail string) error {
			if op == "do" && strings.Contains(detail, "_refresh") {
				return errors.New("refresh down")
			}
			return nil
		}, "refresh down"},
		{"histogram", func(op, detail string) error {
			if op == "search" && strings.HasSuffix(detail, " h") {
				return errors.New("search down")
			}
			return nil
		}, "search down"},
		{"composite", func(op, detail string) error {
			if op == "search" && strings.HasSuffix(detail, " g") {
				return errors.New("agg down")
			}
			return nil
		}, "agg down"},
		{"state read", func(op, _ string) error {
			if op == "get" {
				return errors.New("get down")
			}
			return nil
		}, "get down"},
		{"state write", func(op, _ string) error {
			if op == "create" {
				return errors.New("create down")
			}
			return nil
		}, "create down"},
		{"delete by query", func(op, detail string) error {
			if op == "do" && strings.Contains(detail, "_delete_by_query") {
				return errors.New("dbq down")
			}
			return nil
		}, "dbq down"},
		{"list indices", func(op, _ string) error {
			if op == "list" {
				return errors.New("cat down")
			}
			return nil
		}, "cat down"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, f, clk := newBuilder(t)
			f.add("Authentication", clk.Now().Add(-90*time.Minute), map[string]any{"user": "a"})
			f.fail = c.fail
			err := b.Tick(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Tick = %v, want %q", err, c.want)
			}
			// The fault gone, the next tick catches up.
			f.fail = nil
			mustTick(t, b)
			if st := mustState(t, f, "Authentication"); !st.Through.Equal(target(clk)) {
				t.Errorf("after the fault: through %v, want %v", st.Through, target(clk))
			}
			if _, events := f.rowCount("Authentication"); events != 1 {
				t.Errorf("rows stand for %d events, want 1", events)
			}
		})
	}
}

func TestExistingIndexAndIndexSettings(t *testing.T) {
	b, f, clk := newBuilder(t)
	b.IndexSettings = func() map[string]any { return map[string]any{"number_of_replicas": 2} }
	at := clk.Now().Add(-90 * time.Minute)
	f.add("Authentication", at, map[string]any{"user": "a"})
	// Another month's index was created by an earlier server: creating
	// it again is refused, which is fine.
	other := indexName("sig", at.AddDate(0, -1, 0))
	f.indices[other] = true
	if err := b.ensureIndex(context.Background(), other); err != nil {
		t.Fatalf("ensureIndex of an existing index: %v", err)
	}
	mustTick(t, b)
	body := f.putBodies[indexName("sig", at)]
	if body == nil {
		t.Fatal("the summary index was not created")
	}
	if got := dig(body, "settings", "number_of_replicas"); got != 2.0 {
		t.Errorf("replicas = %v", got)
	}
	if got := dig(body, "settings", "number_of_shards"); got != 1.0 {
		t.Errorf("shards = %v", got)
	}
	if got := dig(body, "mappings", "dynamic"); got != false {
		t.Errorf("dynamic = %v", got)
	}
	// Created once per builder.
	f.calls = nil
	if err := b.ensureIndex(context.Background(), indexName("sig", at)); err != nil || len(f.calls) != 0 {
		t.Errorf("ensureIndex again: %v, calls %v", err, f.calls)
	}
}

func TestTickDoesNothingWithoutDaysOrLease(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*Builder)
	}{
		{"no days func", func(b *Builder) { b.Days = nil }},
		{"zero days", func(b *Builder) { b.Days = func() int { return 0 } }},
		{"not the jobs server", func(b *Builder) { b.Allowed = func() bool { return false } }},
		{"retention unknown", func(b *Builder) { b.KeepDays = func(string) (int, bool) { return 0, false } }},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, f, clk := newBuilder(t)
			f.add("Authentication", clk.Now().Add(-90*time.Minute), map[string]any{"user": "a"})
			c.set(b)
			mustTick(t, b)
			if len(f.rows) != 0 || len(f.runtime) != 0 {
				t.Errorf("wrote %d rows and %d states", len(f.rows), len(f.runtime))
			}
		})
	}
}

func TestKeepDaysShortensTheRange(t *testing.T) {
	b, f, clk := newBuilder(t)
	b.Days = func() int { return 30 }
	b.KeepDays = func(m string) (int, bool) {
		if m == "Authentication" {
			return 1, true
		}
		return 0, true // kept forever: summary_days rules
	}
	mustTick(t, b)
	now := clk.Now()
	if st := mustState(t, f, "Authentication"); !st.From.Equal(now.Add(-24 * time.Hour).Truncate(Slot)) {
		t.Errorf("Authentication from %v", st.From)
	}
	if st := mustState(t, f, "Network_Traffic"); !st.From.Equal(now.Add(-30 * 24 * time.Hour).Truncate(Slot)) {
		t.Errorf("Network_Traffic from %v", st.From)
	}
}

func TestStateOfANewerEpochIsNeverOverwritten(t *testing.T) {
	b, f, clk := newBuilder(t)
	f.add("Authentication", clk.Now().Add(-90*time.Minute), map[string]any{"user": "a"})
	newer := State{Kind: kindState, Model: Models()[0], Layout: layout(Models()[0]), Epoch: 7, Node: "node-b"}
	f.put(stateID(newer.Model), newer)
	mustTick(t, b)
	if st := mustState(t, f, newer.Model); st.Epoch != 7 || st.Node != "node-b" {
		t.Errorf("state was overwritten: %+v", st)
	}
	if len(f.rows) != 0 {
		t.Errorf("%d rows written by a stale server", len(f.rows))
	}
}

func TestSaveConflicts(t *testing.T) {
	b, f, clk := newBuilder(t)
	f.add("Authentication", clk.Now().Add(-90*time.Minute), map[string]any{"user": "a"})
	mustTick(t, b)

	// Someone of the same epoch wrote the state: the save fails, and the
	// next tick reads it again.
	st := mustState(t, f, "Authentication")
	f.put(stateID("Authentication"), st)
	clk.Advance(recentEvery + time.Minute)
	if err := b.Tick(context.Background()); !store.IsConflict(err) {
		t.Fatalf("Tick = %v, want a conflict", err)
	}
	mustTick(t, b)

	// A newer jobs server took over: this one stops quietly.
	st = mustState(t, f, "Authentication")
	st.Epoch, st.Node = 9, "node-b"
	f.put(stateID("Authentication"), st)
	clk.Advance(recentEvery + time.Minute)
	mustTick(t, b)
	if got := mustState(t, f, "Authentication"); got.Epoch != 9 || got.Node != "node-b" {
		t.Errorf("state = %+v", got)
	}
	if _, ok := b.states["Authentication"]; ok {
		t.Error("the stale state is still held")
	}
}

func TestNewLeaseRereadsStates(t *testing.T) {
	b, f, clk := newBuilder(t)
	epoch := int64(1)
	b.Epoch = func() int64 { return epoch }
	f.add("Authentication", clk.Now().Add(-90*time.Minute), map[string]any{"user": "a"})
	mustTick(t, b)
	epoch = 2
	clk.Advance(recentEvery + time.Minute)
	mustTick(t, b)
	if st := mustState(t, f, "Authentication"); st.Epoch != 2 {
		t.Errorf("epoch = %d, want 2", st.Epoch)
	}
}

func TestLayoutChangeStartsAgain(t *testing.T) {
	b, f, clk := newBuilder(t)
	now := clk.Now()
	old := State{Kind: kindState, Model: "Authentication", Layout: "older", From: now.Add(-48 * time.Hour), Through: now, Rows: 99, Epoch: 1}
	f.put(stateID("Authentication"), old)
	// A row of the old layout.
	f.rows["old"] = store.IndexedDoc{Index: indexName("sig", now), ID: "old",
		Doc: map[string]any{"@timestamp": now.Add(-time.Hour).Format(time.RFC3339), ModelField: "Authentication", CountField: 5.0}}
	// A broken state document counts as none.
	f.runtime[stateID("Network_Traffic")] = fakeDoc{raw: json.RawMessage(`{broken`), v: store.Version{SeqNo: 100, PrimaryTerm: 1}}
	mustTick(t, b)
	if _, ok := f.rows["old"]; ok {
		t.Error("the old layout's row is still there")
	}
	for _, m := range []string{"Authentication", "Network_Traffic"} {
		st := mustState(t, f, m)
		if st.Layout != layout(m) || st.Rows != 0 || !st.From.Equal(now.Add(-24*time.Hour).Truncate(Slot)) {
			t.Errorf("%s state = %+v", m, st)
		}
	}
}

func TestRangeMovesOnAndOldRowsGo(t *testing.T) {
	b, f, clk := newBuilder(t)
	now := clk.Now()
	early := now.Add(-23*time.Hour - 30*time.Minute)
	f.add("Authentication", early, map[string]any{"user": "old"})
	mustTick(t, b)
	if rows, _ := f.rowCount("Authentication"); rows != 1 {
		t.Fatalf("%d rows", rows)
	}
	// Seed a gap the range will leave behind.
	b.states["Authentication"].st.Gaps = []Gap{{From: early.Truncate(chunk), To: early.Truncate(chunk).Add(time.Minute)}}

	clk.Advance(2 * time.Hour)
	mustTick(t, b)
	st := mustState(t, f, "Authentication")
	if want := clk.Now().Add(-24 * time.Hour).Truncate(chunk); !st.From.Equal(want) {
		t.Errorf("from %v, want %v", st.From, want)
	}
	if len(st.Gaps) != 0 {
		t.Errorf("gaps before the range are kept: %v", st.Gaps)
	}
	// Rows the state stopped covering only a move ago stay ...
	if rows, _ := f.rowCount("Authentication"); rows != 1 {
		t.Errorf("%d rows after the first move, want 1", rows)
	}
	// ... and go at the next one.
	clk.Advance(2 * time.Hour)
	mustTick(t, b)
	if rows, _ := f.rowCount("Authentication"); rows != 0 {
		t.Errorf("%d rows after the second move, want 0", rows)
	}
}

func TestRaisedDaysBuildsOlderDays(t *testing.T) {
	b, f, clk := newBuilder(t)
	days := 1
	b.Days = func() int { return days }
	now := clk.Now()
	f.add("Authentication", now.Add(-36*time.Hour), map[string]any{"user": "older"})
	mustTick(t, b)
	if rows, _ := f.rowCount("Authentication"); rows != 0 {
		t.Fatalf("%d rows outside the range", rows)
	}
	days = 2
	for range 3 {
		mustTick(t, b)
	}
	st := mustState(t, f, "Authentication")
	if !st.From.Equal(now.Add(-48*time.Hour).Truncate(Slot)) || !st.Through.Equal(target(clk)) {
		t.Errorf("state covers [%v, %v)", st.From, st.Through)
	}
	if rows, _ := f.rowCount("Authentication"); rows != 1 {
		t.Errorf("%d rows, want the older day's", rows)
	}
}

func TestOrphanedRowsGo(t *testing.T) {
	b, f, clk := newBuilder(t)
	at := clk.Now().Add(-90 * time.Minute)
	f.add("Authentication", at, map[string]any{"user": "a"})
	mustTick(t, b)
	// The day's event index was deleted early (a size cap).
	f.hidden[f.rawIndex(f.events[0])] = true
	mustTick(t, b)
	st := mustState(t, f, "Authentication")
	day := at.Truncate(24 * time.Hour)
	if len(st.Gaps) != 1 || !st.Gaps[0].From.Equal(day) || !st.Gaps[0].To.Equal(day.Add(24*time.Hour)) {
		t.Errorf("gaps = %v, want the day %v", st.Gaps, day)
	}
	if rows, _ := f.rowCount("Authentication"); rows != 0 {
		t.Errorf("%d orphaned rows remain", rows)
	}
}

func TestDropMonths(t *testing.T) {
	b, f, _ := newBuilder(t)
	f.extra = []string{"sig_summary-2000.01", "sig_summary-notamonth"}
	mustTick(t, b)
	if len(f.deleted) != 0 {
		t.Fatalf("deleted %v before every model's start was known", f.deleted)
	}
	mustTick(t, b)
	if !slices.Equal(f.deleted, []string{"sig_summary-2000.01"}) {
		t.Errorf("deleted %v", f.deleted)
	}

	f.extra = []string{"sig_summary-2000.02"}
	f.fail = func(op, detail string) error {
		if op == "do" && strings.HasPrefix(detail, "DELETE") {
			return errors.New("delete down")
		}
		return nil
	}
	if err := b.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "could not delete sig_summary-2000.02") {
		t.Errorf("Tick = %v", err)
	}
	f.fail = func(op, detail string) error {
		if op == "do" && strings.HasPrefix(detail, "DELETE") {
			return &store.Error{Status: http.StatusNotFound, Body: "{}"}
		}
		return nil
	}
	mustTick(t, b) // already gone is fine
}

func TestDropMonthsStopsWhenFenced(t *testing.T) {
	b, f, _ := newBuilder(t)
	f.extra = []string{"sig_summary-2000.01"}
	mustTick(t, b)
	starts := map[string]time.Time{}
	for m, h := range b.states {
		starts[m] = h.st.From
	}
	b.Epoch = func() int64 { return 5 }
	if err := b.dropMonths(context.Background(), starts); !errors.Is(err, errStaleEpoch) {
		t.Errorf("dropMonths = %v, want errStaleEpoch", err)
	}
	if len(f.deleted) != 0 {
		t.Errorf("deleted %v", f.deleted)
	}
}

func TestDayIndicesReadParts(t *testing.T) {
	b, f, _ := newBuilder(t)
	f.extra = []string{
		"sig-authentication-2026.01.02",
		"sig-authentication-2026.01.03-2",
		"sig-authentication-notaday",
		"sig-authentication-2026.01.04-x",
	}
	days, err := b.dayIndices(context.Background(), "Authentication")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"2026.01.02": true, "2026.01.03": true}
	if len(days) != len(want) || !days["2026.01.02"] || !days["2026.01.03"] {
		t.Errorf("days = %v, want %v", days, want)
	}
	f.fail = func(op, _ string) error { return &store.Error{Status: http.StatusNotFound, Body: "{}"} }
	if days, err := b.dayIndices(context.Background(), "Authentication"); err != nil || len(days) != 0 {
		t.Errorf("no index: %v, %v", days, err)
	}
}

func TestBuildStopsWhenFenced(t *testing.T) {
	b, f, clk := newBuilder(t)
	at := clk.Now().Add(-90 * time.Minute)
	f.add("Authentication", at, map[string]any{"user": "a"})
	b.states, b.epoch = map[string]*held{}, 1
	b.Epoch = func() int64 { return 2 }
	if _, err := b.build(context.Background(), "Authentication", at.Truncate(chunk), at.Truncate(chunk).Add(chunk)); !errors.Is(err, errStaleEpoch) {
		t.Errorf("build = %v, want errStaleEpoch", err)
	}
	if err := b.deleteRows(context.Background(), "Authentication", time.Time{}, time.Time{}, ""); !errors.Is(err, errStaleEpoch) {
		t.Errorf("deleteRows = %v, want errStaleEpoch", err)
	}
	if len(f.rows) != 0 {
		t.Errorf("%d rows written", len(f.rows))
	}
}

func TestRunTicksUntilCancelled(t *testing.T) {
	b, f, clk := newBuilder(t)
	f.add("Authentication", clk.Now().Add(-90*time.Minute), map[string]any{"user": "a"})
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel once the first tick has written the last model's state.
	last := Models()[len(Models())-1]
	f.fail = func(op, detail string) error {
		if op == "create" && detail == stateID(last) {
			cancel()
		}
		return nil
	}
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()
	<-done
	if _, ok := f.state("Authentication"); !ok {
		t.Error("Run did not tick")
	}
}

func TestCoverage(t *testing.T) {
	var nilCov *Coverage
	if nilCov.Ranges("x") != nil {
		t.Error("nil Coverage has ranges")
	}
	if s, r, err := nilCov.Status(); s != nil || !r.IsZero() || err != nil {
		t.Error("nil Coverage has a status")
	}

	f := newFake("sig")
	now := time.Now().UTC().Truncate(Slot)
	good := State{Kind: kindState, Model: "Authentication", Layout: layout("Authentication"), From: now.Add(-time.Hour), Through: now}
	stale := State{Kind: kindState, Model: "Web", Layout: "old", From: now.Add(-time.Hour), Through: now}
	empty := State{Kind: kindState, Model: "Risk", Layout: layout("Risk"), From: now, Through: now}
	f.put(stateID("Authentication"), good)
	f.put(stateID("Web"), stale)
	f.put(stateID("Risk"), empty)
	f.put("other", map[string]any{"kind": kindState})
	f.runtime["junk"] = fakeDoc{raw: json.RawMessage(`[1]`)}

	var logs strings.Builder
	c := &Coverage{Client: f, Runtime: "sig_runtime", Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	c.Refresh(context.Background())
	sts, read, err := c.Status()
	if err != nil || read.IsZero() {
		t.Fatalf("Status: %v %v", read, err)
	}
	if len(sts) != 2 || sts["Web"].Model != "" {
		t.Errorf("states = %v; a state of an old layout must be left out", sts)
	}
	if got := c.Ranges("Authentication"); len(got) != 1 || !got[0].To.Equal(now) {
		t.Errorf("ranges = %v", got)
	}
	if got := c.Ranges("Risk"); got != nil {
		t.Errorf("an empty state covers %v", got)
	}

	// When the states cannot be read, searches read events only.
	f.fail = func(op, _ string) error {
		if op == "searchdocs" {
			return errors.New("runtime down")
		}
		return nil
	}
	c.Refresh(context.Background())
	if _, read2, err := c.Status(); err == nil || !read2.Equal(read) {
		t.Errorf("Status after a failed read: %v %v", read2, err)
	}
	if c.Ranges("Authentication") != nil {
		t.Error("ranges kept after a failed read")
	}
	if !strings.Contains(logs.String(), "runtime down") {
		t.Errorf("log = %q", logs.String())
	}

	c.Set(map[string][]Range{"Web": {{From: now, To: now.Add(Slot)}}})
	if len(c.Ranges("Web")) != 1 {
		t.Error("Set did not set")
	}
	c.SetStates(map[string]State{"Web": good})
	if s, _, err := c.Status(); err != nil || s["Web"].Model != "Authentication" {
		t.Errorf("SetStates: %v %v", s, err)
	}
}

func TestCoverageRunReadsUntilCancelled(t *testing.T) {
	f := newFake("sig")
	ctx, cancel := context.WithCancel(context.Background())
	f.fail = func(op, _ string) error {
		if op == "searchdocs" {
			cancel()
		}
		return nil
	}
	c := &Coverage{Client: f, Runtime: "sig_runtime"}
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	<-done
	if _, read, _ := c.Status(); read.IsZero() {
		t.Error("Run did not read the states")
	}
}

func TestAddGapMergesAndCaps(t *testing.T) {
	at := func(h int) time.Time { return time.Unix(0, 0).UTC().Add(time.Duration(h) * time.Hour) }
	gs := addGap(nil, Gap{From: at(5), To: at(6)})
	gs = addGap(gs, Gap{From: at(1), To: at(2)})
	gs = addGap(gs, Gap{From: at(2), To: at(3)}) // touches the first
	gs = addGap(gs, Gap{From: at(5), To: at(5)}) // inside
	want := []Gap{{From: at(1), To: at(3)}, {From: at(5), To: at(6)}}
	if !slices.Equal(gs, want) {
		t.Errorf("gaps = %v, want %v", gs, want)
	}
	gs = nil
	for i := range maxGaps + 5 {
		gs = addGap(gs, Gap{From: at(10 * i), To: at(10*i + 1)})
	}
	if len(gs) != maxGaps || !gs[0].From.Equal(at(0)) || !gs[len(gs)-1].To.Equal(at(10*(maxGaps+4)+1)) {
		t.Errorf("%d gaps from %v to %v", len(gs), gs[0].From, gs[len(gs)-1].To)
	}
}

func TestSmallHelpers(t *testing.T) {
	for _, c := range []struct {
		v    any
		want float64
		ok   bool
	}{
		{1.5, 1.5, true}, {int64(3), 3, true}, {4, 4, true}, {json.Number("2.5"), 2.5, true},
		{json.Number("x"), 0, false}, {"7", 0, false}, {nil, 0, false},
	} {
		if got, ok := toFloat(c.v); got != c.want || ok != c.ok {
			t.Errorf("toFloat(%v) = %v, %v", c.v, got, ok)
		}
	}
	if dig(map[string]any{"a": 1}, "a", "b") != nil {
		t.Error("dig through a non-map")
	}
	if isNotFound(errors.New("x")) || !isNotFound(fmt.Errorf("w: %w", &store.Error{Status: 404})) {
		t.Error("isNotFound")
	}
	if got := IndexPattern("p"); got != "p_summary-*" {
		t.Errorf("IndexPattern = %q", got)
	}
	ts := sortTimes([]time.Time{time.Unix(3, 0), time.Unix(1, 0), time.Unix(2, 0)})
	if !ts[0].Equal(time.Unix(1, 0)) || !ts[2].Equal(time.Unix(3, 0)) {
		t.Errorf("sortTimes = %v", ts)
	}
	if !maxTime(time.Unix(1, 0), time.Unix(2, 0)).Equal(time.Unix(2, 0)) || !maxTime(time.Unix(2, 0), time.Unix(1, 0)).Equal(time.Unix(2, 0)) {
		t.Error("maxTime")
	}
	if rowID("m", time.Unix(0, 0), "k") == rowID("m", time.Unix(0, 0), "k2") {
		t.Error("rowID ignores the key")
	}
	r := timeRange(time.Time{}, time.Time{})
	if got := dig(r, "range", "@timestamp").(map[string]any); len(got) != 1 {
		t.Errorf("open range = %v", got)
	}
	if layout("Nope") == layout("Authentication") || Dims("Nope") != nil {
		t.Error("an unknown model")
	}
	// A builder without a clock, epoch or logger uses the defaults.
	var b Builder
	if b.epochNow() != 0 || b.log() == nil || time.Since(b.now()) > time.Minute {
		t.Error("defaults")
	}
}
