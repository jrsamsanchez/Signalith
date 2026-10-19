// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// countHook lets a test change what Count answers: hook gets the index,
// how many times it was counted (from 1) and the true count.
type countHook struct {
	*Memory
	mu   sync.Mutex
	n    map[string]int
	hook func(index string, call int, n int64) (int64, error)
}

func (c *countHook) Count(ctx context.Context, index string) (int64, error) {
	n, err := c.Memory.Count(ctx, index)
	if err != nil {
		return n, err
	}
	c.mu.Lock()
	if c.n == nil {
		c.n = map[string]int{}
	}
	c.n[index]++
	call := c.n[index]
	c.mu.Unlock()
	return c.hook(index, call, n)
}

func runErrors(t *testing.T, f *fixture) *Run {
	t.Helper()
	run, err := f.m.Run(context.Background(), TriggerManual, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func TestColdMoveFaultsKeepTheIndex(t *testing.T) {
	for _, c := range []struct {
		op, want string
	}{
		{"block", "could not make the index read-only before archiving it"},
		{"refresh", "could not refresh the index before archiving it"},
		{"forcemerge", "could not merge the index before moving it"},
		{"snapshot", "the snapshot failed, so the index was kept"},
	} {
		t.Run(c.op, func(t *testing.T) {
			f := coldFixture(t, Policy{KeepDays: 365, ColdAfterDays: 30})
			name := f.add("endpoint", 40, 4*GB, 6)
			f.mem.Fail[c.op+" "+name] = errors.New("refused for a test")
			run := runErrors(t, f)
			if len(run.Errors) != 1 || !strings.Contains(run.Errors[0], c.want) || run.Cold != 0 {
				t.Fatalf("run = %+v", run)
			}
			info, docs, ok := f.mem.Index(name)
			if !ok || info.Cold != nil || len(docs) != 6 {
				t.Fatalf("index = %+v, %d docs, %v", info, len(docs), ok)
			}
			// Kept, it takes late events again.
			if info.WriteBlocked {
				t.Errorf("the kept index is still read-only")
			}
			if len(f.mem.Snapshots()) != 0 {
				t.Errorf("snapshots left: %v", f.mem.Snapshots())
			}
			// Once the fault is gone, the next run moves it.
			delete(f.mem.Fail, c.op+" "+name)
			if run := runErrors(t, f); run.Cold != 1 || len(run.Errors) != 0 {
				t.Errorf("next run = %+v", run)
			}
		})
	}
}

func TestColdMoveCountFails(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 365, ColdAfterDays: 30})
	name := f.add("endpoint", 40, 4*GB, 6)
	f.m.Cluster = &countHook{Memory: f.mem, hook: func(string, int, int64) (int64, error) { return 0, errors.New("count down") }}
	run := runErrors(t, f)
	if len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "could not count its events, so it was kept") {
		t.Fatalf("run = %+v", run)
	}
	if info, _, ok := f.mem.Index(name); !ok || info.WriteBlocked || info.Cold != nil {
		t.Errorf("index = %+v", info)
	}
}

func TestColdMoveDeleteAndMountFaults(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 365, ColdAfterDays: 30})
	name := f.add("endpoint", 40, 4*GB, 6)
	f.mem.Fail["delete "+name] = errors.New("timeout")
	run := runErrors(t, f)
	if len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "deleting the index failed") {
		t.Fatalf("run = %+v", run)
	}
	if _, _, ok := f.mem.Index(name); !ok || len(f.mem.Snapshots()) != 1 {
		t.Fatalf("index kept %v, snapshots %v", ok, f.mem.Snapshots())
	}
	delete(f.mem.Fail, "delete "+name)

	// The mount fails after the delete: the data is in the snapshot, and
	// the next run mounts it.
	f.mem.Fail["mount "+name] = errors.New("no warm node")
	run = runErrors(t, f)
	if len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "mounting it failed (the next run tries again)") {
		t.Fatalf("run = %+v", run)
	}
	if f.exists(name) {
		t.Fatal("the index is still on the nodes")
	}
	delete(f.mem.Fail, "mount "+name)
	run = runErrors(t, f)
	if len(run.Errors) != 0 {
		t.Fatalf("mount run = %+v", run)
	}
	info, docs, ok := f.mem.Index(name)
	if !ok || info.Cold == nil || len(docs) != 6 {
		t.Errorf("mounted = %+v, %d docs", info, len(docs))
	}
}

func TestColdMoveMountedCountDiffers(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 365, ColdAfterDays: 30})
	name := f.add("endpoint", 40, 4*GB, 6)
	f.m.Cluster = &countHook{Memory: f.mem, hook: func(ix string, call int, n int64) (int64, error) {
		if ix == name && call == 2 { // the count of the mounted index
			return n - 1, nil
		}
		return n, nil
	}}
	run := runErrors(t, f)
	if len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "counts 5 events instead of 6") {
		t.Fatalf("run = %+v", run)
	}
}

func TestColdMoveRefusesAnIndexWithoutUUID(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 365, ColdAfterDays: 30})
	name := f.add("endpoint", 40, 4*GB, 6)
	d := Decision{Index: name, Category: "endpoint", Action: ActionCold}
	var act Action
	if err := f.m.toCold(context.Background(), d, &act); err == nil || !strings.Contains(err.Error(), "UUID is unknown") {
		t.Errorf("toCold = %v", err)
	}
	if info, _, _ := f.mem.Index(name); info.WriteBlocked {
		t.Error("the index was changed")
	}
}

func TestCompactFaults(t *testing.T) {
	for _, c := range []struct {
		op, want string
	}{
		{"block", "could not make the index read-only"},
		{"forcemerge", "could not merge the index"},
	} {
		t.Run(c.op, func(t *testing.T) {
			f := newFixture(t, Config{Days: 90})
			if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 90, CompactAfterDays: 7}); err != nil {
				t.Fatal(err)
			}
			name := f.add("endpoint", 10, 2*GB, 3)
			f.mem.Fail[c.op+" "+name] = errors.New("refused")
			run := runErrors(t, f)
			if run.Compacted != 0 || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], c.want) {
				t.Errorf("run = %+v", run)
			}
			if !f.exists(name) {
				t.Error("compaction deleted the index")
			}
		})
	}
}

// An archived day is deleted after a check of its count. When that check
// cannot be made, the day is kept and writable.
func TestVerifiedDeleteFaults(t *testing.T) {
	setup := func(t *testing.T) (*fixture, string) {
		t.Helper()
		f := newFixture(t, Config{Days: 90})
		if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, Archive: true}); err != nil {
			t.Fatal(err)
		}
		name := f.add("endpoint", 40, GB, 10)
		f.mem.Fail["delete "+name] = errors.New("timeout")
		runErrors(t, f)
		delete(f.mem.Fail, "delete "+name)
		f.mem.SetIndex(name, func(ix *IndexInfo) { ix.WriteBlocked = false })
		return f, name
	}

	t.Run("count", func(t *testing.T) {
		f, name := setup(t)
		f.m.Cluster = &countHook{Memory: f.mem, hook: func(string, int, int64) (int64, error) { return 0, errors.New("count down") }}
		run := runErrors(t, f)
		if run.Deleted != 0 || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "could not count its events") {
			t.Fatalf("run = %+v", run)
		}
		if info, _, ok := f.mem.Index(name); !ok || info.WriteBlocked {
			t.Errorf("index = %+v, %v", info, ok)
		}
	})
	t.Run("refresh", func(t *testing.T) {
		f, name := setup(t)
		f.mem.Fail["refresh "+name] = errors.New("refresh down")
		run := runErrors(t, f)
		if run.Deleted != 0 || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "could not refresh") {
			t.Fatalf("run = %+v", run)
		}
		if info, _, ok := f.mem.Index(name); !ok || info.WriteBlocked {
			t.Errorf("index = %+v, %v", info, ok)
		}
	})
	t.Run("delete", func(t *testing.T) {
		f, name := setup(t)
		f.mem.Fail["delete "+name] = errors.New("still timing out")
		run := runErrors(t, f)
		if run.Deleted != 0 || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "still timing out") {
			t.Fatalf("run = %+v", run)
		}
		if info, _, ok := f.mem.Index(name); !ok || info.WriteBlocked {
			t.Errorf("index = %+v, %v", info, ok)
		}
	})
	t.Run("late events archive fails", func(t *testing.T) {
		f, name := setup(t)
		f.mem.AddDocs(name, lateDocs("late", 3)...)
		f.mem.Fail["export "+name] = errors.New("export down")
		run := runErrors(t, f)
		if run.Archived != 0 || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "archiving failed") {
			t.Fatalf("run = %+v", run)
		}
		if info, _, ok := f.mem.Index(name); !ok || info.WriteBlocked {
			t.Errorf("index = %+v, %v", info, ok)
		}
	})
}

// A day held only by OpenSearch's flood-stage block is sealed before it
// is deleted: if the block was lifted and events arrived, it is kept.
func TestSealedFaults(t *testing.T) {
	setup := func(t *testing.T) (*fixture, string) {
		t.Helper()
		f := newFixture(t, Config{Days: 30})
		name := f.add("endpoint", 40, GB, 4)
		f.mem.SetIndex(name, func(ix *IndexInfo) { ix.DiskBlocked = true })
		return f, name
	}
	t.Run("block refused for another reason", func(t *testing.T) {
		f, name := setup(t)
		f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, Archive: true})
		f.mem.Fail["block "+name] = errors.New("no permission")
		run := runErrors(t, f)
		if !f.exists(name) || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "could not make the index read-only before deleting it") {
			t.Fatalf("run = %+v", run)
		}
	})
	t.Run("flood stage still on", func(t *testing.T) {
		f, name := setup(t)
		f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, Archive: true})
		f.mem.Fail["block "+name] = errors.New("index [x] blocked by: [TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark, index has read-only-allow-delete block]")
		run := runErrors(t, f)
		if f.exists(name) || run.Archived != 1 || len(run.Errors) != 0 {
			t.Fatalf("run = %+v", run)
		}
	})
	// The block is lifted while the day is archived; then the seal's
	// refresh or recount fails.
	for _, c := range []struct {
		name, want string
		set        func(h *sealHook)
	}{
		{"recount fails", "could not count its events again", func(h *sealHook) { h.countErr = errors.New("count down") }},
		{"refresh fails", "could not refresh the index before deleting it", func(h *sealHook) { h.refreshErr = errors.New("refresh down") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, name := setup(t)
			f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, Archive: true})
			f.mem.OnExport = func(index string, _ int) {
				f.mem.SetIndex(index, func(i *IndexInfo) { i.DiskBlocked = false })
			}
			h := &sealHook{Memory: f.mem}
			c.set(h)
			f.m.Cluster = h
			run := runErrors(t, f)
			if !f.exists(name) || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], c.want) {
				t.Fatalf("run = %+v", run)
			}
		})
	}
}

// sealHook fails refreshes or counts once a write block was set.
type sealHook struct {
	*Memory
	blocked    bool
	countErr   error
	refreshErr error
}

func (h *sealHook) BlockWrites(ctx context.Context, index string, block bool) error {
	err := h.Memory.BlockWrites(ctx, index, block)
	if err == nil && block {
		h.blocked = true
	}
	return err
}

func (h *sealHook) Refresh(ctx context.Context, index string) error {
	if h.blocked && h.refreshErr != nil {
		return h.refreshErr
	}
	return h.Memory.Refresh(ctx, index)
}

func (h *sealHook) Count(ctx context.Context, index string) (int64, error) {
	if h.blocked && h.countErr != nil {
		return 0, h.countErr
	}
	return h.Memory.Count(ctx, index)
}

// refreshHook lets a test fail a refresh.
type refreshHook struct {
	*Memory
	hook func(index string) error
}

func (r *refreshHook) Refresh(ctx context.Context, index string) error {
	if err := r.hook(index); err != nil {
		return err
	}
	return r.Memory.Refresh(ctx, index)
}

func TestRecordDeletionFaults(t *testing.T) {
	f := newFixture(t, Config{Policies: map[string]Policy{Findings: {KeepDays: 365}}})
	old := testNow.AddDate(-2, 0, 0)
	f.mem.AddRecords("signalith_findings", Record{ID: "f1", Status: "closed", Updated: old})
	f.mem.Fail["delete_closed signalith_findings"] = errors.New("dbq down")
	run := runErrors(t, f)
	if run.DeletedRecords != 0 || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "findings: dbq down") {
		t.Fatalf("run = %+v", run)
	}
	_, acts, _ := f.m.hist.Recent(context.Background())
	if len(acts) == 0 || acts[0].Action != ActionDeleteRecords || !strings.Contains(acts[0].Error, "dbq down") {
		t.Errorf("history = %+v", acts)
	}
	if len(f.mem.Records("signalith_findings")) != 1 {
		t.Error("a record was deleted")
	}

	// Settings changed to keep records longer apply to the step at once.
	recs := []RecordStep{{Category: Findings, Index: "signalith_findings", KeepDays: 30, Before: testNow.AddDate(0, 0, -30)}}
	delete(f.mem.Fail, "delete_closed signalith_findings")
	// keep_days is 365 now, not the step's 30: a record a month old would
	// stay, the 2-year-old one still goes.
	f.mem.AddRecords("signalith_findings", Record{ID: "f2", Status: "closed", Updated: testNow.AddDate(0, -2, 0)})
	var r Run
	f.m.deleteRecords(context.Background(), &r, recs)
	if left := f.mem.Records("signalith_findings"); r.DeletedRecords != 1 || len(left) != 1 || left[0].ID != "f2" {
		t.Errorf("run = %+v, left %v", r, left)
	}
	// A category kept forever now: the step is skipped.
	f.mem.AddRecords("signalith_cases", Record{ID: "c1", Status: "closed", Updated: old})
	r = Run{}
	f.m.deleteRecords(context.Background(), &r, []RecordStep{{Category: Cases, Index: "signalith_cases", KeepDays: 30, Before: testNow}})
	if r.Skipped != 1 || len(f.mem.Records("signalith_cases")) != 1 {
		t.Errorf("run = %+v", r)
	}
	// A cancelled run stops.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = Run{}
	f.m.deleteRecords(ctx, &r, recs)
	if r.Skipped != 0 || r.DeletedRecords != 0 {
		t.Errorf("cancelled run = %+v", r)
	}
}

func TestStartRunsOnScheduleAndStops(t *testing.T) {
	f := newFixture(t, Config{Days: 30})
	f.add("endpoint", 40, GB, 1)
	f.m.SetInterval(0) // ignored
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.m.Start(ctx); close(done) }()
	// The interval can change while it runs.
	f.m.SetInterval(time.Hour)
	f.m.SetInterval(time.Hour) // the same again: nothing to do
	if got := f.m.interval(); got != time.Hour {
		t.Errorf("interval = %v", got)
	}
	cancel()
	<-done
	if f.m.Job() != "" {
		t.Errorf("Job = %q after Start ended", f.m.Job())
	}
}
