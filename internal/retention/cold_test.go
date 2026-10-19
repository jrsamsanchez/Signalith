// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// coldFixture is a fixture whose OpenSearch has the cold storage
// repository and a node that mounts searchable snapshots.
func coldFixture(t *testing.T, pol Policy) *fixture {
	t.Helper()
	f := newFixture(t, Config{Days: 90})
	f.mem.ColdRepo, f.mem.ColdMountable = ColdRepository("signalith"), true
	if err := f.m.SetPolicy("endpoint", &pol); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestColdPolicyProblems(t *testing.T) {
	for _, c := range []struct {
		p    Policy
		kind string
		want string
	}{
		{Policy{KeepDays: 30, ColdAfterDays: 30}, KindEvents, "cold_after_days must be less than keep_days"},
		{Policy{ColdAfterDays: -1}, KindEvents, "cold_after_days cannot be negative"},
		{Policy{KeepDays: 30, ColdAfterDays: 7}, KindRecords, "cold_after_days does not apply"},
		{Policy{KeepDays: 400, ColdAfterDays: 7}, KindMonthly, "cold_after_days does not apply"},
	} {
		if got := strings.Join(c.p.Problems(c.kind), "; "); !strings.Contains(got, c.want) {
			t.Errorf("%+v %s: problems %q, want %q", c.p, c.kind, got, c.want)
		}
	}
	if got := (Policy{KeepDays: 365, ColdAfterDays: 30, CompactAfterDays: 60}).Problems(KindEvents); len(got) > 0 {
		t.Errorf("valid policy: %v", got)
	}
}

func TestRunMovesDaysToColdStorage(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 365, ColdAfterDays: 30})
	old := f.add("endpoint", 31, 4*GB, 12)
	recent := f.add("endpoint", 30, 4*GB, 5)
	run, err := f.m.Run(context.Background(), TriggerManual, "admin")
	if err != nil || len(run.Errors) > 0 {
		t.Fatalf("run = %+v, %v", run, err)
	}
	if run.Cold != 1 || run.FreedBytes == 0 {
		t.Errorf("run = %+v", run)
	}
	info, docs, ok := f.mem.Index(old)
	if !ok || info.Cold == nil || len(docs) != 12 || !info.WriteBlocked {
		t.Fatalf("old day = %+v (%d docs, ok %v)", info, len(docs), ok)
	}
	if info.Cold.Snapshot != f.mem.Snapshots()[0] || len(f.mem.Snapshots()) != 1 {
		t.Errorf("mounted from %q, snapshots %v", info.Cold.Snapshot, f.mem.Snapshots())
	}
	if r, _, _ := f.mem.Index(recent); r.Cold != nil {
		t.Errorf("a day within cold_after_days moved: %+v", r)
	}
	// Merged before the snapshot, deleted only after it, then mounted.
	order := []string{"block=true " + old, "forcemerge " + old, "snapshot " + old, "delete " + old, "mount " + old}
	at := -1
	for _, c := range order {
		i := slices.Index(f.mem.Calls, c)
		if i <= at {
			t.Fatalf("calls %v, want in order %v", f.mem.Calls, order)
		}
		at = i
	}
	// A second run does nothing more, and the day takes no local disk.
	f.mem.Calls = nil
	if run, _ := f.m.Run(context.Background(), TriggerManual, "admin"); run.Cold != 0 || len(f.mem.Calls) != 0 {
		t.Errorf("second run %+v, calls %v", run, f.mem.Calls)
	}
	ov := f.m.Overview(context.Background())
	if !ov.Cold.Ready() || ov.Cold.Days != 1 || ov.Cold.Bytes == 0 || ov.Cold.Message != "" {
		t.Errorf("overview cold = %+v", ov.Cold)
	}
	for _, c := range ov.Categories {
		if c.ID == "endpoint" && (c.ColdDays != 1 || c.Bytes != 4*GB) {
			t.Errorf("endpoint row = %+v", c)
		}
	}
}

func TestColdDayDeletedWithItsSnapshot(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 60, ColdAfterDays: 30, Archive: true})
	day := f.add("endpoint", 45, 4*GB, 7)
	if run, err := f.m.Run(context.Background(), TriggerManual, ""); err != nil || run.Cold != 1 {
		t.Fatalf("run = %+v, %v", run, err)
	}
	f.m.Now = func() time.Time { return testNow.AddDate(0, 0, 16) }
	run, err := f.m.Run(context.Background(), TriggerManual, "")
	if err != nil || run.Archived != 1 || len(run.Errors) > 0 {
		t.Fatalf("run = %+v, %v", run, err)
	}
	if f.exists(day) || len(f.mem.Snapshots()) != 0 {
		t.Errorf("left: index %v, snapshots %v", f.exists(day), f.mem.Snapshots())
	}
	if run.FreedBytes != 0 {
		t.Errorf("deleting a cold day freed %d bytes of local disk", run.FreedBytes)
	}
	man, err := f.m.Archive.Get(day)
	if err != nil || man.Docs != 7 {
		t.Errorf("archive = %+v, %v", man, err)
	}
}

func TestColdMoveStoppedAfterDeleteIsMounted(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 365, ColdAfterDays: 30})
	day := f.add("endpoint", 40, 2*GB, 3)
	f.mem.Fail["mount "+day] = errors.New("no warm node")
	run, _ := f.m.Run(context.Background(), TriggerManual, "")
	if len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "the next run tries again") || f.exists(day) {
		t.Fatalf("run = %+v, exists %v", run, f.exists(day))
	}
	delete(f.mem.Fail, "mount "+day)
	run, _ = f.m.Run(context.Background(), TriggerManual, "")
	if run.Mounted != 1 || len(run.Errors) > 0 {
		t.Fatalf("run = %+v", run)
	}
	if info, docs, ok := f.mem.Index(day); !ok || info.Cold == nil || len(docs) != 3 {
		t.Errorf("day = %+v %d %v", info, len(docs), ok)
	}
}

func TestColdMoveRedoneWhenTheIndexWasKept(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 365, ColdAfterDays: 30})
	day := f.add("endpoint", 40, 2*GB, 3)
	f.mem.Fail["delete "+day] = errors.New("timeout")
	if run, _ := f.m.Run(context.Background(), TriggerManual, ""); len(run.Errors) != 1 || len(f.mem.Snapshots()) != 1 {
		t.Fatalf("run = %+v, snapshots %v", run, f.mem.Snapshots())
	}
	delete(f.mem.Fail, "delete "+day)
	// Late events arrive meanwhile; the next move snapshots them too.
	f.mem.SetIndex(day, func(i *IndexInfo) { i.WriteBlocked = false })
	f.mem.AddDocs(day, testDocs(2)...)
	run, _ := f.m.Run(context.Background(), TriggerManual, "")
	if run.Cold != 1 || len(run.Errors) > 0 {
		t.Fatalf("run = %+v", run)
	}
	if _, docs, _ := f.mem.Index(day); len(docs) != 5 || len(f.mem.Snapshots()) != 1 {
		t.Errorf("%d docs, snapshots %v", len(docs), f.mem.Snapshots())
	}
}

func TestColdWaitsUntilOpenSearchIsReady(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 365, ColdAfterDays: 30, CompactAfterDays: 10}); err != nil {
		t.Fatal(err)
	}
	day := f.add("endpoint", 40, 2*GB, 3)
	ov := f.m.Overview(context.Background())
	if !ov.Cold.Used || !strings.Contains(ov.Cold.Message, "no snapshot repository named signalith-cold") {
		t.Errorf("cold = %+v", ov.Cold)
	}
	if !slices.ContainsFunc(ov.Notes, func(n string) bool { return strings.Contains(n, "Endpoint are due to move to cold storage") }) {
		t.Errorf("notes = %v", ov.Notes)
	}
	// Meanwhile it is compacted as the policy says, and stays on disk.
	if run, _ := f.m.Run(context.Background(), TriggerManual, ""); run.Compacted != 1 || run.Cold != 0 {
		t.Errorf("run = %+v", run)
	}
	f.mem.ColdRepo = ColdRepository("signalith")
	if ov := f.m.Overview(context.Background()); !strings.Contains(ov.Cold.Message, "warm role") {
		t.Errorf("cold = %+v", ov.Cold)
	}
	f.mem.ColdMountable = true
	if run, _ := f.m.Run(context.Background(), TriggerManual, ""); run.Cold != 1 {
		t.Errorf("run = %+v", run)
	}
	if info, _, _ := f.mem.Index(day); info.Cold == nil {
		t.Errorf("not moved: %+v", info)
	}
}

func TestColdDaysOutsideSizeCapsAndGuard(t *testing.T) {
	cold := ix("endpoint", 40, 50*GB)
	cold.Cold = &ColdRef{Repository: "signalith-cold", Snapshot: ColdSnapshotName(cold.Name, "u1")}
	warm := ix("endpoint", 20, 5*GB)
	snap := snapOf(cold, warm)
	snap.Cold = &ColdState{Repository: "signalith-cold", Registered: true, Mountable: true,
		Snapshots: []ColdSnapshot{{Name: cold.Cold.Snapshot, Index: cold.Name}}}
	snap.Disk = &Disk{Node: "n", Total: 100 * GB, Available: 5 * GB}
	snap.NodeBytes = map[string]int64{cold.Name: 50 * GB, warm.Name: 5 * GB}
	s := withPolicy(Effective(Config{Days: 90}, Saved{}), "endpoint", Policy{KeepDays: 365, ColdAfterDays: 30, MaxSizeGB: 10})
	s.Guard.MinDays = 7
	got := byIndex(PlanIndices(snap, s))
	if d := got[cold.Name]; d.Action != ActionKeep || !strings.HasPrefix(d.Reason, "In cold storage") {
		t.Errorf("cold day = %+v", d)
	}
	// The guard needs disk and may only free it from the day on local disk.
	if d := got[warm.Name]; d.Action != ActionDelete || d.Rule != RuleGuard {
		t.Errorf("local day = %+v", d)
	}
}

func TestColdOrphanSnapshots(t *testing.T) {
	gone := IndexName("signalith", "endpoint", dayAgo(400))
	missing := IndexName("signalith", "endpoint", dayAgo(50))
	late := ix("endpoint", 60, GB)
	late.UUID = "new"
	snap := snapOf(late)
	snap.Cold = &ColdState{Registered: true, Mountable: true, Snapshots: []ColdSnapshot{
		{Name: ColdSnapshotName(gone, "a"), Index: gone},
		{Name: ColdSnapshotName(missing, "b"), Index: missing},
		{Name: ColdSnapshotName(late.Name, "c"), Index: late.Name},
		{Name: "signalith-lab-endpoint-2026.01.01.x", Index: "signalith-lab-endpoint-2026.01.01"},
	}}
	s := noGuard(withPolicy(Effective(Config{Days: 90}, Saved{}), "endpoint", Policy{KeepDays: 365, ColdAfterDays: 90}))
	p := PlanIndices(snap, s)
	var acts []string
	for _, d := range p.Decisions {
		if d.Snapshot != "" {
			acts = append(acts, d.Action+" "+d.Snapshot)
		}
	}
	want := []string{"delete " + ColdSnapshotName(gone, "a"), "mount " + ColdSnapshotName(missing, "b"), "keep " + ColdSnapshotName(late.Name, "c")}
	slices.Sort(acts)
	slices.Sort(want)
	if !slices.Equal(acts, want) {
		t.Errorf("snapshot decisions %v, want %v", acts, want)
	}
	if !slices.ContainsFunc(p.Notes, func(n string) bool { return strings.Contains(n, late.Name) }) {
		t.Errorf("notes = %v", p.Notes)
	}
}

// A policy that archives never lets a day's snapshot go unarchived: a day
// past Keep whose mount failed is mounted first, then archived.
func TestColdSnapshotPastKeepIsArchivedFirst(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 60, ColdAfterDays: 30, Archive: true})
	day := f.add("endpoint", 45, 4*GB, 7)
	f.mem.Fail["mount "+day] = errors.New("no warm node")
	if run, _ := f.m.Run(context.Background(), TriggerManual, ""); f.exists(day) || len(f.mem.Snapshots()) != 1 {
		t.Fatalf("run = %+v", run)
	}
	f.m.Now = func() time.Time { return testNow.AddDate(0, 0, 16) }
	run, _ := f.m.Run(context.Background(), TriggerManual, "")
	if run.Deleted != 0 || run.Archived != 0 || len(f.mem.Snapshots()) != 1 {
		t.Fatalf("snapshot deleted without an archive: run %+v, snapshots %v", run, f.mem.Snapshots())
	}
	// Once it can be mounted, it is mounted, then archived and deleted.
	delete(f.mem.Fail, "mount "+day)
	if run, _ := f.m.Run(context.Background(), TriggerManual, ""); run.Mounted != 1 {
		t.Fatalf("run = %+v", run)
	}
	run, _ = f.m.Run(context.Background(), TriggerManual, "")
	if run.Archived != 1 || len(run.Errors) > 0 || f.exists(day) || len(f.mem.Snapshots()) != 0 {
		t.Fatalf("run = %+v, snapshots %v", run, f.mem.Snapshots())
	}
	if man, err := f.m.Archive.Get(day); err != nil || man.Docs != 7 {
		t.Errorf("archive = %+v, %v", man, err)
	}
}

// Without an archive, the snapshot of a day past Keep is simply deleted.
func TestColdSnapshotPastKeepDeletedWithoutArchive(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 60, ColdAfterDays: 30})
	day := f.add("endpoint", 45, 4*GB, 7)
	f.mem.Fail["mount "+day] = errors.New("no warm node")
	f.m.Run(context.Background(), TriggerManual, "")
	f.m.Now = func() time.Time { return testNow.AddDate(0, 0, 16) }
	if run, _ := f.m.Run(context.Background(), TriggerManual, ""); run.Deleted != 1 || len(f.mem.Snapshots()) != 0 {
		t.Errorf("run = %+v, snapshots %v", run, f.mem.Snapshots())
	}
}

// A day under the flood-stage block cannot be made read-only first. If
// OpenSearch lifts the block while it is copied out and events arrive,
// the day is kept, not deleted with them.
func TestDiskBlockLiftedDuringMoveKeepsLateEvents(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 365, ColdAfterDays: 30})
	day := f.add("endpoint", 40, 2*GB, 3)
	f.mem.SetIndex(day, func(i *IndexInfo) { i.DiskBlocked = true })
	f.mem.OnSnapshot = func(index string) {
		f.mem.SetIndex(index, func(i *IndexInfo) { i.DiskBlocked = false })
		f.mem.AddDocs(index, testDocs(2)...)
	}
	run, _ := f.m.Run(context.Background(), TriggerManual, "")
	if run.Cold != 0 || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "events arrived") {
		t.Fatalf("run = %+v", run)
	}
	if info, docs, ok := f.mem.Index(day); !ok || info.Cold != nil || len(docs) != 5 || !info.WriteBlocked {
		t.Fatalf("day = %+v, %d docs, ok %v", info, len(docs), ok)
	}
	// The next run snapshots all five again and moves the day.
	f.mem.OnSnapshot = nil
	if run, _ := f.m.Run(context.Background(), TriggerManual, ""); run.Cold != 1 || len(run.Errors) > 0 {
		t.Fatalf("run = %+v", run)
	}
	if info, docs, _ := f.mem.Index(day); info.Cold == nil || len(docs) != 5 || len(f.mem.Snapshots()) != 1 {
		t.Errorf("day = %+v, %d docs, snapshots %v", info, len(docs), f.mem.Snapshots())
	}
}

// While the flood-stage block holds, nothing can be written, so the day
// moves as it is.
func TestDiskBlockedDayMovesWhileTheBlockHolds(t *testing.T) {
	f := coldFixture(t, Policy{KeepDays: 365, ColdAfterDays: 30})
	day := f.add("endpoint", 40, 2*GB, 3)
	f.mem.SetIndex(day, func(i *IndexInfo) { i.DiskBlocked = true })
	if run, _ := f.m.Run(context.Background(), TriggerManual, ""); run.Cold != 1 || len(run.Errors) > 0 {
		t.Fatalf("run = %+v", run)
	}
	if info, docs, _ := f.mem.Index(day); info.Cold == nil || len(docs) != 3 {
		t.Errorf("day = %+v, %d docs", info, len(docs))
	}
}
