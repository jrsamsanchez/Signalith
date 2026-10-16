package retention

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func lateDocs(prefix string, n int) []Doc {
	out := make([]Doc, n)
	for i := range out {
		out[i] = Doc{ID: fmt.Sprintf("%s-%d", prefix, i), Source: json.RawMessage(`{"late":true}`)}
	}
	return out
}

// archivedIDs returns every document ID in the archive.
func archivedIDs(t *testing.T, a *Archive) []string {
	t.Helper()
	list, _, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range list {
		if err := a.Read(m, func(d Doc) error { ids = append(ids, d.ID); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(ids)
	return ids
}

func TestArchivedCopyIsTiedToTheIndex(t *testing.T) {
	s := noGuard(withPolicy(Effective(Config{Days: 90}, Saved{}), "endpoint", Policy{KeepDays: 30, Archive: true}))
	day := ix("endpoint", 40, GB)
	man := Manifest{ID: day.Name, Index: day.Name, IndexUUID: "first", Docs: 1000}
	cases := []struct {
		name   string
		change func(*IndexInfo)
		mans   []Manifest
		action string
		verify bool
	}{
		// Late events created the day again: a new index, 3 events, which
		// no archive holds however many the first archive has.
		{"late events", func(i *IndexInfo) { i.UUID, i.Docs = "second", 3 }, []Manifest{man}, ActionArchive, false},
		// The archive was made from this very index, but deleting failed.
		{"same index", func(i *IndexInfo) { i.UUID, i.Docs = "first", 1000 }, []Manifest{man}, ActionDelete, true},
		{"same index, more events", func(i *IndexInfo) { i.UUID, i.Docs = "first", 1001 }, []Manifest{man}, ActionArchive, false},
		// Restored from its archive: not archived twice.
		{"restored", func(i *IndexInfo) { i.UUID, i.Docs, i.RestoredFrom = "third", 1000, []string{man.ID} }, []Manifest{man}, ActionDelete, true},
		{"restored, then late events", func(i *IndexInfo) { i.UUID, i.Docs, i.RestoredFrom = "third", 1004, []string{man.ID} }, []Manifest{man}, ActionArchive, false},
		{"restored, file moved away", func(i *IndexInfo) { i.UUID, i.Docs, i.RestoredFrom = "third", 1000, []string{man.ID} }, nil, ActionArchive, false},
		{"restored from two", func(i *IndexInfo) { i.UUID, i.Docs, i.RestoredFrom = "third", 1003, []string{man.ID, man.ID + ".2"} },
			[]Manifest{man, {ID: man.ID + ".2", Index: day.Name, IndexUUID: "second", Docs: 3}}, ActionDelete, true},
		// An empty index is checked again before it is deleted.
		{"empty", func(i *IndexInfo) { i.UUID, i.Docs = "fourth", 0 }, nil, ActionDelete, true},
	}
	for _, c := range cases {
		info := day
		c.change(&info)
		snap := snapOf(info)
		snap.Archives = map[string][]Manifest{day.Name: c.mans}
		d := PlanIndices(snap, s).Decisions[0]
		if d.Action != c.action || d.verify != c.verify {
			t.Errorf("%s: %s (%s), verify %v; want %s, verify %v", c.name, d.Action, d.Reason, d.verify, c.action, c.verify)
		}
	}
}

func TestLateEventsAreArchivedBeforeTheyAreDeleted(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, Archive: true}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	name := f.add("endpoint", 40, GB, 25)
	if run, err := f.m.Run(ctx, TriggerManual, "admin"); err != nil || run.Archived != 1 || f.exists(name) {
		t.Fatalf("first run = %+v %v", run, err)
	}
	// A laptop comes back online and sends 3 late events for that day.
	f.mem.AddIndex(name, 1<<20, lateDocs("late", 3)...)
	run, err := f.m.Run(ctx, TriggerManual, "admin")
	if err != nil || run.Archived != 1 || run.Deleted != 0 || f.exists(name) {
		t.Fatalf("second run = %+v %v", run, err)
	}
	ids := archivedIDs(t, f.m.Archive)
	if len(ids) != 28 || !slices.Contains(ids, "late-0") {
		t.Errorf("archived %d events: %v", len(ids), ids)
	}
	list, _, _ := f.m.Archive.List()
	if len(list) != 2 || list[0].IndexUUID == list[1].IndexUUID || list[0].IndexUUID == "" {
		t.Errorf("archives = %+v", list)
	}
}

func TestEventsWrittenJustBeforeTheBlockAreArchived(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, Archive: true}); err != nil {
		t.Fatal(err)
	}
	name := f.add("endpoint", 40, GB, 100)
	// Indexed, but not refreshed yet when the run starts.
	f.mem.AddUnrefreshed(name, lateDocs("fresh", 20)...)
	run, err := f.m.Run(context.Background(), TriggerManual, "admin")
	if err != nil || run.Archived != 1 || f.exists(name) {
		t.Fatalf("run = %+v %v", run, err)
	}
	if ids := archivedIDs(t, f.m.Archive); len(ids) != 120 {
		t.Errorf("the archive holds %d of 120 events", len(ids))
	}
	if i := slices.Index(f.mem.Calls, "block=true "+name); i < 0 || f.mem.Calls[i+1] != "refresh "+name {
		t.Errorf("calls = %v", f.mem.Calls)
	}

	// An empty-looking index in a category that archives is checked again:
	// unrefreshed events are archived, not deleted.
	empty := f.add("endpoint", 41, GB, 0)
	f.mem.AddUnrefreshed(empty, lateDocs("hidden", 2)...)
	run, _ = f.m.Run(context.Background(), TriggerManual, "admin")
	if run.Archived != 1 || run.Deleted != 0 || f.exists(empty) {
		t.Errorf("empty run = %+v", run)
	}
}

func TestFailedArchiveLeavesTheIndexWritable(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, Archive: true}); err != nil {
		t.Fatal(err)
	}
	name := f.add("endpoint", 40, GB, 5)
	compacted := f.add("endpoint", 41, GB, 5)
	f.mem.SetIndex(compacted, func(ix *IndexInfo) { ix.WriteBlocked, ix.Segments = true, 1 })
	f.mem.Fail["export "+name] = errors.New("no space left on device")
	f.mem.Fail["export "+compacted] = errors.New("no space left on device")
	run, _ := f.m.Run(context.Background(), TriggerManual, "admin")
	if len(run.Errors) != 2 {
		t.Fatalf("run = %+v", run)
	}
	if info, _, ok := f.mem.Index(name); !ok || info.WriteBlocked {
		t.Errorf("kept index = %+v (exists %v); it must take late events again", info, ok)
	}
	// A day that was read-only before (compacted) stays read-only.
	if info, _, _ := f.mem.Index(compacted); !info.WriteBlocked {
		t.Errorf("compacted index lost its block: %+v", info)
	}
}

func TestAlreadyArchivedDayIsCheckedBeforeDeleting(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, Archive: true}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	name := f.add("endpoint", 40, GB, 10)
	f.mem.Fail["delete "+name] = errors.New("timeout")
	run, _ := f.m.Run(ctx, TriggerManual, "admin")
	if !f.exists(name) || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "deleting the index failed") {
		t.Fatalf("run = %+v", run)
	}
	delete(f.mem.Fail, "delete "+name)
	// The archive covers this very index, so the next run deletes it after
	// checking its count, without a second archive.
	run, _ = f.m.Run(ctx, TriggerManual, "admin")
	if f.exists(name) || run.Deleted != 1 || run.Archived != 0 {
		t.Fatalf("second run = %+v", run)
	}
	if list, _, _ := f.m.Archive.List(); len(list) != 1 {
		t.Errorf("archives = %d", len(list))
	}

	// Same again, but events slip in (unrefreshed) before the check: the
	// day is archived again instead.
	other := f.add("endpoint", 42, GB, 10)
	f.mem.Fail["delete "+other] = errors.New("timeout")
	f.m.Run(ctx, TriggerManual, "admin")
	delete(f.mem.Fail, "delete "+other)
	f.mem.SetIndex(other, func(ix *IndexInfo) { ix.WriteBlocked = false })
	f.mem.AddUnrefreshed(other, lateDocs("slipped", 2)...)
	run, _ = f.m.Run(ctx, TriggerManual, "admin")
	if f.exists(other) || run.Archived != 1 || run.Deleted != 0 {
		t.Fatalf("third run = %+v", run)
	}
	if ids := archivedIDs(t, f.m.Archive); !slices.Contains(ids, "slipped-1") {
		t.Errorf("late events not archived: %v", ids)
	}
}

func TestUnavailableIndicesAreLeftAlone(t *testing.T) {
	red := ix("endpoint", 100, 0)
	red.Docs, red.Health, red.Unavailable = 0, "red", true
	redCompact := ix("endpoint", 20, 0)
	redCompact.Health, redCompact.Unavailable = "red", true
	snap := snapOf(red, redCompact, ix("endpoint", 101, GB))
	snap.Disk = &Disk{Total: 100 * GB, Available: 0}
	s := withPolicy(Effective(Config{Days: 90}, Saved{}), "endpoint", Policy{KeepDays: 90, Archive: true, MaxSizeGB: 0.5, CompactAfterDays: 7})
	s.Guard.MinDays = 1
	plan := PlanIndices(snap, s)
	d := byIndex(plan)
	for _, name := range []string{red.Name, redCompact.Name} {
		if d[name].Action != ActionKeep || !strings.Contains(d[name].Reason, "Unavailable in OpenSearch") {
			t.Errorf("%s: %+v", name, d[name])
		}
	}
	if d[ix("endpoint", 101, 0).Name].Action != ActionArchive {
		t.Errorf("healthy day: %+v", d[ix("endpoint", 101, 0).Name])
	}
	if len(plan.Notes) == 0 || !strings.Contains(plan.Notes[0], "OpenSearch can't read 2 indices") {
		t.Errorf("notes = %v", plan.Notes)
	}
}

func TestGuardDoesNotDeleteWhatCannotHelp(t *testing.T) {
	// 880 GB of 1000 is other data: 60 days of 0.1 GB cannot get the disk
	// from 88.6% under 85%, nor is it near the flood stage.
	f := newFixture(t, Config{Days: 365})
	f.mem.DiskTotal, f.mem.DiskBase = 1000*GB, 880*GB
	var names []string
	for ago := 0; ago < 60; ago++ {
		names = append(names, f.add("authentication", ago, GB/10, 2))
	}
	run, err := f.m.Run(context.Background(), TriggerSchedule, "")
	if err != nil {
		t.Fatal(err)
	}
	if run.Deleted != 0 || run.Guard.State != GuardShort || run.Guard.PlannedDays != 0 ||
		!strings.Contains(run.Guard.Message, "so it deletes nothing") {
		t.Errorf("run = %+v guard %+v", run, run.Guard)
	}
	for _, n := range names {
		if !f.exists(n) {
			t.Fatalf("%s was deleted", n)
		}
	}
	// The disk check then waits for the next scheduled run.
	if f.m.guardTripped(context.Background()) {
		t.Error("guard keeps tripping although it cannot help")
	}
	if ov := f.m.Overview(context.Background()); ov.Guard.PausedUntil == nil || ov.Guard.PauseReason == "" {
		t.Errorf("overview guard = %+v", ov.Guard)
	}
}

func TestGuardCountsOnlyWhatFreesTheFullNode(t *testing.T) {
	// Three nodes; the full one holds a copy of only some days.
	var ixs []IndexInfo
	nb := map[string]int64{}
	for ago := 30; ago > 10; ago-- {
		x := ix("endpoint", ago, 3*GB) // every copy, cluster-wide
		ixs = append(ixs, x)
		if ago%2 == 0 {
			nb[x.Name] = GB // one copy on the full node
		}
	}
	snap := snapOf(ixs...)
	snap.Disk = &Disk{Node: "n1", Total: 100 * GB, Available: 12 * GB} // 88%: 3 GB to free on n1
	snap.NodeBytes = nb
	plan := PlanIndices(snap, Effective(Config{}, Saved{}))
	var got []string
	for _, d := range plan.Steps() {
		got = append(got, d.Day)
	}
	// Three days with a copy on n1, oldest first; days without one are not
	// deleted, since that frees nothing there.
	want := []string{dayAgo(30).Format(time.DateOnly), dayAgo(28).Format(time.DateOnly), dayAgo(26).Format(time.DateOnly)}
	if !slices.Equal(got, want) || plan.Guard.PlannedBytes != 3*GB || plan.Guard.State != GuardOver {
		t.Errorf("deleted %v (guard %+v), want %v", got, plan.Guard, want)
	}
	if !strings.Contains(plan.Guard.Message, "the oldest 3 days are deleted") {
		t.Errorf("message = %q", plan.Guard.Message)
	}
	snap.Disk.Available = 14 * GB
	if m := PlanIndices(snap, Effective(Config{}, Saved{})).Guard.Message; !strings.Contains(m, "the oldest day is deleted") {
		t.Errorf("one day: %q", m)
	}
}

func TestRestoredDaysDoNotCountTowardTheSizeCap(t *testing.T) {
	var ixs []IndexInfo
	for ago := 0; ago < 19; ago++ {
		ixs = append(ixs, ix("endpoint", ago, GB))
	}
	for ago := 100; ago < 105; ago++ {
		r := ix("endpoint", ago, GB)
		r.RestoredUntil = "2026-10-26"
		ixs = append(ixs, r)
	}
	s := noGuard(withPolicy(Effective(Config{}, Saved{}), "endpoint", Policy{KeepDays: 365, MaxSizeGB: 20}))
	if steps := PlanIndices(snapOf(ixs...), s).Steps(); len(steps) != 0 {
		t.Errorf("restoring evicted live days: %+v", steps)
	}
}

func TestSettingsSavedDuringARunApplyAtOnce(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, Archive: true}); err != nil {
		t.Fatal(err)
	}
	var names []string
	for ago := 31; ago <= 40; ago++ {
		names = append(names, f.add("endpoint", ago, GB, 2))
	}
	// While the first (oldest) day is being archived, the admin corrects
	// the policy to 300 days.
	var once sync.Once
	f.mem.OnExport = func(string, int) {
		once.Do(func() {
			if err := f.m.Store.Update(func(sv *Saved) { sv.Policies["endpoint"] = Policy{KeepDays: 300, Archive: true} }); err != nil {
				t.Error(err)
			}
		})
	}
	run, err := f.m.Run(context.Background(), TriggerManual, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if run.Archived != 1 || run.Skipped != 9 {
		t.Errorf("run = %+v", run)
	}
	for _, n := range names[:9] {
		if !f.exists(n) {
			t.Errorf("%s was deleted after the correction", n)
		}
	}
}

func TestChangeDuringARunQueuesAnother(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, Archive: true}); err != nil {
		t.Fatal(err)
	}
	a := f.add("endpoint", 40, GB, 2)
	b := f.add("authentication", 70, GB, 2)
	hold, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.mem.OnExport = func(string, int) { once.Do(func() { close(hold); <-release }) }
	if got, err := f.m.ApplySoon(TriggerChange, "admin"); got != ApplyStarted || err != nil {
		t.Fatalf("first = %s %v", got, err)
	}
	<-hold
	// The authentication change arrives during the run.
	if err := f.m.SetPolicy("authentication", &Policy{KeepDays: 60}); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.m.ApplySoon(TriggerChange, "admin"); got != ApplyQueued {
		t.Fatalf("second = %s", got)
	}
	if ov := f.m.Overview(context.Background()); !ov.Schedule.Queued || !ov.Schedule.Running {
		t.Errorf("schedule = %+v", ov.Schedule)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for f.exists(b) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.exists(a) || f.exists(b) {
		t.Errorf("queued run did not apply the change: %v %v", f.exists(a), f.exists(b))
	}
	for f.m.Overview(context.Background()).Schedule.Running && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !f.m.job.TryLock() {
		t.Fatal("job still held")
	}
	f.m.job.Unlock()
}

func TestReadOnlyServerChangesNothing(t *testing.T) {
	f := newFixture(t, Config{Days: 30})
	f.m.ReadOnly = true
	name := f.add("endpoint", 40, GB, 2)
	ctx := context.Background()
	for what, err := range map[string]error{
		"policy":  f.m.SetPolicy("endpoint", &Policy{KeepDays: 5}),
		"default": f.m.SetDefault(Policy{KeepDays: 5}),
		"guard":   f.m.SetGuard(Guard{MaxDiskPercent: 60}),
		"run":     f.m.RunAsync(TriggerManual, "admin"),
	} {
		if !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s: %v", what, err)
		}
	}
	if _, err := f.m.ApplySoon(TriggerChange, "admin"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("apply: %v", err)
	}
	if _, err := f.m.Restore(ctx, []string{name}, 0, "admin", true); !errors.Is(err, ErrReadOnly) {
		t.Errorf("restore: %v", err)
	}
	ov := f.m.Overview(ctx)
	if !ov.Schedule.ReadOnly || ov.Default.Editable || ov.Guard.Editable || ov.Categories[0].Editable {
		t.Errorf("overview = %+v %+v %+v", ov.Schedule, ov.Default, ov.Guard)
	}
	if !f.exists(name) {
		t.Error("a read-only server deleted data")
	}
}

func TestGuardChoosesAgainWhenAnArchiveFails(t *testing.T) {
	f := newFixture(t, Config{Days: 0})
	if err := f.m.SetPolicy("endpoint", &Policy{Archive: true}); err != nil {
		t.Fatal(err)
	}
	f.mem.DiskTotal, f.mem.DiskBase = 100*GB, 60*GB
	oldEP := f.add("endpoint", 50, 10*GB, 2)
	auth := f.add("authentication", 49, 10*GB, 2)
	f.add("authentication", 3, 10*GB, 2)
	f.add("authentication", 2, 10*GB, 2) // 100% used: 15 GB must go
	f.mem.Fail["export "+oldEP] = errors.New("no space left on device")
	run, _ := f.m.Run(context.Background(), TriggerGuard, "")
	// The endpoint day could not be archived, so the guard took the next
	// oldest day instead; still short of the limit, it pauses.
	if !f.exists(oldEP) || f.exists(auth) || run.Deleted != 1 || len(run.Errors) != 1 {
		t.Errorf("run = %+v", run)
	}
	if _, paused := f.m.guardPause(); !paused {
		t.Error("guard did not pause after failing")
	}
}

func TestCheckRestore(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, Archive: true}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	old := f.add("endpoint", 40, 10*GB, 3)
	if _, err := f.m.Run(ctx, TriggerManual, "admin"); err != nil || f.exists(old) {
		t.Fatal(err)
	}
	f.mem.DiskTotal, f.mem.DiskBase = 100*GB, 66*GB
	live := f.add("network_traffic", 20, 6*GB, 2) // 72% used; 82% after the restore
	chk, err := f.m.CheckRestore(ctx, []string{old}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if chk.NeedsConfirm || chk.Bytes != 10*GB || chk.PercentAfter != 82 {
		t.Errorf("check = %+v", chk)
	}
	// At 80% before, the restore takes the disk to 90%: the guard would
	// delete the live network day, which has no archive.
	f.mem.DiskBase = 74 * GB
	chk, _ = f.m.CheckRestore(ctx, []string{old}, 0)
	if !chk.NeedsConfirm || len(chk.Steps) != 1 || chk.Steps[0].Index != live || chk.Unarchived != 1 ||
		!strings.Contains(chk.Message, "1 of them is not archived") {
		t.Errorf("check = %+v", chk)
	}
	// When the guard could not make room at all, it still needs confirming.
	f.mem.SetIndex(live, func(ix *IndexInfo) { ix.Bytes = GB / 2 })
	f.mem.DiskBase = 79*GB + GB/2
	chk, _ = f.m.CheckRestore(ctx, []string{old}, 0)
	if !chk.NeedsConfirm || !chk.OverLimit || len(chk.Steps) != 0 || !strings.Contains(chk.Message, "can't free enough") {
		t.Errorf("over-limit check = %+v", chk)
	}
	var ce *ConfirmError
	if _, err := f.m.Restore(ctx, []string{old}, 0, "admin", false); !errors.As(err, &ce) {
		t.Fatalf("unconfirmed restore = %v", err)
	}
	if _, err := f.m.Restore(ctx, []string{old}, 0, "admin", true); err != nil {
		t.Fatal(err)
	}
	waitRestore(t, f.m, old)
	info, _, ok := f.mem.Index(old)
	if !ok || !slices.Equal(info.RestoredFrom, []string{old}) {
		t.Errorf("restored = %+v", info)
	}
	// Close to the flood stage, a restore needs confirming too.
	f.mem.DiskBase = 86 * GB
	f.mem.DeleteIndex(ctx, old)
	if chk, _ = f.m.CheckRestore(ctx, []string{old}, 0); !chk.Flood || !strings.Contains(chk.Message, "stops taking new events") {
		t.Errorf("flood check = %+v", chk)
	}
}

func TestOverviewWithBrokenSettings(t *testing.T) {
	f := newFixture(t, Config{Days: 30})
	f.add("endpoint", 1, GB, 1)
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 10}); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(f.m.Store.(*Store).Path, []byte("policies: [")); err != nil {
		t.Fatal(err)
	}
	ov := f.m.Overview(context.Background())
	if ov.SettingsError == "" || ov.Guard.Status.State != GuardPaused || !strings.Contains(ov.Guard.Status.Message, "isn't checked") {
		t.Errorf("guard = %+v", ov.Guard.Status)
	}
}

func TestArchiveChecksFreeSpace(t *testing.T) {
	a := &Archive{Dir: t.TempDir()}
	mem := NewMemory()
	name := "signalith-endpoint-2026.07.01"
	mem.AddIndex(name, 1, testDocs(3)...)
	_, err := a.Write(context.Background(), mem, Source{Index: name, Category: "endpoint", Day: "2026-07-01", Estimate: 1 << 62}, 3)
	if !errors.Is(err, ErrArchiveSpace) || !strings.Contains(err.Error(), "free space there") {
		t.Errorf("err = %v", err)
	}
	if list, _, _ := a.List(); len(list) != 0 {
		t.Errorf("files left: %v", list)
	}
	if _, err := a.Write(context.Background(), mem, Source{Index: name, Category: "endpoint", Day: "2026-07-01", Estimate: 1}, 3); err != nil {
		t.Error(err)
	}
}

// TestFenceStopsEveryStep checks that a server that no longer holds the
// background jobs changes nothing, even in a run it already started.
func TestFenceStopsEveryStep(t *testing.T) {
	f := newFixture(t, Config{Days: 30})
	name := f.add("endpoint", 40, GB, 2)
	ctx := context.Background()
	f.m.Fence = func(context.Context) error { return errors.New("another server took the jobs") }
	run, err := f.m.Run(ctx, TriggerManual, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !f.exists(name) || run.Deleted != 0 || len(run.Errors) == 0 || !strings.Contains(run.Errors[0], "no longer runs retention") {
		t.Fatalf("run %+v calls %v", run, f.mem.Calls)
	}
	checked := 0
	f.m.Fence = func(context.Context) error { checked++; return nil }
	if run, err = f.m.Run(ctx, TriggerManual, "admin"); err != nil || run.Deleted != 1 || f.exists(name) || checked == 0 {
		t.Fatalf("run %+v err %v checked %d", run, err, checked)
	}
}

// TestStandbyServerIsReadOnly checks a server that may run retention but
// does not now, because another server holds the background jobs.
func TestStandbyServerIsReadOnly(t *testing.T) {
	f := newFixture(t, Config{Days: 30})
	runs := false
	f.m.Leader = func() (bool, string) { return runs, "siem-a" }
	err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 5})
	if !errors.Is(err, ErrReadOnly) || !strings.Contains(err.Error(), "siem-a runs it") {
		t.Fatalf("set policy: %v", err)
	}
	if err := f.m.RunAsync(TriggerManual, "admin"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("run: %v", err)
	}
	ov := f.m.Overview(context.Background())
	if !ov.Schedule.ReadOnly || !strings.HasPrefix(ov.Schedule.ReadOnlyWhy, "This server doesn't run retention right now: siem-a") || ov.Default.Editable {
		t.Errorf("overview %+v", ov.Schedule)
	}
	runs = true
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 5}); err != nil {
		t.Errorf("as the job holder: %v", err)
	}
	if ov := f.m.Overview(context.Background()); ov.Schedule.ReadOnly || ov.Schedule.ReadOnlyWhy != "" {
		t.Errorf("overview %+v", ov.Schedule)
	}
}
