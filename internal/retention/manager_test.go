package retention

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	m   *Manager
	mem *Memory
	dir string
}

func newFixture(t *testing.T, cfg Config) *fixture {
	t.Helper()
	dir := t.TempDir()
	mem := NewMemory()
	m := &Manager{
		Cluster: mem, Prefix: "signalith", Config: cfg,
		Store:       NewStore(filepath.Join(dir, "lookups", "retention.yaml")),
		Archive:     &Archive{Dir: filepath.Join(dir, "archive")},
		HistoryFile: filepath.Join(dir, "lookups", "retention_history.json"),
		Now:         func() time.Time { return testNow },
	}
	return &fixture{m: m, mem: mem, dir: dir}
}

func (f *fixture) add(cat string, ago int, bytes int64, docs int) string {
	name := IndexName("signalith", cat, dayAgo(ago))
	f.mem.AddIndex(name, bytes, testDocs(docs)...)
	return name
}

func (f *fixture) exists(name string) bool {
	_, _, ok := f.mem.Index(name)
	return ok
}

func TestRunEnforcesPolicies(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 30, CompactAfterDays: 7, Archive: true}); err != nil {
		t.Fatal(err)
	}
	oldAuth := f.add("authentication", 91, 5*GB, 3)
	keepAuth := f.add("authentication", 90, 5*GB, 3)
	oldEP := f.add("endpoint", 31, 2*GB, 25)
	warmEP := f.add("endpoint", 8, 2*GB, 3)
	freshEP := f.add("endpoint", 7, 2*GB, 3)
	today := f.add("endpoint", 0, 2*GB, 3)
	f.mem.AddIndex("signalith-lab-endpoint-2020.01.01", GB) // another install's index

	run, err := f.m.Run(context.Background(), TriggerManual, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if run.Deleted != 1 || run.Archived != 1 || run.Compacted != 1 || len(run.Errors) != 0 || run.Trigger != TriggerManual || run.By != "admin" {
		t.Errorf("run = %+v", run)
	}
	if f.exists(oldAuth) || f.exists(oldEP) || !f.exists(keepAuth) || !f.exists(freshEP) || !f.exists(today) || !f.exists("signalith-lab-endpoint-2020.01.01") {
		t.Errorf("indices left: %v", f.mem.Calls)
	}
	if info, _, _ := f.mem.Index(warmEP); !info.Compacted() {
		t.Errorf("not compacted: %+v", info)
	}
	// The archive holds every event of the deleted day, and was written
	// before the index was deleted.
	man, err := f.m.Archive.Get(oldEP)
	if err != nil || man.Docs != 25 || f.m.Archive.Verify(man) != nil {
		t.Fatalf("archive = %+v %v", man, err)
	}
	if i, j := slices.Index(f.mem.Calls, "block=true "+oldEP), slices.Index(f.mem.Calls, "delete "+oldEP); i < 0 || j < i {
		t.Errorf("calls = %v", f.mem.Calls)
	}
	// Freed: 5 GB + 2 GB deleted, plus a tenth of 2 GB from merging.
	if run.FreedBytes != 7*GB+2*GB/10 {
		t.Errorf("freed = %d", run.FreedBytes)
	}

	// The history survives a restart.
	m2 := &Manager{Cluster: f.mem, Prefix: "signalith", HistoryFile: f.m.HistoryFile, Archive: f.m.Archive, Now: f.m.Now}
	m2.init()
	last, acts := m2.hist.get()
	if last == nil || last.Archived != 1 || len(acts) != 3 {
		t.Fatalf("history = %+v %+v", last, acts)
	}
	// Newest first: deletions ran oldest day first, then compaction.
	if acts[0].Action != ActionCompact || acts[1].Action != ActionArchive || acts[2].Action != ActionDelete ||
		acts[1].File != oldEP+".ndjson.gz" || acts[1].Docs != 25 || acts[1].By != "admin" || acts[2].Index != oldAuth {
		t.Errorf("actions = %+v", acts)
	}

	// A second run finds nothing to do.
	f.mem.Calls = nil
	run, _ = f.m.Run(context.Background(), TriggerSchedule, "")
	if run.Deleted+run.Archived+run.Compacted != 0 || len(f.mem.Calls) != 0 {
		t.Errorf("second run = %+v, calls %v", run, f.mem.Calls)
	}
}

func TestArchiveFailureKeepsTheIndex(t *testing.T) {
	f := newFixture(t, Config{Days: 30, Default: &Policy{KeepDays: 30, Archive: true}})
	a := f.add("endpoint", 40, GB, 5)
	b := f.add("change", 41, GB, 5)
	f.mem.Fail["export "+a] = errors.New("search context missing")
	// The archive folder for b cannot be written either: point it at a file.
	run, err := f.m.Run(context.Background(), TriggerSchedule, "")
	if err != nil {
		t.Fatal(err)
	}
	if !f.exists(a) || f.exists(b) || run.Archived != 1 || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "so the index was kept") {
		t.Errorf("run = %+v", run)
	}
	_, acts := f.m.hist.get()
	if acts[0].Index != a || acts[0].Error == "" || acts[1].Index != b || acts[1].Error != "" {
		t.Errorf("actions = %+v", acts)
	}

	bad := os.WriteFile(filepath.Join(f.dir, "notadir"), nil, 0o600)
	if bad != nil {
		t.Fatal(bad)
	}
	f.m.Archive.Dir = filepath.Join(f.dir, "notadir", "archive")
	delete(f.mem.Fail, "export "+a)
	run, _ = f.m.Run(context.Background(), TriggerSchedule, "")
	if !f.exists(a) || run.Archived != 0 || len(run.Errors) != 1 {
		t.Errorf("unwritable folder: run = %+v", run)
	}
}

// countLiar reports one more document than it exports.
type countLiar struct{ *Memory }

func (c countLiar) Count(ctx context.Context, index string) (int64, error) {
	n, err := c.Memory.Count(ctx, index)
	return n + 1, err
}

func TestArchiveCountMismatchKeepsTheIndex(t *testing.T) {
	f := newFixture(t, Config{Default: &Policy{KeepDays: 30, Archive: true}})
	a := f.add("endpoint", 40, GB, 5)
	f.m.Cluster = countLiar{f.mem}
	run, _ := f.m.Run(context.Background(), TriggerSchedule, "")
	if !f.exists(a) || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "has 5 events but the index has 6") {
		t.Errorf("run = %+v", run)
	}
	if entries, _ := os.ReadDir(f.m.Archive.Dir); len(entries) != 0 {
		t.Errorf("archive folder = %v", entries)
	}
}

// At OpenSearch's flood stage every index is read-only: it can be read
// and deleted, but its settings cannot change and it cannot be merged.
// The guard must still free space, archiving first where the policy says.
func TestFloodStageStillFreesSpace(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 365, CompactAfterDays: 7, Archive: true}); err != nil {
		t.Fatal(err)
	}
	f.mem.DiskTotal, f.mem.DiskBase = 100*GB, 73*GB // 96% once the days are added
	oldEP := f.add("endpoint", 30, 10*GB, 5)
	warmEP := f.add("endpoint", 20, 10*GB, 5)
	compactable := f.add("endpoint", 10, GB, 5) // old enough to compact
	recent := f.add("endpoint", 2, GB, 5)
	today := f.add("endpoint", 0, GB, 5)
	for _, name := range []string{oldEP, warmEP, compactable, recent, today} {
		f.mem.SetIndex(name, func(ix *IndexInfo) { ix.DiskBlocked = true })
	}
	run, err := f.m.Run(context.Background(), TriggerGuard, "")
	if err != nil {
		t.Fatal(err)
	}
	if run.Archived != 2 || run.Compacted != 0 || len(run.Errors) != 0 || run.Guard.State != GuardOver {
		t.Errorf("run = %+v guard %+v", run, run.Guard)
	}
	if f.exists(oldEP) || f.exists(warmEP) || !f.exists(compactable) || !f.exists(recent) || !f.exists(today) {
		t.Errorf("calls = %v", f.mem.Calls)
	}
	if man, err := f.m.Archive.Get(oldEP); err != nil || man.Docs != 5 {
		t.Errorf("archive = %+v %v", man, err)
	}
	for _, c := range f.mem.Calls {
		if strings.HasPrefix(c, "block=") || strings.HasPrefix(c, "forcemerge") {
			t.Errorf("tried to change a blocked index: %v", f.mem.Calls)
		}
	}
}

func TestRunsNeverOverlap(t *testing.T) {
	f := newFixture(t, Config{Default: &Policy{KeepDays: 30, Archive: true}})
	for ago := 40; ago < 45; ago++ {
		f.add("endpoint", ago, GB, 20)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.mem.OnExport = func(string, int) {
		once.Do(func() { close(started); <-release })
	}
	var wg sync.WaitGroup
	var first *Run
	wg.Add(1)
	go func() {
		defer wg.Done()
		first, _ = f.m.Run(context.Background(), TriggerSchedule, "")
	}()
	<-started
	if _, err := f.m.Run(context.Background(), TriggerManual, "admin"); !errors.Is(err, ErrBusy) {
		t.Errorf("second run: %v", err)
	}
	if err := f.m.RunAsync(TriggerManual, "admin"); !errors.Is(err, ErrBusy) {
		t.Errorf("async run: %v", err)
	}
	if ov := f.m.Overview(context.Background()); !ov.Schedule.Running || ov.Schedule.Current != "run" {
		t.Errorf("schedule = %+v", ov.Schedule)
	}
	close(release)
	wg.Wait()
	if first == nil || first.Archived != 5 || len(first.Errors) != 0 {
		t.Errorf("first run = %+v", first)
	}
	if list, _, _ := f.m.Archive.List(); len(list) != 5 {
		t.Errorf("archives = %d", len(list))
	}
	// Many runs at once: exactly one does the work, the rest are told so.
	for ago := 50; ago < 55; ago++ {
		f.add("endpoint", ago, GB, 2)
	}
	var mu sync.Mutex
	done, busy := 0, 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run, err := f.m.Run(context.Background(), TriggerSchedule, "")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, ErrBusy):
				busy++
			case err == nil:
				done += run.Archived
			}
		}()
	}
	wg.Wait()
	if done != 5 || busy+1 > 8 {
		t.Errorf("archived %d across runs (busy %d)", done, busy)
	}
	if list, _, _ := f.m.Archive.List(); len(list) != 10 {
		t.Errorf("archives = %d, want 10 with no duplicates", len(list))
	}
}

func TestFindingsAndCasesRetention(t *testing.T) {
	f := newFixture(t, Config{Policies: map[string]Policy{Findings: {KeepDays: 365}}})
	old := testNow.AddDate(-2, 0, 0)
	recent := testNow.AddDate(0, -1, 0)
	f.mem.AddRecords("signalith_cases",
		Record{ID: "CASE-open", Status: "in_progress", Updated: old},
		Record{ID: "CASE-old", Status: "closed", Updated: old},
		Record{ID: "CASE-new", Status: "resolved", Updated: recent},
	)
	f.mem.AddRecords("signalith_findings",
		Record{ID: "f-open", Status: "new", Updated: old},
		Record{ID: "f-closed-old", Status: "closed", Updated: old},
		Record{ID: "f-resolved-old", Status: "resolved", Updated: old},
		Record{ID: "f-closed-recent", Status: "closed", Updated: recent},
		Record{ID: "f-in-open-case", Status: "closed", Updated: old, CaseID: "CASE-open"},
		Record{ID: "f-in-closed-case", Status: "closed", Updated: old, CaseID: "CASE-old"},
	)
	// Cases are kept forever by default; preview a policy for them.
	pv, err := f.m.Preview(context.Background(), Change{Category: Cases, Policy: &Policy{KeepDays: 180}})
	if err != nil {
		t.Fatal(err)
	}
	if pv.Summary.DeleteRecords != 1 || !pv.DeletesData || len(pv.Records) != 1 || pv.Records[0].Category != Cases {
		t.Errorf("preview = %+v", pv)
	}
	run, err := f.m.Run(context.Background(), TriggerSchedule, "")
	if err != nil {
		t.Fatal(err)
	}
	if run.DeletedRecords != 2 {
		t.Errorf("run = %+v", run)
	}
	findingsLeft := func() []string {
		var left []string
		for _, r := range f.mem.Records("signalith_findings") {
			left = append(left, r.ID)
		}
		return left
	}
	// A finding in an investigation stays as long as the investigation
	// does, open or closed: a case holds only its findings' IDs.
	if left := findingsLeft(); !slices.Equal(left, []string{"f-open", "f-closed-recent", "f-in-open-case", "f-in-closed-case"}) {
		t.Errorf("findings left = %v", left)
	}
	if len(f.mem.Records("signalith_cases")) != 3 {
		t.Error("cases were deleted without a policy")
	}
	if err := f.m.SetPolicy(Cases, &Policy{KeepDays: 180}); err != nil {
		t.Fatal(err)
	}
	f.m.Run(context.Background(), TriggerSchedule, "")
	if n := len(f.mem.Records("signalith_cases")); n != 2 {
		t.Errorf("cases left = %d", n)
	}
	_, acts := f.m.hist.get()
	if acts[0].Action != ActionDeleteRecords || acts[0].Category != Cases || acts[0].Docs != 1 {
		t.Errorf("actions = %+v", acts)
	}
	// Once its investigation is gone, the finding goes at the next run.
	f.m.Run(context.Background(), TriggerSchedule, "")
	if left := findingsLeft(); !slices.Equal(left, []string{"f-open", "f-closed-recent", "f-in-open-case"}) {
		t.Errorf("findings left after the case went = %v", left)
	}
	// If the investigations cannot be listed, no finding is deleted.
	f.mem.AddRecords("signalith_findings", Record{ID: "f-later", Status: "closed", Updated: old})
	f.mem.Fail["caseids signalith_cases"] = errors.New("boom")
	run, _ = f.m.Run(context.Background(), TriggerSchedule, "")
	if run.DeletedRecords != 0 || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "no findings are deleted") {
		t.Errorf("run without case list = %+v", run)
	}
}

func TestBrokenSettingsFilePausesRetention(t *testing.T) {
	f := newFixture(t, Config{Days: 30})
	a := f.add("endpoint", 40, GB, 1)
	os.MkdirAll(filepath.Dir(f.m.Store.Path), 0o750)
	os.WriteFile(f.m.Store.Path, []byte("policies:\n  endpoint: {keep_days: forever}\n"), 0o600)
	run, err := f.m.Run(context.Background(), TriggerSchedule, "")
	if err == nil || !strings.Contains(err.Error(), "paused") || !f.exists(a) || len(run.Errors) != 1 {
		t.Errorf("run = %+v, err = %v", run, err)
	}
	ov := f.m.Overview(context.Background())
	if ov.SettingsError == "" || ov.LastRun == nil || len(ov.LastRun.Errors) != 1 {
		t.Errorf("overview = %+v", ov)
	}
	if err := f.m.SetDefault(Policy{KeepDays: 10}); err == nil {
		t.Error("saved over a broken file")
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	f := newFixture(t, Config{Days: 30, Default: &Policy{KeepDays: 30, Archive: true}})
	name := f.add("endpoint", 40, GB, 1200)
	_, orig, _ := f.mem.Index(name)
	if _, err := f.m.Run(context.Background(), TriggerSchedule, ""); err != nil || f.exists(name) {
		t.Fatalf("archive run: %v", err)
	}
	list, err := f.m.Archives(context.Background())
	if err != nil || len(list.Archives) != 1 || list.Archives[0].Searchable || list.Archives[0].CategoryName != "Endpoint" || list.Docs != 1200 {
		t.Fatalf("archives = %+v %v", list, err)
	}

	if _, err := f.m.Restore(context.Background(), []string{"nope"}, 0, "admin", false); !errors.Is(err, ErrArchiveNotFound) {
		t.Errorf("unknown archive: %v", err)
	}
	if _, err := f.m.Restore(context.Background(), []string{name}, 400, "admin", false); err == nil {
		t.Error("keep_days 400 accepted")
	}
	sts, err := f.m.Restore(context.Background(), []string{name, name}, 0, "admin", false)
	if err != nil || len(sts) != 1 || sts[0].KeepUntil != "2026-10-26" || sts[0].State != RestoreQueued {
		t.Fatalf("restore = %+v %v", sts, err)
	}
	waitRestore(t, f.m, name)
	info, docs, ok := f.mem.Index(name)
	if !ok || len(docs) != 1200 || info.RestoredUntil != "2026-10-26" || info.WriteBlocked {
		t.Fatalf("restored index = %+v (%d docs)", info, len(docs))
	}
	for i := range docs {
		if docs[i].ID != orig[i].ID || string(docs[i].Source) != `{"n":`+strings.TrimPrefix(orig[i].ID, "id-")+`,"user":"bob","message":"line\nbreak"}` {
			t.Fatalf("doc %d = %s %s", i, docs[i].ID, docs[i].Source)
		}
	}
	// Restoring again does not duplicate events.
	if _, err := f.m.Restore(context.Background(), []string{name}, 7, "admin", false); err != nil {
		t.Fatal(err)
	}
	waitRestore(t, f.m, name)
	if info, docs, _ := f.mem.Index(name); len(docs) != 1200 || info.RestoredUntil != "2026-10-19" {
		t.Errorf("second restore: %d docs, until %s", len(docs), info.RestoredUntil)
	}

	// Retention keeps the restored day, and does not archive it again
	// once its time is up.
	if _, err := f.m.Run(context.Background(), TriggerSchedule, ""); err != nil || !f.exists(name) {
		t.Fatalf("run deleted a restored day: %v", err)
	}
	f.m.Now = func() time.Time { return testNow.AddDate(0, 0, 8) }
	run, _ := f.m.Run(context.Background(), TriggerSchedule, "")
	if f.exists(name) || run.Deleted != 1 || run.Archived != 0 {
		t.Errorf("after keep-until: run = %+v", run)
	}
	if list, _ := f.m.Archives(context.Background()); len(list.Archives) != 1 || list.Archives[0].Restore == nil || list.Archives[0].Restore.State != RestoreDone {
		t.Errorf("archives = %+v", list)
	}
	_, acts := f.m.hist.get()
	if !slices.ContainsFunc(acts, func(a Action) bool { return a.Action == ActionRestore && a.Docs == 1200 && a.By == "admin" }) {
		t.Errorf("actions = %+v", acts)
	}

	// A damaged archive restores nothing.
	man, _ := f.m.Archive.Get(name)
	p := filepath.Join(f.m.Archive.Dir, man.File)
	data, _ := os.ReadFile(p)
	data[100] ^= 1
	os.WriteFile(p, data, 0o600)
	if _, err := f.m.RestoreArchive(context.Background(), man, "2026-12-01", nil); err == nil || f.exists(name) {
		t.Errorf("damaged restore: %v, exists %v", err, f.exists(name))
	}
}

func waitRestore(t *testing.T, m *Manager, id string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		// The newest restore of the archive is the one to wait for.
		sts := m.restoreStatuses()
		i := slices.IndexFunc(sts, func(r RestoreStatus) bool { return r.ID == id })
		if i >= 0 && (sts[i].State == RestoreDone || sts[i].State == RestoreFailed) {
			if sts[i].State == RestoreFailed {
				t.Fatalf("restore failed: %s", sts[i].Error)
			}
			// Let the job release its lock.
			m.job.Lock()
			m.job.Unlock()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("restore did not finish")
}

func TestRestoreRefusesOtherPrefixes(t *testing.T) {
	f := newFixture(t, Config{})
	other := &Archive{Dir: f.m.Archive.Dir}
	mem := NewMemory()
	mem.AddIndex("otherprefix-endpoint-2026.07.01", 1, testDocs(2)...)
	if _, err := other.Write(context.Background(), mem, Source{Index: "otherprefix-endpoint-2026.07.01", Category: "endpoint", Day: "2026-07-01", Bytes: 1}, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Restore(context.Background(), []string{"otherprefix-endpoint-2026.07.01"}, 0, "admin", false); err == nil || !strings.Contains(err.Error(), "not a signalith-* daily index") {
		t.Errorf("restore = %v", err)
	}
}

func TestPreviewShowsOnlyTheChange(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	for ago := 0; ago < 120; ago++ {
		f.add("endpoint", ago, GB, 1)
		f.add("authentication", ago, GB, 1)
	}
	ctx := context.Background()
	pv, err := f.m.Preview(ctx, Change{Category: "endpoint", Policy: &Policy{KeepDays: 30, Archive: true}})
	if err != nil {
		t.Fatal(err)
	}
	// Today's policy already deletes days 91 to 119 of both categories;
	// the change adds days 31 to 90 of endpoint, and archives all 89.
	s := pv.Summary
	if s.DeleteDays != 89 || s.ArchiveDays != 89 || s.DeleteBytes != 89*GB || !slices.Equal(s.Categories, []string{"endpoint"}) || !pv.DeletesData {
		t.Errorf("summary = %+v", s)
	}
	// What the current settings already delete is listed apart (Due): the
	// run a save starts does it too.
	if pv.Due.DeleteDays != 29 || !slices.Equal(pv.Due.Categories, []string{"authentication"}) {
		t.Errorf("due = %+v", pv.Due)
	}
	pv, _ = f.m.Preview(ctx, Change{Category: "endpoint", Policy: &Policy{KeepDays: 90, CompactAfterDays: 7}})
	if pv.Summary.DeleteDays != 0 || pv.Summary.CompactDays != 83 || pv.Due.DeleteDays != 58 || !pv.DeletesData {
		t.Errorf("compact preview = %+v due %+v", pv.Summary, pv.Due)
	}
	pv, _ = f.m.Preview(ctx, Change{Default: &Policy{KeepDays: 100}})
	if pv.Summary.DeleteDays != 0 {
		t.Errorf("longer default = %+v", pv.Summary)
	}
	f.mem.DiskTotal, f.mem.DiskBase = 300*GB, 0 // 240 GB used: 80%
	pv, _ = f.m.Preview(ctx, Change{Guard: &Guard{MaxDiskPercent: 60}})
	if pv.Guard.State != GuardOver || pv.Summary.DeleteDays == 0 {
		t.Errorf("guard preview = %+v %+v", pv.Guard, pv.Summary)
	}
	if _, err := f.m.Preview(ctx, Change{Category: "endpoint", Policy: &Policy{KeepDays: -3}}); err == nil {
		t.Error("invalid policy previewed")
	}
	if _, err := f.m.Preview(ctx, Change{Category: "endpoint", Default: &Policy{}}); err == nil {
		t.Error("two changes at once previewed")
	}
}

func TestOverview(t *testing.T) {
	f := newFixture(t, Config{Days: 90, Policies: map[string]Policy{"change": {KeepDays: 400}}})
	f.add("endpoint", 0, 3*GB, 4)
	f.add("endpoint", 100, 2*GB, 5)
	f.add("authentication", 10, GB, 6)
	f.mem.AddIndex("signalith_findings", 7000)
	f.mem.AddIndex("signalith_intel", 9000)
	f.mem.AddIndex("signalith-mystery", 5)
	f.mem.AddRecords("signalith_findings", Record{ID: "a", Status: "new", Created: dayAgo(30)}, Record{ID: "b", Status: "new", Created: dayAgo(2)})
	f.mem.DiskTotal, f.mem.DiskBase = 100*GB, 40*GB
	ov := f.m.Overview(context.Background())
	if ov.Error != "" || ov.SettingsError != "" {
		t.Fatalf("errors: %s %s", ov.Error, ov.SettingsError)
	}
	var ids []string
	cats := map[string]CategoryView{}
	for _, c := range ov.Categories {
		ids = append(ids, c.ID)
		cats[c.ID] = c
	}
	// No "other" events yet, so that row is left out.
	if !slices.Equal(ids, []string{"authentication", "endpoint", "network_traffic", "change", "filesystem", "registry", "network_resolution", "image_load", "script", "inventory", "configuration_check", "alerts", "risk", Findings, Cases, Intel}) {
		t.Errorf("categories = %v", ids)
	}
	ep := cats["endpoint"]
	if ep.Bytes != 5*GB || ep.Docs != 9 || ep.Days != 2 || ep.OldestDay != "2026-07-04" || ep.NewestDay != "2026-10-12" ||
		ep.Policy.KeepDays != 90 || ep.Source != SourceDefault || !ep.Editable || ep.Pending.DeleteDays != 1 {
		t.Errorf("endpoint = %+v", ep)
	}
	if ch := cats["change"]; ch.Editable || ch.Source != SourceConfig || ch.Note != "From signalith.yaml" || ch.Policy.KeepDays != 400 {
		t.Errorf("change = %+v", ch)
	}
	if in := cats[Intel]; in.Editable || in.Note != "Managed by feeds" || in.Bytes != 9000 {
		t.Errorf("intel = %+v", in)
	}
	if fi := cats[Findings]; fi.Bytes != 7000 || fi.OldestDay != "2026-09-12" || fi.NewestDay != "2026-10-10" || fi.Policy.KeepDays != 0 || !fi.Editable {
		t.Errorf("findings = %+v", fi)
	}
	if ov.TotalBytes != 6*GB+16000 || ov.Disk == nil || ov.Disk.Percent() < 40 || ov.Guard.Status.State != GuardOK || !ov.Guard.Enabled ||
		ov.Guard.MaxDiskPercent != 85 || ov.Guard.Source != SourceBuiltin || !ov.Guard.Editable {
		t.Errorf("overview = %+v", ov)
	}
	if ov.Default.Source != SourceDays || ov.Default.Policy.KeepDays != 90 || !ov.Default.Editable {
		t.Errorf("default = %+v", ov.Default)
	}
	if len(ov.Unmanaged) != 1 || ov.Unmanaged[0].Name != "signalith-mystery" {
		t.Errorf("unmanaged = %+v", ov.Unmanaged)
	}
	if ov.Pending.DeleteDays != 1 || ov.Schedule.Interval != "1h" || ov.Schedule.Automatic || ov.Schedule.NextRun != nil {
		t.Errorf("pending = %+v schedule = %+v", ov.Pending, ov.Schedule)
	}
	if ov.Archive.Dir != f.m.Archive.Dir || ov.Archive.Files != 0 {
		t.Errorf("archive = %+v", ov.Archive)
	}

	// OpenSearch down: the page still gets policies (every category but
	// "other", which has no events), and says why sizes are missing.
	f.mem.Fail["indices"] = errors.New("connection refused")
	ov = f.m.Overview(context.Background())
	if !strings.Contains(ov.Error, "connection refused") || len(ov.Categories) != len(Categories())-1 || ov.Guard.Status.State != GuardUnknown {
		t.Errorf("down: %+v", ov)
	}
}

func TestGuardTriggersARun(t *testing.T) {
	f := newFixture(t, Config{})
	f.add("endpoint", 30, 10*GB, 1)
	f.mem.DiskTotal, f.mem.DiskBase = 100*GB, 80*GB // 90%
	if !f.m.guardTripped(context.Background()) {
		t.Fatal("guard did not trip at 90%")
	}
	run, _ := f.m.Run(context.Background(), TriggerGuard, "")
	if run.Deleted != 1 || run.Guard == nil || run.Guard.State != GuardOver {
		t.Errorf("run = %+v", run)
	}
	// Still over (the rest is not Signalith's), and nothing is left to
	// delete: the next check waits for the next scheduled run.
	if _, err := f.m.Run(context.Background(), TriggerGuard, ""); err != nil {
		t.Fatal(err)
	}
	if f.m.guardTripped(context.Background()) {
		t.Error("guard keeps triggering runs that cannot help")
	}
}

func TestSettingsChanges(t *testing.T) {
	f := newFixture(t, Config{Days: 90, Policies: map[string]Policy{"risk": {KeepDays: 30}}})
	if err := f.m.SetPolicy("risk", &Policy{KeepDays: 10}); !errors.Is(err, ErrFromConfig) {
		t.Errorf("config policy: %v", err)
	}
	if err := f.m.SetPolicy("risk", nil); !errors.Is(err, ErrFromConfig) {
		t.Errorf("config reset: %v", err)
	}
	if err := f.m.SetPolicy(Intel, &Policy{KeepDays: 10}); !errors.Is(err, ErrManaged) {
		t.Errorf("intel: %v", err)
	}
	var pe *PolicyError
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 5, CompactAfterDays: 9}); !errors.As(err, &pe) {
		t.Errorf("invalid: %v", err)
	}
	if err := f.m.SetPolicy(Findings, &Policy{KeepDays: 5, Archive: true}); !errors.As(err, &pe) {
		t.Errorf("archive findings: %v", err)
	}
	if err := f.m.SetDefault(Policy{KeepDays: 60, CompactAfterDays: 3}); err != nil {
		t.Fatal(err)
	}
	if err := f.m.SetGuard(Guard{MaxDiskPercent: 80}); err != nil {
		t.Fatal(err)
	}
	if err := f.m.SetPolicy("endpoint", &Policy{KeepDays: 7}); err != nil {
		t.Fatal(err)
	}
	s, err := f.m.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if p, src := s.For("endpoint"); p.KeepDays != 7 || src != SourceUI {
		t.Errorf("endpoint = %+v %s", p, src)
	}
	if p, src := s.For("change"); p.KeepDays != 60 || p.CompactAfterDays != 3 || src != SourceDefault {
		t.Errorf("change = %+v %s", p, src)
	}
	if !s.Guard.IsEnabled() || s.Guard.MaxDiskPercent != 80 || s.Guard.MinDays != 7 || s.GuardSource != SourceUI {
		t.Errorf("guard = %+v", s.Guard)
	}
	if err := f.m.SetPolicy("endpoint", nil); err != nil {
		t.Fatal(err)
	}
	s, _ = f.m.Settings()
	if p, src := s.For("endpoint"); p.KeepDays != 60 || src != SourceDefault {
		t.Errorf("after reset = %+v %s", p, src)
	}
	if err := (&Manager{}).SetDefault(Policy{}); err == nil {
		t.Error("saved without a store")
	}
}

// The archive part of the fingerprint names the folder, not what is in it:
// it does not change as days are archived, is the same for servers that
// share the folder, and differs for another folder.
func TestFingerprintNamesTheArchiveFolder(t *testing.T) {
	f := newFixture(t, Config{Days: 30, Default: &Policy{KeepDays: 30, Archive: true}})
	_, before := f.m.Fingerprint()
	if before == "" {
		t.Fatal("no archive fingerprint while archiving")
	}
	f.add("endpoint", 40, GB, 5)
	if run, err := f.m.Run(context.Background(), TriggerSchedule, ""); err != nil || run.Archived != 1 {
		t.Fatalf("run %+v %v", run, err)
	}
	if _, after := f.m.Fingerprint(); after != before {
		t.Error("archiving a day changed the fingerprint")
	}
	// Another server sharing the folder.
	shared := &Manager{Cluster: f.mem, Prefix: "signalith", Config: f.m.Config, Store: NewStore(filepath.Join(t.TempDir(), "retention.yaml")),
		Archive: &Archive{Dir: f.m.Archive.Dir}}
	if _, other := shared.Fingerprint(); other != before {
		t.Error("a server sharing the archive folder has another fingerprint")
	}
	shared.Archive.Dir = t.TempDir()
	if _, other := shared.Fingerprint(); other == before {
		t.Error("another archive folder has the same fingerprint")
	}
	// Without archiving, no part at all.
	plain := newFixture(t, Config{Days: 30})
	if _, a := plain.m.Fingerprint(); a != "" {
		t.Errorf("archive fingerprint %q without archiving", a)
	}
}

// A run started in the background shows as running from the moment it is
// started, not only once its goroutine gets going, so a page (or a test)
// that asks at once never takes it for finished; Wait waits for it,
// history file included.
func TestBackgroundRunShowsAsRunningAtOnce(t *testing.T) {
	f := newFixture(t, Config{Default: &Policy{KeepDays: 30, Archive: true}})
	for i, start := range []func() error{
		func() error { return f.m.RunAsync(TriggerManual, "admin") },
		func() error { _, err := f.m.ApplySoon(TriggerChange, "admin"); return err },
	} {
		// A day to archive, whose export waits until the checks are done.
		f.add("endpoint", 40+i, GB, 2)
		release := make(chan struct{})
		var once sync.Once
		f.mem.OnExport = func(string, int) { once.Do(func() { <-release }) }
		if err := start(); err != nil {
			t.Fatal(err)
		}
		if ov := f.m.Overview(context.Background()); !ov.Schedule.Running || ov.Schedule.Current != "run" {
			t.Errorf("right after starting: schedule = %+v", ov.Schedule)
		}
		if job := f.m.Job(); job != "run" {
			t.Errorf("job = %q", job)
		}
		close(release)
		f.m.Wait()
		if ov := f.m.Overview(context.Background()); ov.Schedule.Running {
			t.Errorf("after Wait: schedule = %+v", ov.Schedule)
		}
		if _, err := os.Stat(f.m.HistoryFile); err != nil {
			t.Errorf("history not written before Wait returned: %v", err)
		}
	}
}
