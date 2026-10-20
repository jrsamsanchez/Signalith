// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// otherServer is a second server sharing l's OpenSearch.
func otherServer(l *Loader, name string) *Loader {
	return &Loader{Prefix: l.Prefix, Bulk: l.Bulk, OS: l.OS, Intel: l.Intel, Findings: l.Findings, Cases: l.Cases,
		Docs: l.Docs, Server: name, Now: l.Now}
}

// set writes a document of the runtime index as another process would.
func (m *memDocs) set(t *testing.T, id string, body any) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.next(body)
	if err != nil {
		t.Fatal(err)
	}
	m.docs[m.key("signalith_runtime", id)] = d
}

// remove deletes the record as another process would.
func (m *memDocs) remove() {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.docs, m.key("signalith_runtime", stateID))
}

// failingOS fails every delete from one index, as an OpenSearch error part
// way through a removal would.
type failingOS struct {
	*fakeOS
	index string
}

func (f failingOS) Do(ctx context.Context, method, path string, body, out any) error {
	if strings.HasPrefix(path, "/"+f.index+"/_delete_by_query") {
		return &store.Error{Status: http.StatusInternalServerError, Body: "boom"}
	}
	return f.fakeOS.Do(ctx, method, path, body, out)
}

// A removal that stops part way leaves the set marked as not finished, on
// every server, rather than as loaded: a load is refused, and running the
// removal again finishes it.
func TestStoppedRemovalShowsUnfinished(t *testing.T) {
	ctx := context.Background()
	l, _, fos, _, _ := newTestLoader(t, t.TempDir())
	seed(t, l, &State{ID: "sample-x", Size: SizeStandard, Events: 27000, Findings: 31, LoadedAt: fixedNow})
	l.OS = failingOS{fos, "signalith-risk-2026.10.10"}
	if _, err := l.Remove(ctx, nil); err == nil {
		t.Fatal("the removal should have failed")
	}

	other := otherServer(l, "siem-b")
	other.OS = fos
	st, act, err := other.Current(ctx)
	if err != nil || act != nil || st == nil || !st.Partial || !st.Removing {
		t.Fatalf("after a stopped removal another server sees %+v, %+v, %v; want an unfinished removal", st, act, err)
	}
	if _, err := other.Load(ctx, SizeSmall, nil); !errors.Is(err, ErrPartial) {
		t.Errorf("Load after a stopped removal = %v, want ErrPartial", err)
	}
	if _, err := other.Remove(ctx, nil); err != nil {
		t.Fatalf("running the removal again: %v", err)
	}
	if rec := l.Docs.(*memDocs).record(t); rec != nil {
		t.Errorf("record left: %+v", rec)
	}
}

// Whether a job runs is judged by whether its record changes, on the
// reader's own clock: never by comparing the heartbeat's time, written by
// another computer's clock, with this one's.
func TestJobJudgedByChangeNotClock(t *testing.T) {
	ctx := context.Background()
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	clk := useClock(l)
	docs := l.Docs.(*memDocs)
	put := func(a *Activity) {
		docs.put(t, stateDoc{Kind: stateKind, State: &State{ID: "sample-b", Partial: true}, Job: a, Owner: "siem-b-load"})
	}

	// A computer whose clock is ten minutes slow runs a load: its
	// heartbeats look old here, but they keep coming.
	job := &Activity{Op: "load", Phase: "Writing events", Server: "siem-b", Node: "n_b", Process: "p_b", Beat: time.Now().Add(-10 * time.Minute)}
	put(job)
	for range 4 {
		if l.Activity(ctx) == nil {
			t.Fatal("a running job with a slow clock shows as stopped")
		}
		if _, err := l.Remove(ctx, nil); !errors.Is(err, ErrBusy) {
			t.Fatalf("Remove took over a running job: %v", err)
		}
		clk.add(40 * time.Second)
		job.Percent += 10
		put(job)
	}

	// A computer whose clock is an hour fast stops: its last heartbeat
	// looks new here, but the record stands still.
	job.Beat = time.Now().Add(time.Hour)
	put(job)
	if l.Activity(ctx) == nil {
		t.Fatal("the job shows as stopped at once")
	}
	clk.add(StaleJob)
	if a := l.Activity(ctx); a != nil {
		t.Fatalf("a job whose record stood still for a minute shows as running: %+v", a)
	}
	if st, err := l.Remove(ctx, nil); err != nil || st == nil {
		t.Fatalf("Remove of the stopped job's load = %+v, %v", st, err)
	}
}

// A job this server recorded from an earlier process (it was restarted
// or stopped mid-load) is stopped at once; one of this process runs.
func TestJobOfEarlierRunIsStopped(t *testing.T) {
	ctx := context.Background()
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	useClock(l)
	l.NodeID = "n_a"
	docs := l.Docs.(*memDocs)
	put := func(node, process string) {
		docs.put(t, stateDoc{Kind: stateKind, State: &State{ID: "sample-a", Partial: true},
			Job: &Activity{Op: "load", Server: "siem-a", Node: node, Process: process, Beat: time.Now()}})
	}
	put("n_a", processID)
	if l.Activity(ctx) == nil {
		t.Error("this process's own job shows as stopped")
	}
	put("n_b", "another")
	if l.Activity(ctx) == nil {
		t.Error("another server's job shows as stopped at once")
	}
	put("n_a", "an-earlier-process")
	if a := l.Activity(ctx); a != nil {
		t.Errorf("a job of an earlier run of this server shows as running: %+v", a)
	}
	if _, err := l.Load(ctx, SizeSmall, nil); !errors.Is(err, ErrPartial) {
		t.Errorf("Load = %v, want ErrPartial", err)
	}
	if st, err := l.Remove(ctx, nil); err != nil || st == nil {
		t.Fatalf("Remove = %+v, %v", st, err)
	}
}

// flakyDocs applies a PutIf but answers with a timeout, as a write whose
// answer was lost and whose recheck saw the old version would; failPuts
// and failDeletes fail the next writes outright, as a busy OpenSearch.
type flakyDocs struct {
	*memDocs
	mu          sync.Mutex
	loseNext    bool
	failPuts    int
	failDeletes int
}

func (f *flakyDocs) PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error) {
	f.mu.Lock()
	lose, fail := f.loseNext, f.failPuts > 0
	f.loseNext = false
	if fail {
		f.failPuts--
	}
	f.mu.Unlock()
	if fail {
		return store.Version{}, &store.Error{Status: http.StatusTooManyRequests, Body: "busy"}
	}
	nv, err := f.memDocs.PutIf(ctx, index, id, body, v, refresh)
	if err == nil && lose {
		return store.Version{}, context.DeadlineExceeded
	}
	return nv, err
}

func (f *flakyDocs) DeleteIf(ctx context.Context, index, id string, v store.Version, refresh bool) error {
	f.mu.Lock()
	fail := f.failDeletes > 0
	if fail {
		f.failDeletes--
	}
	f.mu.Unlock()
	if fail {
		return &store.Error{Status: http.StatusServiceUnavailable, Body: "busy"}
	}
	return f.memDocs.DeleteIf(ctx, index, id, v, refresh)
}

// A write that went through although its answer was lost does not make
// the job think another process took it over.
func TestLostAnswerIsNotTakeover(t *testing.T) {
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	fd := &flakyDocs{memDocs: newMemDocs()}
	l.Docs = fd
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	st := &State{ID: "sample-y", Partial: true}
	j, err := l.startLoad(ctx, cancel, st)
	if err != nil {
		t.Fatal(err)
	}
	fd.loseNext = true
	_ = j.save(st) // went through, but its answer was lost
	st.Events = 10
	if err := j.save(st); err != nil {
		t.Fatalf("the next write = %v", err)
	}
	if c := context.Cause(ctx); c != nil {
		t.Fatalf("the job was stopped: %v", c)
	}
	st.Partial = false
	if err := j.end(st); err != nil {
		t.Fatalf("end = %v", err)
	}
	if rec := fd.record(t); rec == nil || rec.Job != nil || rec.State.Partial || rec.State.Events != 10 {
		t.Errorf("record = %+v", rec)
	}
}

// A job that ends while OpenSearch is busy tries a few times to settle its
// record, and gives up only after that.
func TestEndTriesAgain(t *testing.T) {
	defer func(b time.Duration) { endBackoff = b }(endBackoff)
	endBackoff = time.Millisecond
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	fd := &flakyDocs{memDocs: newMemDocs()}
	l.Docs = fd
	start := func() *job {
		t.Helper()
		ctx, cancel := context.WithCancelCause(context.Background())
		t.Cleanup(func() { cancel(nil) })
		j, err := l.startLoad(ctx, cancel, &State{ID: "sample-z", Partial: true})
		if err != nil {
			t.Fatal(err)
		}
		return j
	}

	j := start()
	fd.failPuts = endTries - 1
	if err := j.end(&State{ID: "sample-z", LoadedAt: fixedNow}); err != nil {
		t.Fatalf("end with OpenSearch busy for a moment = %v", err)
	}
	if rec := fd.record(t); rec == nil || rec.Job != nil || rec.State.Partial {
		t.Fatalf("record = %+v", rec)
	}
	fd.remove()

	j = start()
	fd.failDeletes = endTries - 1
	if err := j.end(nil); err != nil {
		t.Fatalf("end of a removal with OpenSearch busy for a moment = %v", err)
	}
	if rec := fd.record(t); rec != nil {
		t.Fatalf("record left: %+v", rec)
	}

	j = start()
	fd.failPuts = endTries
	if err := j.end(&State{ID: "sample-z"}); err == nil {
		t.Error("end succeeded although every try failed")
	}
	fd.failPuts = 0
}

// WatchJob tells the command line whether a job recorded as running still
// runs: its record moves on, or it stands still for a minute.
func TestWatchJob(t *testing.T) {
	ctx := context.Background()
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	clk := useClock(l)
	docs := l.Docs.(*memDocs)
	job := &Activity{Op: "load", Phase: "Writing events", Server: "build-host", Command: true, Process: "p"}
	put := func() { docs.put(t, stateDoc{Kind: stateKind, State: &State{ID: "sample-c", Partial: true}, Job: job}) }

	if w, _, err := l.WatchJob(ctx, time.Minute); w != JobNone || err != nil {
		t.Errorf("nothing recorded: %v, %v", w, err)
	}
	put()
	moves := 0
	l.sleep = func(ctx context.Context, d time.Duration) error {
		clk.add(d)
		if moves++; moves == 3 {
			job.Percent = 20
			put()
		}
		return nil
	}
	if w, a, err := l.WatchJob(ctx, 10*time.Second); w != JobRunning || a == nil || a.Percent != 20 || err != nil {
		t.Errorf("a job that moved on: %v, %+v, %v", w, a, err)
	}

	cmd := otherServer(l, "cli")
	useClock(cmd)
	if w, _, _ := cmd.WatchJob(ctx, 10*time.Second); w != JobUnknown {
		t.Errorf("a job still for 10 seconds: %v, want JobUnknown", w)
	}
	if w, _, _ := cmd.WatchJob(ctx, StaleJob); w != JobStopped {
		t.Errorf("a job still for a minute: %v, want JobStopped", w)
	}
	if _, err := cmd.Remove(ctx, nil); err != nil {
		t.Errorf("Remove after watching the job stop: %v", err)
	}
}

// A load is refused while the server running the background jobs runs a
// version without sample data, whose scheduled detections and feeds would
// not leave it out.
func TestLoadRefusedWhileJobsServerIsOld(t *testing.T) {
	ctx := context.Background()
	l, _, _, _, fb := newTestLoader(t, t.TempDir())
	docs := l.Docs.(*memDocs)
	docs.set(t, cluster.LeaseDocID, cluster.LeaseDoc{Kind: "lease", Job: "jobs", Holder: "n_b", HolderName: "siem-b", HolderVersion: "1.4.0"})
	hb := cluster.Heartbeat{Kind: "node", NodeID: "n_b", Name: "siem-b", Version: "1.4.0", State: cluster.StateReady}
	docs.set(t, cluster.NodeDocID("n_b"), hb)

	_, err := l.Load(ctx, SizeSmall, nil)
	var old *OldJobsServerError
	if !errors.As(err, &old) || old.Name != "siem-b" || old.Version != "1.4.0" {
		t.Fatalf("Load = %v, want an OldJobsServerError naming siem-b", err)
	}
	if st, _ := l.Status(ctx); st != nil || len(fb.docs) != 0 {
		t.Fatalf("a refused load wrote something: %+v, %d events", st, len(fb.docs))
	}

	hb.State = cluster.StateStopped
	docs.set(t, cluster.NodeDocID("n_b"), hb)
	if err := l.CheckJobsServer(ctx); err != nil {
		t.Errorf("a stopped jobs server: %v", err)
	}
	hb.State, hb.Features = cluster.StateReady, []string{cluster.FeatureSampleData}
	docs.set(t, cluster.NodeDocID("n_b"), hb)
	if _, err := l.Load(ctx, SizeSmall, nil); err != nil {
		t.Fatalf("Load with an up-to-date jobs server: %v", err)
	}
}

// Remove refreshes before it looks for marked events, so those written a
// moment before are found, and looks again before it clears the record,
// deleting what turned up meanwhile.
func TestRemoveFindsRecentEvents(t *testing.T) {
	ctx := context.Background()
	l, _, fos, _, _ := newTestLoader(t, t.TempDir())
	fos.late = []string{"signalith-risk-2026.10.12"}
	seed(t, l, &State{ID: "sample-r", Partial: true})
	if _, err := l.Remove(ctx, nil); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	want := []string{"signalith-authentication-2026.10.09", "signalith-risk-2026.10.10", "signalith-risk-2026.10.12"}
	got := slices.Clone(fos.deleted)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("deleted from %v, want each of %v once", fos.deleted, want)
	}
	// All of it in the first pass: the last look found nothing left.
	if i := slices.Index(fos.log, "count"); i < 0 || !slices.Contains(fos.log[:i], "delete:signalith-risk-2026.10.12") ||
		slices.Index(fos.log, "refresh") > slices.Index(fos.log, "search") {
		t.Errorf("calls %v: want a refresh before the search, and every delete before the last look", fos.log)
	}

	// A write still being applied lands while the removal runs.
	l, _, fos, _, _ = newTestLoader(t, t.TempDir())
	landed := false
	fos.onDelete = func(f *fakeOS) {
		if !landed {
			landed = true
			f.late = append(f.late, "signalith-network-2026.10.12")
		}
	}
	seed(t, l, &State{ID: "sample-r", Partial: true})
	if _, err := l.Remove(ctx, nil); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !slices.Contains(fos.deleted, "signalith-network-2026.10.12") {
		t.Errorf("the events that landed during the removal were left: deleted from %v", fos.deleted)
	}

	// Events that keep coming: the removal says so and keeps the record,
	// so it can be run again.
	l, _, fos, _, _ = newTestLoader(t, t.TempDir())
	n := 0
	fos.onDelete = func(f *fakeOS) {
		n++
		f.late = append(f.late, "signalith-network-2026.10."+string(rune('a'+n%26)))
	}
	seed(t, l, &State{ID: "sample-r", Partial: true})
	if _, err := l.Remove(ctx, nil); err == nil {
		t.Fatal("Remove succeeded while events kept coming")
	}
	if st, _ := l.Status(ctx); st == nil || !st.Partial || !st.Removing {
		t.Errorf("record after the stopped removal: %+v", st)
	}
}

// A load that OpenSearch took none of the events of leaves nothing to
// remove, so it leaves no record: the next step is simply to load again.
func TestNothingWrittenLeavesNoRecord(t *testing.T) {
	ctx := context.Background()
	l, _, _, _, fb := newTestLoader(t, t.TempDir())
	fb.rejectAll = true
	if _, err := l.Load(ctx, SizeSmall, nil); !errors.Is(err, ErrNothingWritten) {
		t.Fatalf("Load = %v, want ErrNothingWritten", err)
	}
	if st, err := l.Status(ctx); st != nil || err != nil {
		t.Fatalf("record after a load that wrote nothing: %+v, %v", st, err)
	}
	fb.rejectAll = false
	if _, err := l.Load(ctx, SizeSmall, nil); err != nil {
		t.Fatalf("Load again: %v", err)
	}
}

// syncIntel is a fakeIntel that another process may change: Sync counts
// the reads.
type syncIntel struct {
	fakeIntel
	syncs int
}

func (s *syncIntel) Sync(context.Context) (bool, error) {
	s.syncs++
	return true, nil
}

// Another server reads the threat intel again as soon as it sees the
// sample set change, not up to a minute later, and only then.
func TestFollowSyncsIntelOnChange(t *testing.T) {
	ctx := context.Background()
	a, _, _, _, _ := newTestLoader(t, t.TempDir())
	b, _, _, _, _ := newTestLoader(t, t.TempDir())
	b.Docs, b.Server = a.Docs, "siem-b"
	si := &syncIntel{}
	b.Intel = si

	syncs := func(want int) {
		t.Helper()
		if err := b.SyncLists(ctx); err != nil {
			t.Fatal(err)
		}
		if si.syncs != want {
			t.Errorf("threat intel read %d times, want %d", si.syncs, want)
		}
	}
	syncs(1)
	syncs(1)
	if _, err := a.Load(ctx, SizeSmall, nil); err != nil {
		t.Fatal(err)
	}
	syncs(2)
	syncs(2)
	if _, err := a.Remove(ctx, nil); err != nil {
		t.Fatal(err)
	}
	syncs(3)
}

// Changes counts the sample sets a server's reads see come and go.
func TestChangesCountsSets(t *testing.T) {
	ctx := context.Background()
	a, _, _, _, _ := newTestLoader(t, t.TempDir())
	b := otherServer(a, "siem-b")
	_, _ = b.Status(ctx)
	if _, err := a.Load(ctx, SizeSmall, nil); err != nil {
		t.Fatal(err)
	}
	_, _ = b.Status(ctx)
	_, _ = b.Status(ctx)
	if n := b.Changes(); n != 1 {
		t.Errorf("after a load: %d changes, want 1", n)
	}
	if _, err := a.Remove(ctx, nil); err != nil {
		t.Fatal(err)
	}
	_, _ = b.Status(ctx)
	if n := b.Changes(); n != 2 {
		t.Errorf("after a removal: %d changes, want 2", n)
	}
}

// WaitJobs returns once this process's jobs have settled their records.
func TestWaitJobs(t *testing.T) {
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	j, err := l.startLoad(ctx, cancel, &State{ID: "sample-w", Partial: true})
	if err != nil {
		t.Fatal(err)
	}
	if WaitJobs(20 * time.Millisecond) {
		t.Error("WaitJobs returned while a job runs")
	}
	go func() { _ = j.end(&State{ID: "sample-w", Partial: true}) }()
	if !WaitJobs(5 * time.Second) {
		t.Error("WaitJobs did not return once the job ended")
	}
}

// The record's owner survives a round trip, under body.
func TestRecordOwner(t *testing.T) {
	b, _ := json.Marshal(stateDoc{Kind: stateKind, State: &State{ID: "x"}, Owner: "tok"})
	var back stateDoc
	if err := json.Unmarshal(b, &back); err != nil || back.Owner != "tok" {
		t.Errorf("round trip %s = %+v, %v", b, back, err)
	}
	if !strings.Contains(string(b), `"body":{`) || strings.Contains(string(b), `"owner":"tok","kind"`) {
		t.Errorf("owner not under body: %s", b)
	}
}
