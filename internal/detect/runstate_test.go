package detect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// TestStatusWhileStateIsWritten: the Detections page and the health
// check read the run state while the scheduler writes it (run with
// -race).
func TestStatusWhileStateIsWritten(t *testing.T) {
	lib := OnlyRules(t, &Detection{ID: "rule-r", Title: "R", Query: "user=r", Enabled: true, Schedule: "5m", Lookback: "5m"})
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, &recRunner{}, clock)
	ctx := context.Background()
	s.RunDue(ctx)
	if _, err := s.StatusCtx(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Make every read refresh the cache.
			s.mu.Lock()
			s.cache.at = time.Time{}
			s.mu.Unlock()
			if _, err := s.StatusCtx(ctx); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := range 200 {
		e, _ := s.entry("rule-r")
		e.doc.LastResults = i
		if _, err := s.writeState(ctx, e, 0); err != nil {
			t.Fatal(err)
		}
		if err := s.writeManual(ctx, "rule-r", ManualRun{At: t0, Results: i}); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}

// failingFindings fails Create as fail says.
type failingFindings struct {
	findings.Store
	fail atomic.Bool
}

func (f *failingFindings) Create(ctx context.Context, fd *findings.Finding) error {
	if f.fail.Load() {
		return &store.Error{Status: http.StatusBadRequest, Body: `{"error":{"type":"mapper_parsing_exception"}}`}
	}
	return f.Store.Create(ctx, fd)
}

// TestFailedWriteIsRetried: a finding OpenSearch refuses to store is not
// a broken rule. The slot runs again, finds its own throttle claim, and
// raises the finding.
func TestFailedWriteIsRetried(t *testing.T) {
	d := &Detection{ID: "rule-w", Title: "W", Query: "user=w", Enabled: true, Schedule: "5m", Lookback: "5m", Throttle: Throttle{Window: "1h", Fields: []string{"user"}}}
	lib := OnlyRules(t, d)
	run := &recRunner{rows: map[string][]search.Row{"user=w": {{"user": "bob"}}}}
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, run, clock)
	fs := &failingFindings{Store: findings.NewMemory()}
	fs.fail.Store(true)
	s.Findings = fs
	ctx := context.Background()
	s.RunDue(ctx)
	last := mustState(t, s, "rule-w").LastSlot
	clock.Add(5 * time.Minute)
	s.RunDue(ctx)
	st := mustState(t, s, "rule-w")
	if st.ErrorKind != ErrorTransient || !st.LastSlot.Equal(last) {
		t.Fatalf("a failed write moved on: %+v", st)
	}
	fs.fail.Store(false)
	s.RunDue(ctx)
	st = mustState(t, s, "rule-w")
	if st.LastError != "" || st.LastFindings != 1 || !st.LastSlot.Equal(last.Add(5*time.Minute)) {
		t.Fatalf("after the retry: %+v", st)
	}
	if ErrorKind(&store.Error{Status: http.StatusBadRequest}) != ErrorTransient ||
		ErrorKind(&searchError{Err: &store.Error{Status: http.StatusBadRequest}}) != ErrorQuery {
		t.Error("a 400 outside the search is taken for a broken rule, or one of the search is not")
	}
}

// TestCapHoldsWhenASlotRunsAgain: findings a slot raised before count
// toward the cap when it runs again, so it raises no more.
func TestCapHoldsWhenASlotRunsAgain(t *testing.T) {
	d := &Detection{ID: "rule-c", Title: "C", Query: "user=c", Enabled: true, Schedule: "5m", Lookback: "5m"}
	lib := OnlyRules(t, d)
	run := &recRunner{rows: map[string][]search.Row{"user=c": {{"user": "a"}, {"user": "b"}, {"user": "c"}, {"user": "d"}}}}
	s := newTestScheduler(lib, run, &fakeClock{t: t0})
	s.MaxFindingsPerRun = 2
	fs := findings.NewMemory()
	s.Findings = fs
	ctx := context.Background()
	spec := runSpec{at: t0, slot: t0, raised: t0}
	first, err := s.run(ctx, d, spec)
	if err != nil || len(first.Findings) != 2 || !first.Capped {
		t.Fatalf("first run: %+v, %v", first, err)
	}
	again, err := s.run(ctx, d, spec)
	if err != nil || len(again.Findings) != 0 || again.Duplicates != 2 || !again.Capped {
		t.Fatalf("the slot run again: %+v, %v", again, err)
	}
	if _, n, _ := fs.Search(ctx, findings.Filter{}); n != 2 {
		t.Errorf("%d findings for a cap of 2", n)
	}
}

// TestRunStateOfAnOlderLeaseIsRefused: a run that started under one lease
// epoch cannot write its state once the lease has moved on, even when
// this server holds the lease again.
func TestRunStateOfAnOlderLeaseIsRefused(t *testing.T) {
	lib := OnlyRules(t, &Detection{ID: "rule-e", Title: "E", Query: "user=e", Enabled: true, Schedule: "5m", Lookback: "5m"})
	s := newTestScheduler(lib, &recRunner{}, &fakeClock{t: t0})
	var epoch atomic.Int64
	epoch.Store(1)
	s.Epoch = epoch.Load
	ctx := context.Background()
	s.RunDue(ctx)
	e, ok := s.entry("rule-e")
	if !ok {
		t.Fatal("no state")
	}
	epoch.Store(3)
	e.doc.LastSlot = e.doc.LastSlot.Add(-time.Hour)
	if _, err := s.writeState(ctx, e, 1); !errors.Is(err, errStaleEpoch) {
		t.Fatalf("a write of epoch 1 under epoch 3: %v", err)
	}
	raw, _, _, _ := s.memRuns.Get(ctx, s.runtimeIndex(), detStateID("rule-e"))
	if st := decodeState(t, raw); st.Epoch != 1 || !st.LastSlot.Equal(e.doc.LastSlot.Add(time.Hour)) {
		t.Errorf("stored %+v", st)
	}
}

// TestDeletedManualOnlyRuleIsRemoved: a rule only ever run with Run now,
// then deleted, loses its Run now record and throttles a day later.
func TestDeletedManualOnlyRuleIsRemoved(t *testing.T) {
	lib := OnlyRules(t, &Detection{ID: "kept", Title: "K", Query: "user=k", Enabled: true, Schedule: "5m", Lookback: "5m"})
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, &recRunner{}, clock)
	rs := NewMemoryRunStore()
	s.Runtime = rs
	ctx := context.Background()
	idx := s.runtimeIndex()
	if _, err := rs.Create(ctx, idx, detManualID("gone"), manualDoc{Kind: kindDetManual, DetectionID: "gone"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := rs.Create(ctx, idx, throttleID("gone", "k"), throttleDoc{Kind: kindThrottle, DetectionID: "gone", GroupKey: "k", Slot: manualSlot}, false); err != nil {
		t.Fatal(err)
	}
	s.RunDue(ctx)
	if st := mustState(t, s, "gone"); !st.GoneSince.Equal(t0) || st.Enabled {
		t.Fatalf("state %+v", st)
	}
	clock.Add(goneFor)
	s.RunDue(ctx)
	docs, _ := rs.SearchDocs(ctx, idx, nil)
	for _, d := range docs {
		if d.ID != detStateID("kept") {
			t.Errorf("left: %s", d.ID)
		}
	}
}

// TestPreUpgradeFindingHoldsForTheWholeWindow: a finding raised before
// throttles were documents holds its group back for the rule's whole
// throttle window, even when that is longer than a week.
func TestPreUpgradeFindingHoldsForTheWholeWindow(t *testing.T) {
	d := &Detection{ID: "rule-l", Title: "L", Query: "user=l", Enabled: true, Schedule: "1h", Lookback: "1h", Throttle: Throttle{Window: "720h", Fields: []string{"user"}}}
	lib := OnlyRules(t, d)
	row := search.Row{"user": "bob"}
	run := &recRunner{rows: map[string][]search.Row{"user=l": {row}}}
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, run, clock)
	fs := findings.NewMemory()
	s.Findings = fs
	ctx := context.Background()
	old := &findings.Finding{ID: "old", DetectionID: "rule-l", GroupKey: GroupKey(d, row), Status: findings.StatusNew,
		Created: t0.Add(-24 * time.Hour), Updated: t0.Add(-24 * time.Hour)}
	if err := fs.Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	s.RunDue(ctx)
	clock.Add(8 * 24 * time.Hour)
	s.RunDue(ctx)
	if st := mustState(t, s, "rule-l"); st.LastThrottled == 0 {
		t.Fatalf("state %+v", st)
	}
	if _, n, _ := fs.Search(ctx, findings.Filter{}); n != 1 {
		t.Errorf("%d findings: the old one stopped holding after a week", n)
	}
}

// TestFirstStartRunsTheCurrentSlot: with no run state at all (the first
// start after the upgrade), each enabled rule runs its current slot at
// once, as every start did before, and nothing older.
func TestFirstStartRunsTheCurrentSlot(t *testing.T) {
	lib := OnlyRules(t,
		&Detection{ID: "rule-f", Title: "F", Query: "user=f", Enabled: true, Schedule: "1h", Lookback: "1h"},
		&Detection{ID: "rule-off", Title: "Off", Query: "user=off", Schedule: "1h", Lookback: "1h"},
	)
	run := &recRunner{}
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, run, clock)
	s.noFirstStart = false
	ctx := context.Background()
	s.RunDue(ctx)
	cur := SlotAt("rule-f", time.Hour, t0)
	w := run.windows("user=")
	if len(w) != 1 || !w[0].to.Equal(cur) || !w[0].from.Equal(cur.Add(-time.Hour)) {
		t.Fatalf("first start searched %+v, want just up to %v", w, cur)
	}
	if st := mustState(t, s, "rule-f"); !st.LastSlot.Equal(cur) {
		t.Errorf("state %+v", st)
	}
	// A rule turned on later starts at its next slot, as a new rule does.
	on, _ := lib.Get("rule-off")
	cp := *on
	cp.Enabled = true
	if err := lib.Put(&cp); err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Minute)
	s.RunDue(ctx)
	if n := len(run.windows("user=off")); n != 0 {
		t.Errorf("a rule turned on later ran %d times at once", n)
	}
}

func decodeState(t *testing.T, raw []byte) DetState {
	t.Helper()
	var st DetState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return st
}
