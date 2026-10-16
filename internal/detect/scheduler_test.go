package detect

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeClock is a clock tests move by hand; the scheduler's workers read
// it at once.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var t0 = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)

// call is one search a run made.
type call struct {
	key      string
	from, to time.Time
}

// recRunner records every search, answers the ones whose query mentions
// a key of rows with those rows, and fails the ones err says to.
type recRunner struct {
	mu    sync.Mutex
	calls []call
	rows  map[string][]search.Row
	err   func(q string) error
}

func (r *recRunner) Execute(ctx context.Context, q *query.Query) (*search.Result, error) {
	key := q.String()
	from, _ := time.Parse(time.RFC3339, q.Earliest)
	to, _ := time.Parse(time.RFC3339, q.Latest)
	r.mu.Lock()
	r.calls = append(r.calls, call{key, from, to})
	errf, rows := r.err, r.rows
	r.mu.Unlock()
	if errf != nil {
		if err := errf(key); err != nil {
			return nil, err
		}
	}
	for marker, rs := range rows {
		if strings.Contains(key, marker) {
			return &search.Result{Kind: "table", Rows: rs}, nil
		}
	}
	return &search.Result{Kind: "table"}, nil
}

// windows returns the windows searched by queries mentioning marker, in
// order.
func (r *recRunner) windows(marker string) []call {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []call
	for _, c := range r.calls {
		if strings.Contains(c.key, marker) {
			out = append(out, c)
		}
	}
	return out
}

func newTestScheduler(lib *Library, run Runner, clock *fakeClock) *Scheduler {
	return (&Scheduler{Library: lib, Engine: run, Findings: findings.NewMemory(), Now: clock.Now,
		Log: slog.New(slog.DiscardHandler), CatchUp: DefaultCatchUp}).AsNew()
}

func mustState(t *testing.T, s *Scheduler, id string) DetState {
	t.Helper()
	st, ok := s.LeaderState(id)
	if !ok {
		t.Fatalf("no run state for %s", id)
	}
	return st
}

func TestSlotGrid(t *testing.T) {
	s := 5 * time.Minute
	for _, id := range []string{"auth-brute-force", "x", "another-rule"} {
		o := SlotOffset(id, s)
		if o < 0 || o >= s || o%time.Second != 0 || o != SlotOffset(id, s) {
			t.Errorf("%s: offset %v", id, o)
		}
		for _, now := range []time.Time{t0, t0.Add(1234 * time.Second), time.Unix(-1000, 0), time.Unix(7, 0)} {
			end := SlotAt(id, s, now)
			if end.After(now) || now.Sub(end) >= s || (end.Unix()-int64(o/time.Second))%300 != 0 || end.Location() != time.UTC {
				t.Errorf("%s at %v: slot %v", id, now, end)
			}
		}
		// Exactly on a slot end, that is the slot.
		on := SlotAt(id, s, t0).Add(s)
		if got := SlotAt(id, s, on); !got.Equal(on) {
			t.Errorf("%s on the boundary %v: %v", id, on, got)
		}
		if got := SlotAt(id, s, on.Add(-time.Nanosecond)); !got.Equal(on.Add(-s)) {
			t.Errorf("%s just before the boundary: %v", id, got)
		}
		if got := Slots(id, s, on.Add(-2*s), on, 10); len(got) != 2 || !got[1].Equal(on) {
			t.Errorf("slots %v", got)
		}
		if got := Slots(id, s, on.Add(-100*s), on, 48); len(got) != 48 || !got[0].Equal(on.Add(-99*s)) {
			t.Errorf("capped slots: %d from %v", len(got), got[0])
		}
	}
	if SlotOffset("auth-brute-force", time.Hour) == SlotOffset("auth-password-spray", time.Hour) {
		t.Error("two rules got the same offset")
	}
	// Floor division below the epoch.
	if got := floorDiv(-1, 60); got != -1 {
		t.Errorf("floorDiv(-1, 60) = %d", got)
	}
}

func TestSlotIDsAreStable(t *testing.T) {
	slot := time.Date(2026, 10, 12, 9, 15, 7, 0, time.UTC)
	a, b := SlotFindingID("rule-r", "k", slot), SlotFindingID("rule-r", "k", slot.In(time.FixedZone("x", 3600)))
	if a != b || !strings.HasPrefix(a, "20261012-091507-") || len(a) != len("20261012-091507-")+8 {
		t.Errorf("finding IDs %q %q", a, b)
	}
	if SlotFindingID("rule-r", "k", slot.Add(time.Minute)) == a || SlotFindingID("rule-r", "k2", slot) == a {
		t.Error("finding IDs collide")
	}
	if RiskEventID("rule-r", "k", slot, "user", "Bob") != RiskEventID("rule-r", "k", slot, "user", "bob") || len(RiskEventID("rule-r", "k", slot, "user", "bob")) != 24 {
		t.Error("risk event IDs differ by case or have the wrong length")
	}
}

// TestSlowDetectionTimesOut reproduces dos-5: detections ran one at a
// time, each for up to five minutes, so one slow query held up every
// other detection. Now a run stops at its timeout and says so, the other
// detections run on the other workers meanwhile, and a slot that keeps
// timing out is given up after three tries.
func TestSlowDetectionTimesOut(t *testing.T) {
	lib := OnlyRules(t,
		&Detection{ID: "aaa-slow", Title: "Slow", Query: "user=slow", Enabled: true, Schedule: "5m", Lookback: "1h"},
		&Detection{ID: "bbb-fast", Title: "Fast", Query: "user=fast", Enabled: true, Schedule: "5m", Lookback: "1h"},
	)
	run := &slowRunner{}
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, run, clock)
	s.Workers, s.Timeout = 2, 300*time.Millisecond
	s.RunDue(context.Background()) // first sight: nothing runs
	if len(run.done) != 0 {
		t.Fatalf("ran at first sight: %v", run.done)
	}
	clock.Add(5 * time.Minute)
	first := mustState(t, s, "aaa-slow").LastSlot
	start := time.Now()
	s.RunDue(context.Background())
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("RunDue took %v", took)
	}
	slow := s.Status()["aaa-slow"]
	if !slow.TimedOut || slow.ErrorKind != ErrorTimeout || !strings.Contains(slow.LastError, "timed out after 300ms") || slow.Running || !slow.LastSlot.Equal(first) {
		t.Errorf("slow detection state %+v", slow)
	}
	if fast := s.Status()["bbb-fast"]; fast.LastRun.IsZero() || fast.LastError != "" || !fast.LastSlot.After(first.Add(-5*time.Minute)) {
		t.Errorf("fast detection state %+v", fast)
	}
	if !run.done["user=fast"].Before(run.done["slow"]) {
		t.Error("the fast detection waited for the slow one")
	}
	// Two more tries of the same slot, then it is given up.
	s.RunDue(context.Background())
	if st := mustState(t, s, "aaa-slow"); st.Attempts != 2 || !st.LastSlot.Equal(first) {
		t.Errorf("after two tries: %+v", st)
	}
	s.RunDue(context.Background())
	if st := mustState(t, s, "aaa-slow"); st.Attempts != 0 || !st.LastSlot.After(first) || !st.TimedOut {
		t.Errorf("after three tries: %+v", st)
	}

	// A run stopped by its caller (the server shutting down, a closed
	// request) is not a timeout.
	d, _ := lib.Get("aaa-slow")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if _, err := s.RunManual(ctx, d, ""); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled run: %v", err)
	}
}

// slowRunner answers at once, except for queries mentioning "slow", which
// run until their context ends. It records how many runs of each query
// overlap.
type slowRunner struct {
	mu      sync.Mutex
	running map[string]int
	overlap bool
	done    map[string]time.Time
}

func (r *slowRunner) Execute(ctx context.Context, q *query.Query) (*search.Result, error) {
	key := q.String()
	if strings.Contains(key, "slow") {
		key = "slow"
	}
	r.mu.Lock()
	if r.running == nil {
		r.running, r.done = map[string]int{}, map[string]time.Time{}
	}
	r.running[key]++
	if r.running[key] > 1 {
		r.overlap = true
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running[key]--
		r.done[key] = time.Now()
		r.mu.Unlock()
	}()
	if key == "slow" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &search.Result{Kind: "table"}, nil
}

// TestCatchUpRunsMissedSlotsInOrder: slots missed while detections did
// not run are run later, oldest first, each with its own window, 48 per
// tick, after the rules that are on time.
func TestCatchUpRunsMissedSlotsInOrder(t *testing.T) {
	lib := OnlyRules(t,
		&Detection{ID: "catch", Title: "Catching up", Query: "user=catch", Enabled: true, Schedule: "1m", Lookback: "1m"},
		&Detection{ID: "hourly", Title: "On time", Query: "user=hourly", Enabled: true, Schedule: "1h", Lookback: "1h"},
	)
	run := &recRunner{}
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, run, clock)
	s.Workers = 1
	s.RunDue(context.Background())
	last := mustState(t, s, "catch").LastSlot
	clock.Add(time.Hour)
	s.RunDue(context.Background())
	if len(run.calls) == 0 || !strings.Contains(run.calls[0].key, "hourly") {
		t.Fatalf("the rule on time did not run first: %v", run.calls)
	}
	w := run.windows("catch")
	if len(w) != 48 {
		t.Fatalf("%d catch-up runs in one tick, want 48", len(w))
	}
	for i, c := range w {
		want := last.Add(time.Duration(i+1) * time.Minute)
		if !c.to.Equal(want) || !c.from.Equal(want.Add(-time.Minute)) {
			t.Errorf("run %d searched %v..%v, want up to %v", i, c.from, c.to, want)
		}
	}
	if st := mustState(t, s, "catch"); !st.LastSlot.Equal(w[47].to) || st.Skipped.Count != 0 || st.LateRuns == 0 {
		t.Errorf("state %+v", st)
	}
	s.RunDue(context.Background())
	w = run.windows("catch")
	if len(w) != 60 || !w[59].to.Equal(last.Add(time.Hour)) {
		t.Fatalf("after the second tick %d runs, last up to %v", len(w), w[len(w)-1].to)
	}
	for i := 1; i < len(w); i++ {
		if !w[i].from.Equal(w[i-1].to) {
			t.Errorf("gap or overlap between %v and %v", w[i-1].to, w[i].from)
		}
	}
	if !Behind(mustDet(t, lib, "catch"), s.Status()["catch"], clock.Now()) {
		t.Error("late runs in the last hour do not count as behind")
	}
}

func mustDet(t *testing.T, lib *Library, id string) *Detection {
	t.Helper()
	d, err := lib.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestCatchUpLimitSkips: missed slots older than detections.catch_up are
// skipped and recorded; with catch-up off only the current slot runs.
func TestCatchUpLimitSkips(t *testing.T) {
	lib := OnlyRules(t, &Detection{ID: "catch", Title: "Catching up", Query: "user=catch", Enabled: true, Schedule: "1m", Lookback: "1m"})
	run := &recRunner{}
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, run, clock)
	s.RunDue(context.Background())
	last := mustState(t, s, "catch").LastSlot
	clock.Add(8 * time.Hour)
	s.RunDue(context.Background())
	st := s.Status()["catch"]
	sk := st.Skipped
	if sk == nil || sk.Count != 120 || !sk.From.Equal(last) || !sk.To.Equal(last.Add(2*time.Hour)) || !sk.At.Equal(clock.Now()) {
		t.Fatalf("skipped %+v", sk)
	}
	w := run.windows("catch")
	if len(w) != 48 || !w[0].to.Equal(sk.To.Add(time.Minute)) {
		t.Errorf("%d runs, first up to %v", len(w), w[0].to)
	}

	s.SetCatchUp(0)
	clock.Add(time.Hour)
	before := len(run.windows("catch"))
	s.RunDue(context.Background())
	w = run.windows("catch")
	cur := SlotAt("catch", time.Minute, clock.Now())
	if len(w) != before+1 || !w[len(w)-1].to.Equal(cur) {
		t.Errorf("with catch-up off: %d new runs, last up to %v, want just %v", len(w)-before, w[len(w)-1].to, cur)
	}
	if st := mustState(t, s, "catch"); !st.Skipped.To.Equal(cur.Add(-time.Minute)) || !st.LastSlot.Equal(cur) {
		t.Errorf("state %+v", st)
	}
}

// TestErrorsRetryOrAdvance: a slot that failed because OpenSearch did not
// answer runs again; one whose rule cannot run as written does not.
func TestErrorsRetryOrAdvance(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		kind string
	}{
		"busy":      {search.ErrBusy, ErrorTransient},
		"503":       {&store.Error{Status: http.StatusServiceUnavailable, Body: "{}"}, ErrorTransient},
		"cancelled": {context.Canceled, ErrorTransient},
		"query":     {&search.QueryError{Msg: "unknown field"}, ErrorQuery},
		"400":       {&store.Error{Status: http.StatusBadRequest, Body: `{"error":{"type":"search_phase_execution_exception"}}`}, ErrorQuery},
	} {
		t.Run(name, func(t *testing.T) {
			lib := OnlyRules(t, &Detection{ID: "rule-r", Title: "R", Query: "user=r", Enabled: true, Schedule: "5m", Lookback: "5m"})
			fail := true
			run := &recRunner{err: func(string) error {
				if fail {
					return tc.err
				}
				return nil
			}}
			clock := &fakeClock{t: t0}
			s := newTestScheduler(lib, run, clock)
			s.RunDue(context.Background())
			last := mustState(t, s, "rule-r").LastSlot
			clock.Add(10 * time.Minute)
			s.RunDue(context.Background())
			st := mustState(t, s, "rule-r")
			if st.ErrorKind != tc.kind || st.LastError == "" {
				t.Fatalf("state %+v", st)
			}
			n := len(run.calls)
			if tc.kind == ErrorTransient {
				// The batch stopped at the failed slot, which runs again.
				if !st.LastSlot.Equal(last) || n != 1 {
					t.Fatalf("watermark %v (was %v), %d runs", st.LastSlot, last, n)
				}
				fail = false
				s.RunDue(context.Background())
				if st := mustState(t, s, "rule-r"); !st.LastSlot.Equal(last.Add(10*time.Minute)) || st.LastError != "" || len(run.calls) != 3 {
					t.Errorf("after the retry: %+v, %d runs", st, len(run.calls))
				}
				if !run.calls[1].to.Equal(run.calls[0].to) {
					t.Error("the retry searched another slot")
				}
				return
			}
			if !st.LastSlot.Equal(last.Add(10*time.Minute)) || n != 2 {
				t.Errorf("a query error did not move on: %v (was %v), %d runs", st.LastSlot, last, n)
			}
		})
	}
	// A query that does not parse never reaches OpenSearch.
	lib := OnlyRules(t, &Detection{ID: "bad", Title: "Bad", Query: "user=x", Enabled: true, Schedule: "5m", Lookback: "5m"})
	d, _ := lib.Get("bad")
	d.Query = "user=x | stats count by"
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, &recRunner{}, clock)
	if _, err := s.run(context.Background(), d, runSpec{at: t0, slot: t0, raised: t0}); ErrorKind(err) != ErrorQuery {
		t.Errorf("parse error is %q: %v", ErrorKind(err), err)
	}
}

// countingStore counts the writes to a RunStore.
type countingStore struct {
	RunStore
	mu     sync.Mutex
	writes map[string]int
}

func (c *countingStore) count(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writes == nil {
		c.writes = map[string]int{}
	}
	c.writes[id]++
}

func (c *countingStore) Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error) {
	c.count(id)
	return c.RunStore.Create(ctx, index, id, body, refresh)
}

func (c *countingStore) PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error) {
	c.count(id)
	return c.RunStore.PutIf(ctx, index, id, body, v, refresh)
}

func (c *countingStore) n(id string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes[id]
}

// TestNewEnabledAndRescheduledRulesStartAtNextSlot: a rule seen for the
// first time, turned back on, or given a new schedule starts at its next
// slot, with nothing replayed. A change to the query keeps the watermark.
func TestNewEnabledAndRescheduledRulesStartAtNextSlot(t *testing.T) {
	d := &Detection{ID: "rule-r", Title: "R", Query: "user=r", Enabled: true, Schedule: "5m", Lookback: "5m"}
	lib := OnlyRules(t, d)
	run := &recRunner{}
	clock := &fakeClock{t: t0}
	rs := &countingStore{RunStore: NewMemoryRunStore()}
	s := newTestScheduler(lib, run, clock)
	s.Runtime = rs
	S := 5 * time.Minute

	// New: nothing runs until its next slot.
	s.RunDue(context.Background())
	st := mustState(t, s, "rule-r")
	if !st.LastSlot.Equal(SlotAt("rule-r", S, t0)) || !st.Enabled || st.Schedule != "5m" || len(run.calls) != 0 || st.Created.IsZero() {
		t.Fatalf("new rule: %+v, %d runs", st, len(run.calls))
	}
	clock.Add(S)
	s.RunDue(context.Background())
	if len(run.calls) != 1 {
		t.Fatalf("%d runs at the next slot", len(run.calls))
	}

	// Turned off: enabled:false written once.
	off := *d
	off.Enabled = false
	if err := lib.Put(&off); err != nil {
		t.Fatal(err)
	}
	writes := rs.n(detStateID("rule-r"))
	for range 3 {
		s.RunDue(context.Background())
	}
	if got := rs.n(detStateID("rule-r")) - writes; got != 1 || mustState(t, s, "rule-r").Enabled {
		t.Errorf("a rule turned off wrote its state %d times", got)
	}
	// Back on after three hours: nothing replayed.
	clock.Add(3 * time.Hour)
	if err := lib.Put(d); err != nil {
		t.Fatal(err)
	}
	s.RunDue(context.Background())
	if st := mustState(t, s, "rule-r"); len(run.calls) != 1 || !st.LastSlot.Equal(SlotAt("rule-r", S, clock.Now())) {
		t.Fatalf("re-enabled: %+v, %d runs", st, len(run.calls))
	}
	clock.Add(S)
	s.RunDue(context.Background())
	if len(run.calls) != 2 {
		t.Fatalf("%d runs after re-enabling", len(run.calls))
	}

	// A new schedule: a new grid, from its next slot.
	re := *d
	re.Schedule, re.Lookback = "10m", "10m"
	if err := lib.Put(&re); err != nil {
		t.Fatal(err)
	}
	clock.Add(30 * time.Minute)
	s.RunDue(context.Background())
	if st := mustState(t, s, "rule-r"); len(run.calls) != 2 || !st.LastSlot.Equal(SlotAt("rule-r", 10*time.Minute, clock.Now())) || st.Schedule != "10m" {
		t.Fatalf("rescheduled: %+v, %d runs", st, len(run.calls))
	}

	// A new query only: the missed slots are caught up.
	q := re
	q.Query = "user=r2"
	if err := lib.Put(&q); err != nil {
		t.Fatal(err)
	}
	clock.Add(30 * time.Minute)
	s.RunDue(context.Background())
	if len(run.calls) != 5 || !strings.Contains(run.calls[4].key, "r2") {
		t.Errorf("after a query change: %d runs", len(run.calls))
	}
}

// TestDeletedRuleStateIsRemoved: a rule no longer in the library is
// marked gone, and a day later its run state, Run now record and
// throttles are removed.
func TestDeletedRuleStateIsRemoved(t *testing.T) {
	d := &Detection{ID: "rule-r", Title: "R", Query: "user=r", Enabled: true, Schedule: "5m", Lookback: "5m", Throttle: Throttle{Window: "1h"}}
	lib := OnlyRules(t, d)
	run := &recRunner{rows: map[string][]search.Row{"user=r": {{"user": "bob"}}}}
	clock := &fakeClock{t: t0}
	rs := NewMemoryRunStore()
	s := newTestScheduler(lib, run, clock)
	s.Runtime = rs
	s.RunDue(context.Background())
	clock.Add(5 * time.Minute)
	s.RunDue(context.Background())
	ctx := context.Background()
	idx := s.runtimeIndex()
	if _, err := rs.Create(ctx, idx, detManualID("rule-r"), manualDoc{Kind: kindDetManual, DetectionID: "rule-r"}, false); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		docs, _ := rs.SearchDocs(ctx, idx, nil)
		return len(docs)
	}
	if n := count(); n != 3 {
		t.Fatalf("%d runtime documents, want state, manual and throttle", n)
	}
	if err := lib.Delete("rule-r"); err != nil {
		t.Fatal(err)
	}
	clock.Add(housekeepEvery)
	s.RunDue(context.Background())
	if st := mustState(t, s, "rule-r"); !st.GoneSince.Equal(clock.Now()) {
		t.Fatalf("gone since %v", st.GoneSince)
	}
	clock.Add(goneFor)
	s.RunDue(context.Background())
	if n := count(); n != 0 {
		t.Errorf("%d runtime documents left a day after the rule was deleted", n)
	}
	if _, ok := s.LeaderState("rule-r"); ok {
		t.Error("the leader still keeps its state")
	}
}

// TestScheduledThrottles: a throttle holds a group back from the slot
// that raised it until its window ends, through throttle documents.
func TestScheduledThrottles(t *testing.T) {
	d := &Detection{ID: "rule-r", Title: "R {user}", Query: "user=r", Enabled: true, Schedule: "5m", Lookback: "5m", Throttle: Throttle{Window: "1h", Fields: []string{"user"}}}
	lib := OnlyRules(t, d)
	run := &recRunner{rows: map[string][]search.Row{"user=r": {{"user": "bob"}}}}
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, run, clock)
	s.RunDue(context.Background())
	clock.Add(5 * time.Minute)
	s.RunDue(context.Background())
	first := mustState(t, s, "rule-r")
	if first.LastFindings != 1 {
		t.Fatalf("first slot %+v", first)
	}
	raw, _, found, _ := s.memRuns.Get(context.Background(), s.runtimeIndex(), throttleID("rule-r", GroupKey(d, map[string]any{"user": "bob"})))
	var th throttleDoc
	if !found || json.Unmarshal(raw, &th) != nil || th.Slot != first.LastSlot.Format(time.RFC3339) || !th.Until.Equal(first.LastSlot.Add(time.Hour)) ||
		th.FindingID != SlotFindingID("rule-r", GroupKey(d, map[string]any{"user": "bob"}), first.LastSlot) {
		t.Fatalf("throttle %s", raw)
	}
	clock.Add(55 * time.Minute)
	s.RunDue(context.Background())
	if st := mustState(t, s, "rule-r"); st.LastFindings != 0 || st.LastThrottled != 1 {
		t.Errorf("within the window %+v", st)
	}
	clock.Add(5 * time.Minute)
	s.RunDue(context.Background())
	if st := mustState(t, s, "rule-r"); st.LastFindings != 1 {
		t.Errorf("after the window %+v", st)
	}
	list, _, _ := s.Findings.Search(context.Background(), findings.Filter{})
	if len(list) != 2 || list[0].Slot == nil || list[0].RaisedAt.IsZero() || !list[0].Created.Equal(*list[0].Slot) {
		t.Errorf("findings %+v", list)
	}
}

// TestSameSlotsWhateverTheWallClock: two schedulers whose wall clocks
// are 5 s apart, but that share OpenSearch's time, work out the same
// slots.
func TestSameSlotsWhateverTheWallClock(t *testing.T) {
	lib := OnlyRules(t, &Detection{ID: "rule-r", Title: "R", Query: "user=r", Enabled: true, Schedule: "1m", Lookback: "1m"})
	cluster := &fakeClock{t: t0.Add(30 * time.Second)}
	a := newTestScheduler(lib, &recRunner{}, &fakeClock{t: t0})
	b := newTestScheduler(lib, &recRunner{}, &fakeClock{t: t0.Add(5 * time.Second)})
	a.ClusterNow, b.ClusterNow = cluster.Now, cluster.Now
	a.RunDue(context.Background())
	b.RunDue(context.Background())
	if sa, sb := mustState(t, a, "rule-r").LastSlot, mustState(t, b, "rule-r").LastSlot; !sa.Equal(sb) || !sa.Equal(SlotAt("rule-r", time.Minute, cluster.Now())) {
		t.Errorf("slots %v and %v", sa, sb)
	}
}

func TestRunTimeout(t *testing.T) {
	s := &Scheduler{}
	for sched, want := range map[string]time.Duration{
		"1m": time.Minute, "2m": 2 * time.Minute, "5m": 5 * time.Minute, "1h": MaxRunTimeout, "bogus": MaxRunTimeout,
	} {
		if got := s.RunTimeout(&Detection{Schedule: sched}); got != want {
			t.Errorf("schedule %s: %v, want %v", sched, got, want)
		}
	}
	s.Timeout = 10 * time.Second
	if got := s.RunTimeout(&Detection{Schedule: "1h"}); got != 10*time.Second {
		t.Errorf("explicit timeout: %v", got)
	}
}

// TestStartDoesNotOverlapRuns: with workers busy, a detection that is
// still waiting or running is not started again on the next tick.
func TestStartDoesNotOverlapRuns(t *testing.T) {
	lib := OnlyRules(t,
		&Detection{ID: "aaa-slow", Title: "Slow", Query: "user=slow", Enabled: true, Schedule: "5m", Lookback: "1h"},
		&Detection{ID: "bbb-fast", Title: "Fast", Query: "user=fast", Enabled: true, Schedule: "1m", Lookback: "1h"},
	)
	run := &slowRunner{}
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, run, clock)
	s.Workers, s.Timeout, s.Tick = 1, 100*time.Millisecond, 5*time.Millisecond
	s.RunDue(context.Background())
	clock.Add(time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	s.Start(ctx)
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.overlap {
		t.Error("a detection ran twice at once")
	}
	for key, n := range run.running {
		if n != 0 {
			t.Errorf("%s still running after Start returned", key)
		}
	}
	if run.done["slow"].IsZero() {
		t.Error("the slow detection never ran")
	}
}

// searcher answers every search with no hits, and blocks the ones whose
// request mentions "analyst" until release is closed.
type searcher struct{ started, release chan struct{} }

func (s searcher) Search(ctx context.Context, _ string, body map[string]any) (map[string]any, error) {
	b, _ := json.Marshal(body)
	if strings.Contains(string(b), "analyst") {
		s.started <- struct{}{}
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return map[string]any{"hits": map[string]any{"total": map[string]any{"value": 0}, "hits": []any{}}}, nil
}

// TestDetectionsDoNotWaitForAnalysts: the search engine caps searches at
// once, but the scheduler's runs (already bounded by Workers) do not
// queue behind analysts' searches.
func TestDetectionsDoNotWaitForAnalysts(t *testing.T) {
	st := searcher{started: make(chan struct{}, 1), release: make(chan struct{})}
	eng := &search.Engine{Store: st, Opt: search.Options{MaxSearches: 1, QueueWait: 50 * time.Millisecond}}
	go eng.Run(context.Background(), "user=analyst")
	<-st.started
	if _, err := eng.Run(context.Background(), "user=other"); !errors.Is(err, search.ErrBusy) {
		t.Fatalf("second analyst search: %v, want ErrBusy", err)
	}

	lib, _, _ := NewLibrary("")
	clock := &fakeClock{t: t0}
	s := newTestScheduler(lib, eng, clock)
	s.RunDue(context.Background())
	clock.Add(15 * time.Minute)
	s.RunDue(context.Background())
	ok := 0
	for id, rs := range s.Status() {
		switch {
		case strings.Contains(rs.LastError, "busy"):
			t.Errorf("%s: %s", id, rs.LastError)
		case rs.LastError == "" && !rs.LastRun.IsZero():
			ok++
		}
	}
	if ok == 0 {
		t.Error("no detection ran")
	}
	close(st.release)
}
