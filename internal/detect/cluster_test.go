package detect_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/risk"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// These tests run schedulers against the fake OpenSearch, where the
// versions and create-only writes of the real one decide what happens.

const runtimeIndex = "t_runtime"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

// rowsRunner answers every search with the same rows.
type rowsRunner struct{ rows []search.Row }

func (r rowsRunner) Execute(context.Context, *query.Query) (*search.Result, error) {
	return &search.Result{Kind: "table", Rows: r.rows}, nil
}

type rig struct {
	t   *testing.T
	srv *ostest.Server
	cl  *store.Client
	fs  *findings.OpenSearch
	rk  *risk.Store
	lib *detect.Library
	run detect.Runner
}

func newRig(t *testing.T, rows []search.Row, ds ...*detect.Detection) *rig {
	srv := ostest.New(t)
	cl := store.New(store.Config{URL: srv.URL})
	return &rig{t: t, srv: srv, cl: cl, fs: &findings.OpenSearch{Client: cl, Index: "t_findings"},
		rk: &risk.Store{Client: cl, Prefix: "t"}, lib: detect.OnlyRules(t, ds...), run: rowsRunner{rows}}
}

// scheduler is one server's scheduler, with its own wall clock, the
// cluster time, and the lease epoch it holds.
func (r *rig) scheduler(wall, cluster *clock, epoch int64, node string) *detect.Scheduler {
	return (&detect.Scheduler{Library: r.lib, Engine: r.run, Findings: r.fs, Risk: r.rk,
		Now: wall.Now, ClusterNow: cluster.Now, Log: slog.New(slog.DiscardHandler),
		Runtime: r.cl, RuntimeIndex: runtimeIndex, Epoch: func() int64 { return epoch }, NodeID: node}).AsNew()
}

func (r *rig) docs(index string) []store.Doc {
	r.t.Helper()
	docs, err := r.cl.SearchDocs(context.Background(), index, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	return docs
}

// detstate returns a rule's stored run state.
func (r *rig) detstate(id string) detect.DetState {
	r.t.Helper()
	var st detect.DetState
	b, _ := json.Marshal(r.srv.Source(runtimeIndex, "detstate:"+id))
	if err := json.Unmarshal(b, &st); err != nil {
		r.t.Fatal(err)
	}
	return st
}

// rewind moves a rule's stored watermark back by d, as when the server
// that ran a slot stopped before it recorded it.
func (r *rig) rewind(id string, d time.Duration) {
	src := r.srv.Source(runtimeIndex, "detstate:"+id)
	last, _ := time.Parse(time.RFC3339, src["last_slot"].(string))
	src["last_slot"] = last.Add(-d).Format(time.RFC3339)
	r.srv.Put(runtimeIndex, "detstate:"+id, src)
}

func slotOf(id string, s time.Duration, now time.Time) time.Time { return detect.SlotAt(id, s, now) }

var t0 = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)

// TestTwoServersRaiseTheSameFindings: a slot run again on another server
// (a new leader, whose wall clock is 5 s off) finds the same IDs and
// times, and stores nothing twice.
func TestTwoServersRaiseTheSameFindings(t *testing.T) {
	d := &detect.Detection{ID: "shared-rule", Title: "Seen {user}", Query: "user=* | stats count by user, dest", Enabled: true,
		Schedule: "5m", Lookback: "5m", Severity: "medium",
		Risk: &detect.Risk{Score: 10, Objects: []detect.RiskObject{{Field: "user", Type: "user"}, {Field: "dest", Type: "system"}}}}
	r := newRig(t, []search.Row{{"user": "bob", "dest": "web1"}, {"user": "alice", "dest": "web2"}}, d)
	cluster := &clock{t: t0}
	a := r.scheduler(cluster, cluster, 1, "node-a")
	a.RunDue(context.Background())
	cluster.Set(t0.Add(5 * time.Minute))
	a.RunDue(context.Background())
	slot := slotOf(d.ID, 5*time.Minute, cluster.Now())
	first := r.docs("t_findings")
	riskIndex := datamodel.IndexName("t", datamodel.RiskModel, slot.Format("2006.01.02"))
	riskDocs := r.docs(riskIndex)
	if len(first) != 2 || len(riskDocs) != 4 {
		t.Fatalf("%d findings, %d risk events", len(first), len(riskDocs))
	}
	ids := map[string]bool{}
	for _, f := range first {
		var got findings.Finding
		_ = json.Unmarshal(f.Source, &got)
		if !got.Created.Equal(slot) || got.Slot == nil || !got.Slot.Equal(slot) || !strings.HasPrefix(f.ID, slot.Format("20060102-150405")) {
			t.Errorf("finding %s: created %v, slot %v, want %v", f.ID, got.Created, got.Slot, slot)
		}
		ids[f.ID] = true
	}

	r.rewind(d.ID, 5*time.Minute)
	b := r.scheduler(&clock{t: cluster.Now().Add(5 * time.Second)}, cluster, 2, "node-b")
	b.RunDue(context.Background())
	again := r.docs("t_findings")
	if len(again) != 2 || len(r.docs(riskIndex)) != 4 {
		t.Fatalf("after the second run: %d findings, %d risk events", len(again), len(r.docs(riskIndex)))
	}
	for _, f := range again {
		if !ids[f.ID] {
			t.Errorf("new finding %s", f.ID)
		}
	}
	st := r.detstate(d.ID)
	if st.LastDuplicates != 2 || st.LastFindings != 0 || !st.LastSlot.Equal(slot) || st.Epoch != 2 || st.Node != "node-b" {
		t.Errorf("state %+v", st)
	}
}

// TestRerunAfterMidnightWritesNoSecondRiskEvent: a slot that ended just
// before midnight, run again after it, writes its risk event into the
// same day's index, where it is already stored.
func TestRerunAfterMidnightWritesNoSecondRiskEvent(t *testing.T) {
	d := &detect.Detection{ID: "night-rule", Title: "Seen {user}", Query: "user=*", Enabled: true, Schedule: "1m", Lookback: "1m",
		Severity: "low", Throttle: detect.Throttle{Window: "1h"},
		Risk: &detect.Risk{Score: 10, Only: true, Objects: []detect.RiskObject{{Field: "user", Type: "user"}}}}
	r := newRig(t, []search.Row{{"user": "bob"}}, d)
	midnight := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	s1 := slotOf(d.ID, time.Minute, midnight.Add(-time.Nanosecond))
	cluster := &clock{t: s1.Add(-30 * time.Second)}
	a := r.scheduler(cluster, cluster, 1, "node-a")
	a.RunDue(context.Background())
	cluster.Set(s1.Add(time.Second))
	a.RunDue(context.Background())
	day1 := datamodel.IndexName("t", datamodel.RiskModel, "2026.10.13")
	day2 := datamodel.IndexName("t", datamodel.RiskModel, "2026.10.14")
	if n := len(r.docs(day1)); n != 1 {
		t.Fatalf("%d risk events before midnight", n)
	}
	r.rewind(d.ID, time.Minute)
	cluster.Set(s1.Add(time.Minute + time.Second))
	if !cluster.Now().After(midnight) {
		t.Fatal("the test means to run after midnight")
	}
	b := r.scheduler(cluster, cluster, 2, "node-b")
	b.RunDue(context.Background())
	if n, m := len(r.docs(day1)), len(r.docs(day2)); n != 1 || m != 0 {
		t.Errorf("%d risk events on the slot's day, %d on the next", n, m)
	}
	if st := r.detstate(d.ID); !st.LastSlot.After(midnight) || st.LastError != "" {
		t.Errorf("state %+v", st)
	}
}

// TestCrashBetweenThrottleAndFinding: a run that claimed its throttle but
// could not write its finding leaves the slot to run again, and the
// re-run raises the finding.
func TestCrashBetweenThrottleAndFinding(t *testing.T) {
	d := &detect.Detection{ID: "crash-rule", Title: "Seen {user}", Query: "user=*", Enabled: true, Schedule: "5m", Lookback: "5m",
		Severity: "low", Throttle: detect.Throttle{Window: "1h", Fields: []string{"user"}}}
	r := newRig(t, []search.Row{{"user": "bob"}}, d)
	cluster := &clock{t: t0}
	a := r.scheduler(cluster, cluster, 1, "node-a")
	a.RunDue(context.Background())
	before := r.detstate(d.ID).LastSlot
	cluster.Set(t0.Add(5 * time.Minute))
	r.srv.FailN(1, http.MethodPut, "t_findings/_create", http.StatusServiceUnavailable, "unavailable_shards_exception")
	a.RunDue(context.Background())
	st := r.detstate(d.ID)
	if !st.LastSlot.Equal(before) || st.ErrorKind != detect.ErrorTransient || len(r.docs("t_findings")) != 0 {
		t.Fatalf("after the failed write: %+v, %d findings", st, len(r.docs("t_findings")))
	}
	throttles := 0
	for _, doc := range r.docs(runtimeIndex) {
		if strings.HasPrefix(doc.ID, "throttle:") {
			throttles++
		}
	}
	if throttles != 1 {
		t.Fatalf("%d throttles", throttles)
	}
	a.RunDue(context.Background())
	slot := slotOf(d.ID, 5*time.Minute, cluster.Now())
	got := r.docs("t_findings")
	if len(got) != 1 || got[0].ID != detect.SlotFindingID(d.ID, detect.GroupKey(d, map[string]any{"user": "bob"}), slot) {
		t.Fatalf("findings after the re-run: %+v", got)
	}
	if st := r.detstate(d.ID); !st.LastSlot.Equal(slot) || st.LastFindings != 1 || st.LastError != "" {
		t.Errorf("state %+v", st)
	}
}

// TestOlderEpochIsRefused: a server whose lease epoch is older than the
// one in the run state, or in a throttle, writes neither.
func TestOlderEpochIsRefused(t *testing.T) {
	d := &detect.Detection{ID: "epoch-rule", Title: "Seen {user}", Query: "user=*", Enabled: true, Schedule: "5m", Lookback: "5m",
		Severity: "low", Throttle: detect.Throttle{Window: "1h", Fields: []string{"user"}}}
	r := newRig(t, []search.Row{{"user": "bob"}}, d)
	cluster := &clock{t: t0}
	old := r.scheduler(cluster, cluster, 8, "node-old")
	old.RunDue(context.Background())
	src := r.srv.Source(runtimeIndex, "detstate:"+d.ID)
	src["epoch"], src["node"] = 9, "node-new"
	r.srv.Put(runtimeIndex, "detstate:"+d.ID, src)
	cluster.Set(t0.Add(5 * time.Minute))
	old.RunDue(context.Background())
	if got := r.srv.Source(runtimeIndex, "detstate:"+d.ID); got["node"] != "node-new" || got["last_slot"] != src["last_slot"] {
		t.Errorf("an older leader wrote the run state: %v", got)
	}
	if _, ok := old.LeaderState(d.ID); ok {
		t.Error("the older leader kept its copy")
	}

	// A throttle written under epoch 9 holds back a writer with epoch 8,
	// even once its window has passed.
	r2 := newRig(t, []search.Row{{"user": "bob"}}, d)
	c2 := &clock{t: t0}
	s := r2.scheduler(c2, c2, 8, "node-old")
	s.RunDue(context.Background())
	key := detect.GroupKey(d, map[string]any{"user": "bob"})
	var thID string
	{
		// The throttle's ID is a hash of the rule and the group key; find
		// it by writing one through a run with epoch 9 first.
		c9 := &clock{t: t0.Add(5 * time.Minute)}
		n := r2.scheduler(c9, c9, 9, "node-new")
		n.RunDue(context.Background())
		for _, doc := range r2.docs(runtimeIndex) {
			if strings.HasPrefix(doc.ID, "throttle:") {
				thID = doc.ID
			}
		}
	}
	if thID == "" {
		t.Fatal("no throttle written")
	}
	th := r2.srv.Source(runtimeIndex, thID)
	if th["group_key"] != key {
		t.Fatalf("throttle %v", th)
	}
	// Epoch 8 again, after the window, with the run state its own.
	st := r2.srv.Source(runtimeIndex, "detstate:"+d.ID)
	st["epoch"] = 8
	r2.srv.Put(runtimeIndex, "detstate:"+d.ID, st)
	before := len(r2.docs("t_findings"))
	c8 := &clock{t: t0.Add(2 * time.Hour)}
	s8 := r2.scheduler(c8, c8, 8, "node-old")
	s8.CatchUp = time.Hour
	s8.RunDue(context.Background())
	if got := r2.srv.Source(runtimeIndex, thID); got["node"] != "node-new" || len(r2.docs("t_findings")) != before {
		t.Errorf("an older leader took the throttle: %v", got)
	}
}
