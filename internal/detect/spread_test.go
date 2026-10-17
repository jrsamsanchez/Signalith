package detect

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

func ms(v int64) *int64 { return &v }

// testAssigner is an Assigner over a memory run store, its servers
// changeable between steps.
type testAssigner struct {
	*Assigner
	mu      sync.Mutex
	servers []SpreadServer
	on      bool
	lease   int64
}

func newTestAssigner(rs RunStore) *testAssigner {
	ta := &testAssigner{on: true, lease: 3}
	ta.Assigner = &Assigner{
		Tenant: "acme", Runtime: rs, RuntimeIndex: "rt", Self: "a",
		Lease: func() int64 { ta.mu.Lock(); defer ta.mu.Unlock(); return ta.lease },
		On:    func() bool { ta.mu.Lock(); defer ta.mu.Unlock(); return ta.on },
		Servers: func() []SpreadServer {
			ta.mu.Lock()
			defer ta.mu.Unlock()
			return append([]SpreadServer(nil), ta.servers...)
		},
		Now: func() time.Time { return t0 },
	}
	return ta
}

func server(id string) SpreadServer {
	return SpreadServer{ID: id, Spread: true, Eligible: true, Live: true, Fingerprint: "f1", ClockOffsetMS: ms(0)}
}

func readAssignment(t *testing.T, rs RunStore) *Assignment {
	t.Helper()
	raw, _, found, err := rs.Get(context.Background(), "rt", AssignmentID("acme"))
	if err != nil || !found {
		t.Fatalf("no assignment: %v", err)
	}
	a, err := DecodeAssignment(raw, "acme")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAssignerSpreadsAndMoves(t *testing.T) {
	ctx := context.Background()
	rs := NewMemoryRunStore()
	ta := newTestAssigner(rs)
	ta.servers = []SpreadServer{server("a"), server("b")}
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if ta.LeaderRuns() {
		t.Fatal("the leader runs rules after owners were written")
	}
	first := readAssignment(t, rs)
	seen := map[int64]bool{}
	for b, o := range first.Owners {
		if o.Node != Rendezvous([]string{"a", "b"}, "acme", b) || o.State != BucketRun {
			t.Fatalf("bucket %d: %+v", b, o)
		}
		if o.DetEpoch < FirstEpoch(3) || seen[o.DetEpoch] {
			t.Fatalf("bucket %d epoch %d", b, o.DetEpoch)
		}
		seen[o.DetEpoch] = true
	}
	if first.LeaseEpoch != 3 {
		t.Errorf("lease %d", first.LeaseEpoch)
	}

	// Nothing changed: nothing is written.
	_, v1, _, _ := rs.Get(ctx, "rt", AssignmentID("acme"))
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if _, v2, _, _ := rs.Get(ctx, "rt", AssignmentID("acme")); v2 != v1 {
		t.Error("an unchanged assignment was written again")
	}

	// c joins: only the buckets moving to c change, each with a bigger epoch.
	ta.mu.Lock()
	ta.servers = append(ta.servers, server("c"))
	ta.mu.Unlock()
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	var top int64
	for _, o := range first.Owners {
		top = max(top, o.DetEpoch)
	}
	second := readAssignment(t, rs)
	for b, o := range second.Owners {
		switch want := Rendezvous([]string{"a", "b", "c"}, "acme", b); {
		case o.Node != want:
			t.Errorf("bucket %d owned by %s, not %s", b, o.Node, want)
		case o.Node == first.Owners[b].Node && o != first.Owners[b]:
			t.Errorf("bucket %d changed without moving", b)
		case o.Node != first.Owners[b].Node && o.DetEpoch <= top:
			t.Errorf("bucket %d moved with epoch %d, not above %d", b, o.DetEpoch, top)
		}
	}
}

func TestAssignerLeavesOut(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(s *SpreadServer){
		"dead":          func(s *SpreadServer) { s.Live = false },
		"not eligible":  func(s *SpreadServer) { s.Eligible = false },
		"other files":   func(s *SpreadServer) { s.Fingerprint = "f2" },
		"no tenant":     func(s *SpreadServer) { s.Fingerprint = "" },
		"clock unknown": func(s *SpreadServer) { s.ClockOffsetMS = nil },
		"clock ahead":   func(s *SpreadServer) { s.ClockOffsetMS = ms(2500) },
		"clock behind":  func(s *SpreadServer) { s.ClockOffsetMS = ms(-2500) },
	}
	for name, change := range cases {
		rs := NewMemoryRunStore()
		ta := newTestAssigner(rs)
		b := server("b")
		change(&b)
		ta.servers = []SpreadServer{server("a"), b}
		if err := ta.Step(ctx); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if runs := readAssignment(t, rs).RunsOn("b"); len(runs) != 0 {
			t.Errorf("%s: b given %d buckets", name, len(runs))
		}
	}
}

// TestAssignerOnlyWhenAllCan: while a live server cannot run assigned
// buckets, or spreading is off, nobody owns a bucket and the leader runs
// every rule; it starts running them again only once that was written.
func TestAssignerOnlyWhenAllCan(t *testing.T) {
	ctx := context.Background()
	rs := NewMemoryRunStore()
	ta := newTestAssigner(rs)
	resumed := 0
	ta.Resume = func() { resumed++ }
	if ta.LeaderRuns() {
		t.Fatal("the leader runs rules before the assignment was read")
	}
	ta.servers = []SpreadServer{server("a"), server("b")}
	if err := ta.Step(ctx); err != nil || ta.LeaderRuns() {
		t.Fatal(err)
	}
	old := server("c")
	old.Spread = false
	ta.mu.Lock()
	ta.servers = append(ta.servers, old)
	ta.mu.Unlock()
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if !ta.LeaderRuns() || resumed != 1 || len(readAssignment(t, rs).RunsOn("a")) != 0 {
		t.Error("still spread with an old server live")
	}

	ta.mu.Lock()
	ta.servers = ta.servers[:2]
	ta.on = false
	ta.mu.Unlock()
	if err := ta.Step(ctx); err != nil || !ta.LeaderRuns() || resumed != 1 {
		t.Errorf("spread when off: %v, resumed %d", err, resumed)
	}

	// A failed write of the empty assignment keeps the leader out.
	ta.mu.Lock()
	ta.on = true
	ta.mu.Unlock()
	if err := ta.Step(ctx); err != nil || ta.LeaderRuns() {
		t.Fatal(err)
	}
	ta.mu.Lock()
	ta.on = false
	ta.mu.Unlock()
	ta.Runtime = failingPut{rs}
	if err := ta.Step(ctx); err == nil || ta.LeaderRuns() {
		t.Errorf("the leader runs rules again though the owners were not cleared: %v", err)
	}
}

type failingPut struct{ RunStore }

func (failingPut) PutIf(context.Context, string, string, any, store.Version, bool) (store.Version, error) {
	return store.Version{}, errors.New("down")
}

func TestAssignerRefusesNewerHolder(t *testing.T) {
	ctx := context.Background()
	rs := NewMemoryRunStore()
	ta := newTestAssigner(rs)
	ta.servers = []SpreadServer{server("a"), server("b")}
	ta.lease = 5
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	stale := newTestAssigner(rs)
	stale.servers = []SpreadServer{server("a")}
	if err := stale.Step(ctx); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("an older holder wrote the assignment: %v", err)
	}
	if len(readAssignment(t, rs).RunsOn("b")) == 0 {
		t.Error("the newer assignment was overwritten")
	}
}

func TestFollower(t *testing.T) {
	ctx := context.Background()
	rs := NewMemoryRunStore()
	var now time.Duration
	f := &Follower{Tenant: "acme", Self: "b", Runtime: rs, RuntimeIndex: "rt", Mono: func() time.Duration { return now }}
	if _, ok := f.Owned(); ok {
		t.Error("owned before any read")
	}
	if err := f.Read(ctx); err != nil {
		t.Fatal(err)
	}
	if m, ok := f.Owned(); !ok || len(m) != 0 {
		t.Errorf("no assignment: %v %v", m, ok)
	}
	a := validAssignment("acme", []string{"a", "b"})
	if _, err := rs.Create(ctx, "rt", AssignmentID("acme"), a, true); err != nil {
		t.Fatal(err)
	}
	if err := f.Read(ctx); err != nil {
		t.Fatal(err)
	}
	if m, ok := f.Owned(); !ok || len(m) != len(a.RunsOn("b")) || len(m) == 0 {
		t.Errorf("owned %d, want %d", len(m), len(a.RunsOn("b")))
	}
	now += DefaultFollowMaxAge
	if _, ok := f.Owned(); ok {
		t.Error("an old read still runs buckets")
	}

	// A document failing its checks runs nothing.
	bad := map[string]any{"kind": kindDetAssign, "tenant": "acme", "owners": []BucketOwner{{Node: "b", DetEpoch: 1, State: BucketRun}}}
	_, ver, _, _ := rs.Get(ctx, "rt", AssignmentID("acme"))
	if _, err := rs.PutIf(ctx, "rt", AssignmentID("acme"), bad, ver, true); err != nil {
		t.Fatal(err)
	}
	if err := f.Read(ctx); err == nil {
		t.Error("a bad assignment was taken")
	}
	if m, ok := f.Owned(); !ok || len(m) != 0 {
		t.Errorf("a bad assignment runs %d buckets", len(m))
	}
}

// TestAssignerUnspreadNoDocument: with spreading off and no assignment,
// nothing is written and the leader runs the rules after one read.
func TestAssignerUnspreadNoDocument(t *testing.T) {
	ctx := context.Background()
	rs := NewMemoryRunStore()
	ta := newTestAssigner(rs)
	ta.on = false
	ta.servers = []SpreadServer{server("a"), server("b")}
	if err := ta.Step(ctx); err != nil || !ta.LeaderRuns() {
		t.Fatalf("%v, leader runs %v", err, ta.LeaderRuns())
	}
	if _, _, found, _ := rs.Get(ctx, "rt", AssignmentID("acme")); found {
		t.Error("an assignment was written though nothing is spread")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	ta.Run(cctx, time.Hour)
	if ta.LeaderRuns() {
		t.Error("the leader still runs rules after the assigner stopped")
	}
}

// TestLostBucket: a refused write stops every rule of its bucket on this
// server until the assignment gives the bucket a new epoch.
func TestLostBucket(t *testing.T) {
	ep := int64(5)
	s := &Scheduler{Tenant: "acme", Owned: func() (map[int]int64, bool) {
		return map[int]int64{BucketOf("acme", "r1"): ep}, true
	}}
	s.gen()
	if _, mine := s.ownsRule("r1"); !mine {
		t.Fatal("not owned")
	}
	s.dropStale("r1")
	if _, mine := s.ownsRule("r1"); mine {
		t.Error("a lost bucket still runs")
	}
	s.gen()
	if _, mine := s.ownsRule("r1"); mine {
		t.Error("a lost bucket runs again under the same epoch")
	}
	ep = 7
	s.gen()
	if got, mine := s.ownsRule("r1"); !mine || got != 7 {
		t.Error("the bucket did not run again under its new epoch")
	}
}
