package detect

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	clock   time.Duration
}

// advance moves the test Assigner's monotonic clock on.
func (ta *testAssigner) advance(d time.Duration) {
	ta.mu.Lock()
	ta.clock += d
	ta.mu.Unlock()
}

// setServer changes server id as change says.
func (ta *testAssigner) setServer(id string, change func(s *SpreadServer)) {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	for i := range ta.servers {
		if ta.servers[i].ID == id {
			change(&ta.servers[i])
		}
	}
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
		Now:  func() time.Time { return t0 },
		Mono: func() time.Duration { ta.mu.Lock(); defer ta.mu.Unlock(); return ta.clock },
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

	// c joins: nothing moves before it has been able to run buckets for
	// the join delay.
	ta.mu.Lock()
	ta.servers = append(ta.servers, server("c"))
	ta.mu.Unlock()
	step := func() *Assignment {
		t.Helper()
		if err := ta.Step(ctx); err != nil {
			t.Fatal(err)
		}
		return readAssignment(t, rs)
	}
	if got := step(); !slicesEqual(got.Owners, first.Owners) {
		t.Fatal("buckets moved to a server that just joined")
	}
	ta.advance(DefaultJoinDelay)

	// Then c's buckets are handed over: marked moving, under the same
	// epoch, their owners still holding them.
	toC := map[int]bool{}
	moving := step()
	for b, o := range moving.Owners {
		want := Rendezvous([]string{"a", "b", "c"}, "acme", b)
		was := first.Owners[b]
		switch {
		case want == was.Node:
			if o != was {
				t.Errorf("bucket %d changed without moving: %+v", b, o)
			}
		case o.Node != was.Node || o.DetEpoch != was.DetEpoch || o.State != BucketMoving || o.To != "c":
			t.Errorf("bucket %d for c: %+v", b, o)
		default:
			toC[b] = true
		}
	}
	if len(toC) == 0 {
		t.Fatal("no bucket moves to c")
	}

	// a releases its buckets; b has a run in flight. Only a's move on,
	// each with a bigger epoch.
	var top int64
	for _, o := range first.Owners {
		top = max(top, o.DetEpoch)
	}
	ta.setServer("a", func(s *SpreadServer) {
		s.Released = map[int]int64{}
		for b := range toC {
			if moving.Owners[b].Node == "a" {
				s.Released[b] = moving.Owners[b].DetEpoch
			}
		}
	})
	third := step()
	for b := range toC {
		o, from := third.Owners[b], moving.Owners[b].Node
		switch {
		case from == "a" && (o.Node != "c" || o.State != BucketRun || o.DetEpoch <= top):
			t.Errorf("bucket %d released by a: %+v", b, o)
		case from == "b" && o != moving.Owners[b]:
			t.Errorf("bucket %d moved before b released it: %+v", b, o)
		}
	}

	// b never releases: its buckets move once the move timeout passed.
	ta.advance(DefaultMoveTimeout)
	last := step()
	for b, o := range last.Owners {
		if want := Rendezvous([]string{"a", "b", "c"}, "acme", b); o.Node != want || o.State != BucketRun {
			t.Errorf("bucket %d after the timeout: %+v, not %s", b, o, want)
		}
	}
}

// TestAssignerCrashMovesAtOnce: a bucket whose owner is gone moves at
// once, without the handover or the join delay.
func TestAssignerCrashMovesAtOnce(t *testing.T) {
	ctx := context.Background()
	rs := NewMemoryRunStore()
	ta := newTestAssigner(rs)
	ta.servers = []SpreadServer{server("a"), server("b")}
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	ta.setServer("b", func(s *SpreadServer) { s.Live = false })
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := readAssignment(t, rs); len(got.Holds("b")) != 0 || len(got.RunsOn("a")) != Buckets {
		t.Errorf("b still holds %d buckets", len(got.Holds("b")))
	}
}

// TestAssignerMoveCancelled: a bucket whose move is no longer wanted
// runs on with its owner, under the same epoch.
func TestAssignerMoveCancelled(t *testing.T) {
	ctx := context.Background()
	rs := NewMemoryRunStore()
	ta := newTestAssigner(rs)
	ta.servers = []SpreadServer{server("a"), server("b")}
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	before := readAssignment(t, rs)
	ta.setServer("b", func(s *SpreadServer) { s.Eligible = false })
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := readAssignment(t, rs); len(got.Holds("b")) == 0 || len(got.RunsOn("b")) != 0 {
		t.Fatal("b's buckets are not being handed over")
	}
	ta.setServer("b", func(s *SpreadServer) { s.Eligible = true })
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	after := readAssignment(t, rs)
	stale := map[int]int64{}
	for b, o := range after.Owners {
		was := before.Owners[b]
		switch {
		case o.Node != was.Node || o.State != BucketRun:
			t.Fatalf("bucket %d: a cancelled move gave it to %q (%s), not back to %q", b, o.Node, o.State, was.Node)
		case was.Node == "b" && o.DetEpoch <= was.DetEpoch:
			t.Fatalf("bucket %d: a cancelled move kept epoch %d", b, o.DetEpoch)
		case was.Node == "a" && o.DetEpoch != was.DetEpoch:
			t.Fatalf("bucket %d: a's bucket changed epoch", b)
		case was.Node == "b":
			stale[b] = was.DetEpoch
		}
	}
	// b's heartbeat still says it released the old epochs: a new move
	// waits for a release of the new ones.
	ta.setServer("b", func(s *SpreadServer) { s.Eligible, s.Released = false, stale })
	for range 2 {
		if err := ta.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := readAssignment(t, rs); len(got.RunsOn("a")) != Buckets-len(got.Holds("b")) || len(got.Holds("b")) != len(stale) {
		t.Error("a stale release ended the move")
	}
}

func slicesEqual(a, b []BucketOwner) bool { return slices.Equal(a, b) }

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

// TestFollowerMoving: a bucket being handed over is still held (its runs
// in flight may write) but starts no new slot, and is released once no
// run of it is in flight.
func TestFollowerMoving(t *testing.T) {
	ctx := context.Background()
	rs := NewMemoryRunStore()
	a := validAssignment("acme", []string{"b"})
	a.Owners[7] = BucketOwner{Node: "b", DetEpoch: 42, State: BucketMoving, To: "c"}
	if _, err := rs.Create(ctx, "rt", AssignmentID("acme"), a, true); err != nil {
		t.Fatal(err)
	}
	f := &Follower{Tenant: "acme", Self: "b", Runtime: rs, RuntimeIndex: "rt"}
	if err := f.Read(ctx); err != nil {
		t.Fatal(err)
	}
	if m, ok := f.Owned(); !ok || m[7] != 42 || len(m) != Buckets {
		t.Errorf("held: %d buckets, bucket 7 at %d", len(m), m[7])
	}
	if !f.Moving(7) || f.Moving(8) {
		t.Error("moving buckets")
	}
	busy := true
	if r := f.Released(func(int) bool { return busy }); len(r) != 0 {
		t.Errorf("released with a run in flight: %v", r)
	}
	busy = false
	if r := f.Released(func(int) bool { return busy }); len(r) != 1 || r[7] != 42 {
		t.Errorf("released: %v", r)
	}

	// The scheduler starts no slot of it.
	s := &Scheduler{Tenant: "acme", Owned: f.Owned, Moving: f.Moving}
	s.gen()
	var in7, in8 string
	for i := 0; in7 == "" || in8 == ""; i++ {
		id := fmt.Sprintf("r%d", i)
		switch BucketOf("acme", id) {
		case 7:
			in7 = id
		case 8:
			in8 = id
		}
	}
	if s.startsRule(in7) || !s.startsRule(in8) {
		t.Error("a moving bucket's rule starts, or another's does not")
	}
	if _, mine := s.ownsRule(in7); !mine {
		t.Error("a moving bucket's run in flight cannot write")
	}
	s.setFlags(in7, runFlags{running: true})
	if !s.BucketBusy(7) || s.BucketBusy(8) {
		t.Error("busy buckets")
	}
}

// TestAssignerSearchBudget: the assignment carries the search budget
// while the detections are spread, and each follower reads its share.
func TestAssignerSearchBudget(t *testing.T) {
	ctx := context.Background()
	rs := NewMemoryRunStore()
	ta := newTestAssigner(rs)
	budget := 12
	ta.Budget = func(context.Context) int { ta.mu.Lock(); defer ta.mu.Unlock(); return budget }
	ta.servers = []SpreadServer{server("a"), server("b")}
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := readAssignment(t, rs).SearchBudget; got != 12 {
		t.Fatalf("budget %d, want 12", got)
	}
	ta.mu.Lock()
	budget = MaxSearchBudget + 1
	ta.mu.Unlock()
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := readAssignment(t, rs).SearchBudget; got != MaxSearchBudget {
		t.Fatalf("budget %d, want it capped at %d", got, MaxSearchBudget)
	}
	total := 0
	for _, id := range []string{"a", "b"} {
		f := &Follower{Tenant: "acme", Self: id, Runtime: rs, RuntimeIndex: "rt"}
		if err := f.Read(ctx); err != nil {
			t.Fatal(err)
		}
		s, ok := f.Share()
		if !ok || s.Assigned != Buckets || s.Budget != MaxSearchBudget || s.Mine == 0 {
			t.Fatalf("%s's share %+v", id, s)
		}
		total += s.Mine
	}
	if total != Buckets {
		t.Errorf("shares add up to %d buckets", total)
	}
	ta.on = false
	if err := ta.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got := readAssignment(t, rs).SearchBudget; got != 0 {
		t.Errorf("budget %d written while nothing is spread", got)
	}
	bad := readAssignment(t, rs)
	bad.SearchBudget = -1
	if err := bad.Check("acme"); err == nil {
		t.Error("a negative budget passed the checks")
	}
}
