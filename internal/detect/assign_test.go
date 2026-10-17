package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/search"
)

func TestBucketsSpreadEvenly(t *testing.T) {
	count := make([]int, Buckets)
	for i := range 6400 {
		b := BucketOf("acme", fmt.Sprintf("rule-%d", i))
		if b < 0 || b >= Buckets || b != BucketOf("acme", fmt.Sprintf("rule-%d", i)) {
			t.Fatalf("bucket %d", b)
		}
		count[b]++
	}
	for b, n := range count {
		if n < 50 || n > 150 {
			t.Errorf("bucket %d holds %d of 6400 rules", b, n)
		}
	}
	if BucketOf("a", "bc") == BucketOf("ab", "c") && BucketOf("x", "yz") == BucketOf("xy", "z") {
		t.Error("tenant and rule are not kept apart")
	}
}

// TestRendezvousMovesOnlyTheChangedShare: a server joining takes about
// its share from the others, and one leaving gives only its own buckets
// away.
func TestRendezvousMovesOnlyTheChangedShare(t *testing.T) {
	three, four := []string{"a", "b", "c"}, []string{"a", "b", "c", "d"}
	if Rendezvous(nil, "t", 1) != "" {
		t.Error("an owner among no servers")
	}
	moved, perNode := 0, map[string]int{}
	for b := range Buckets {
		before, after := Rendezvous(three, "t", b), Rendezvous(four, "t", b)
		perNode[before]++
		if before != after {
			moved++
			if after != "d" {
				t.Errorf("bucket %d moved from %s to %s, not to the new server", b, before, after)
			}
		}
		if Rendezvous([]string{"c", "a", "b"}, "t", b) != before {
			t.Errorf("bucket %d depends on the order of the servers", b)
		}
		if gone := Rendezvous([]string{"a", "c"}, "t", b); before != "b" && gone != before {
			t.Errorf("bucket %d of %s moved when b left", b, before)
		}
	}
	if moved < Buckets/8 || moved > Buckets/2 {
		t.Errorf("%d of %d buckets moved to a fourth server", moved, Buckets)
	}
	for n, c := range perNode {
		if c < Buckets/6 {
			t.Errorf("%s owns only %d buckets", n, c)
		}
	}
}

func validAssignment(tenant string, nodes []string) *Assignment {
	a := &Assignment{Kind: kindDetAssign, Tenant: tenant, LeaseEpoch: 3, Owners: make([]BucketOwner, Buckets)}
	for b := range Buckets {
		a.Owners[b] = BucketOwner{Node: Rendezvous(nodes, tenant, b), DetEpoch: FirstEpoch(3) + 1, State: BucketRun}
	}
	return a
}

func TestDecodeAssignment(t *testing.T) {
	good := validAssignment("acme", []string{"a", "b"})
	raw, _ := json.Marshal(good)
	if got, err := DecodeAssignment(raw, "acme"); err != nil || !reflect.DeepEqual(got, good) {
		t.Fatalf("%+v, %v", got, err)
	}
	if _, err := DecodeAssignment(raw, "other"); err == nil {
		t.Error("an assignment for another tenant was taken")
	}
	bad := map[string]func(a *Assignment){
		"kind":         func(a *Assignment) { a.Kind = "detstate" },
		"short":        func(a *Assignment) { a.Owners = a.Owners[:10] },
		"no epoch":     func(a *Assignment) { a.Owners[3].DetEpoch = 0 },
		"state":        func(a *Assignment) { a.Owners[3].State = "maybe" },
		"move nowhere": func(a *Assignment) { a.Owners[3].State = BucketMoving },
		"move to self": func(a *Assignment) { a.Owners[3].State, a.Owners[3].To = BucketMoving, a.Owners[3].Node },
		"run with to":  func(a *Assignment) { a.Owners[3].To = "x" },
		"ownerless":    func(a *Assignment) { a.Owners[3].Node = "" },
		"long node":    func(a *Assignment) { a.Owners[3].Node = string(make([]byte, maxNodeID+1)) },
		"newline node": func(a *Assignment) { a.Owners[3].Node = "a\nb" },
	}
	for name, change := range bad {
		a := validAssignment("acme", []string{"a", "b"})
		change(a)
		raw, _ := json.Marshal(a)
		if _, err := DecodeAssignment(raw, "acme"); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	empty := validAssignment("acme", nil)
	empty.Owners[0] = BucketOwner{}
	for b := range empty.Owners {
		empty.Owners[b] = BucketOwner{}
	}
	raw, _ = json.Marshal(empty)
	if a, err := DecodeAssignment(raw, "acme"); err != nil || len(a.RunsOn("a")) != 0 {
		t.Errorf("an assignment with no owners: %v", err)
	}
	moving := validAssignment("acme", []string{"a"})
	moving.Owners[5] = BucketOwner{Node: "a", DetEpoch: 9, State: BucketMoving, To: "b"}
	if runs := moving.RunsOn("a"); len(runs) != Buckets-1 || runs[0] != FirstEpoch(3)+1 {
		t.Errorf("runs on a: %d buckets", len(runs))
	}
	if _, ok := moving.RunsOn("a")[5]; ok {
		t.Error("a bucket being moved away still runs")
	}
}

func FuzzAssignment(f *testing.F) {
	raw, _ := json.Marshal(validAssignment("acme", []string{"a", "b"}))
	f.Add(raw)
	f.Add([]byte(`{"kind":"detassign","tenant":"acme","owners":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, err := DecodeAssignment(raw, "acme")
		if err != nil {
			return
		}
		again, _ := json.Marshal(a)
		b, err := DecodeAssignment(again, "acme")
		if err != nil || !reflect.DeepEqual(a, b) {
			t.Fatalf("a checked assignment does not read back: %v", err)
		}
		for _, ep := range a.RunsOn("a") {
			if ep <= 0 {
				t.Fatal("a bucket runs without a detection epoch")
			}
		}
	})
}

// spreadCluster is servers sharing one run store and findings store,
// each with its own view of the assignment.
type spreadCluster struct {
	mu    sync.Mutex
	views map[string]*Assignment
}

func (c *spreadCluster) set(node string, a *Assignment) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := *a
	cp.Owners = append([]BucketOwner(nil), a.Owners...)
	c.views[node] = &cp
}

func (c *spreadCluster) owned(node string) func() (map[int]int64, bool) {
	return func() (map[int]int64, bool) {
		c.mu.Lock()
		defer c.mu.Unlock()
		a := c.views[node]
		if a == nil {
			return nil, false
		}
		return a.RunsOn(node), true
	}
}

// TestSpreadRunsEachRuleOnce: two servers split the rules by bucket; each
// rule runs on its bucket's owner only, its state fenced with the
// bucket's epoch. When a bucket moves, the new owner catches up from the
// watermark, and the old owner, still reading the old assignment, can
// write neither the state nor a second finding.
func TestSpreadRunsEachRuleOnce(t *testing.T) {
	const tenant = "acme"
	var rules []*Detection
	rows := map[string][]search.Row{}
	for i := range 24 {
		id := fmt.Sprintf("spread-%d", i)
		q := fmt.Sprintf("user=s%d", i)
		rules = append(rules, &Detection{ID: id, Title: id, Query: q, Enabled: true, Schedule: "5m", Lookback: "5m"})
		rows[q] = []search.Row{{"user": fmt.Sprintf("s%d", i)}}
	}
	lib := OnlyRules(t, rules...)
	run := &recRunner{rows: rows}
	clock := &fakeClock{t: t0}
	rs := NewMemoryRunStore()
	fs := findings.NewMemory()
	c := &spreadCluster{views: map[string]*Assignment{}}
	a := validAssignment(tenant, []string{"a", "b"})
	for b := range a.Owners {
		if a.Owners[b].Node == "b" {
			a.Owners[b].DetEpoch = FirstEpoch(3) + 2
		}
	}
	server := func(node string) *Scheduler {
		s := newTestScheduler(lib, run, clock)
		s.Runtime, s.Findings, s.NodeID, s.Tenant, s.Owned = rs, fs, node, tenant, c.owned(node)
		c.set(node, a)
		return s
	}
	sa, sb := server("a"), server("b")
	ctx := context.Background()
	sa.RunDue(ctx)
	sb.RunDue(ctx)
	owner := func(id string) BucketOwner { return a.Owners[BucketOf(tenant, id)] }
	byNode := map[string]int{}
	for _, d := range rules {
		st := storedState(t, sa, d.ID)
		o := owner(d.ID)
		if st.Node != o.Node || st.DetEpoch != o.DetEpoch {
			t.Errorf("%s: written by %s at %d, owner %s at %d", d.ID, st.Node, st.DetEpoch, o.Node, o.DetEpoch)
		}
		byNode[st.Node]++
	}
	if byNode["a"] == 0 || byNode["b"] == 0 {
		t.Fatalf("the rules did not spread: %v", byNode)
	}

	// Move the bucket of one of a's rules to b, with a fresh epoch. b sees
	// the new assignment; a does not yet.
	var moved *Detection
	for _, d := range rules {
		if owner(d.ID).Node == "a" {
			moved = d
			break
		}
	}
	mb := BucketOf(tenant, moved.ID)
	next := *a
	next.Owners = append([]BucketOwner(nil), a.Owners...)
	next.Owners[mb] = BucketOwner{Node: "b", DetEpoch: FirstEpoch(3) + 3, State: BucketRun}
	c.set("b", &next)
	_, before, _ := fs.Search(ctx, findings.Filter{})
	clock.Add(5 * time.Minute)
	sb.RunDue(ctx)
	st := storedState(t, sb, moved.ID)
	if st.Node != "b" || st.DetEpoch != FirstEpoch(3)+3 {
		t.Fatalf("after the move: %+v", st)
	}
	searched := func() int {
		run.mu.Lock()
		defer run.mu.Unlock()
		n := 0
		for _, c := range run.calls {
			if strings.Contains(c.key, moved.Query) {
				n++
			}
		}
		return n
	}
	n := searched()
	sa.RunDue(ctx)
	if searched() == n {
		t.Fatal("the old owner did not try the moved rule; the test proves nothing")
	}
	if st2 := storedState(t, sa, moved.ID); st2.Node != "b" || st2.DetEpoch != st.DetEpoch || !st2.LastSlot.Equal(st.LastSlot) {
		t.Errorf("the old owner wrote over the new one: %+v", st2)
	}
	_, after, _ := fs.Search(ctx, findings.Filter{})
	if after-before != len(rules) {
		t.Errorf("%d findings for %d rules in one slot", after-before, len(rules))
		for _, d := range rules {
			st := storedState(t, sa, d.ID)
			t.Logf("%s owner %s: node %s last %s next %s run %s res %d err %q findings %d dup %d", d.ID, owner(d.ID).Node, st.Node, st.LastSlot.Format("15:04:05"), st.NextSlot.Format("15:04:05"), st.LastRun.Format("15:04:05"), st.LastResults, st.LastError, st.LastFindings, st.LastDuplicates)
		}
	}

	// a's in-flight copy of the moved rule cannot be written either, once
	// a reads the new assignment.
	c.set("a", &next)
	e, ok := sa.entry(moved.ID)
	if ok {
		e.doc.LastError = "stale"
		if _, err := sa.writeState(ctx, e, sa.gen()); !errors.Is(err, errStaleEpoch) {
			t.Errorf("a's write of a bucket it no longer runs: %v", err)
		}
	}
	if _, ok := sa.fenceEpoch(moved.ID); ok {
		t.Error("a still has a detection epoch for the moved rule")
	}

	// With no assignment read, a runs nothing.
	c.mu.Lock()
	delete(c.views, "a")
	c.mu.Unlock()
	calls := len(run.calls)
	clock.Add(5 * time.Minute)
	sa.RunDue(ctx)
	if len(run.calls) != calls {
		t.Errorf("a ran %d searches without an assignment", len(run.calls)-calls)
	}
}

// TestSpreadSharedPool: two tenants' spread schedulers on one server take
// their workers from one pool, and every rule of both runs.
func TestSpreadSharedPool(t *testing.T) {
	var rules []*Detection
	rows := map[string][]search.Row{}
	for i := range 6 {
		id := fmt.Sprintf("pool-%d", i)
		q := fmt.Sprintf("user=p%d", i)
		rules = append(rules, &Detection{ID: id, Title: id, Query: q, Enabled: true, Schedule: "5m", Lookback: "5m"})
		rows[q] = []search.Row{{"user": fmt.Sprintf("p%d", i)}}
	}
	lib := OnlyRules(t, rules...)
	run := &recRunner{rows: rows}
	clock := &fakeClock{t: t0}
	pool := NewPool(1)
	var scheds []*Scheduler
	for _, tenant := range []string{"acme", "beta"} {
		runs := validAssignment(tenant, []string{"a"}).RunsOn("a")
		s := newTestScheduler(lib, run, clock)
		s.Runtime, s.NodeID, s.Tenant, s.Pool = NewMemoryRunStore(), "a", tenant, pool
		s.Owned = func() (map[int]int64, bool) { return runs, true }
		scheds = append(scheds, s)
	}
	ctx := context.Background()
	for range 2 {
		var wg sync.WaitGroup
		for _, s := range scheds {
			wg.Go(func() { s.RunDue(ctx) })
		}
		wg.Wait()
		clock.Add(5 * time.Minute)
	}
	for _, s := range scheds {
		for _, d := range rules {
			if st := storedState(t, s, d.ID); st.LastRun.IsZero() {
				t.Errorf("%s: %s did not run", s.Tenant, d.ID)
			}
		}
	}
	if st := pool.Stats(); st.Busy != 0 || st.Waiting != 0 {
		t.Errorf("pool left %+v", st)
	}
}

// TestSpreadStatusShowsOtherServersRuns: a spread scheduler's status shows
// the runs other servers made of their buckets' rules, not its copy of
// them read when its own buckets last changed.
func TestSpreadStatusShowsOtherServersRuns(t *testing.T) {
	const tenant = "acme"
	var rules []*Detection
	used := map[int]bool{}
	for i := range 24 {
		id := fmt.Sprintf("spread-%d", i)
		rules = append(rules, &Detection{ID: id, Title: id, Query: fmt.Sprintf("user=s%d", i), Enabled: true, Schedule: "5m", Lookback: "5m"})
		used[BucketOf(tenant, id)] = true
	}
	lib := OnlyRules(t, rules...)
	run := &recRunner{rows: map[string][]search.Row{}}
	clock := &fakeClock{t: t0}
	rs := NewMemoryRunStore()
	fs := findings.NewMemory()
	c := &spreadCluster{views: map[string]*Assignment{}}
	a := validAssignment(tenant, []string{"a", "b"})
	server := func(node string) *Scheduler {
		s := newTestScheduler(lib, run, clock)
		s.Runtime, s.Findings, s.NodeID, s.Tenant, s.Owned = rs, fs, node, tenant, c.owned(node)
		c.set(node, a)
		return s
	}
	sa, sb := server("a"), server("b")
	ctx := context.Background()
	sa.RunDue(ctx)
	sb.RunDue(ctx)

	// a is given an empty bucket of b's, so it reads every rule's run
	// state again, b's rules' too.
	free := -1
	for b := range Buckets {
		if !used[b] && a.Owners[b].Node == "b" {
			free = b
			break
		}
	}
	if free < 0 {
		t.Fatal("no bucket of b's without rules")
	}
	more := *a
	more.Owners = append([]BucketOwner(nil), a.Owners...)
	more.Owners[free] = BucketOwner{Node: "a", DetEpoch: FirstEpoch(3) + 5, State: BucketRun}
	c.set("a", &more)
	sa.RunDue(ctx)

	// b runs its rules' next slot; a's status shows that run.
	clock.Add(5 * time.Minute)
	sb.RunDue(ctx)
	status, err := sa.StatusCtx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, d := range rules {
		if a.Owners[BucketOf(tenant, d.ID)].Node != "b" {
			continue
		}
		checked++
		want := storedState(t, sb, d.ID)
		if got := status[d.ID]; !got.LastSlot.Equal(want.LastSlot) || got.Node != "b" {
			t.Errorf("%s: a's status says last slot %s by %q, b ran %s", d.ID, got.LastSlot.Format("15:04"), got.Node, want.LastSlot.Format("15:04"))
		}
	}
	if checked == 0 {
		t.Fatal("b runs none of the rules; the test proves nothing")
	}
}
