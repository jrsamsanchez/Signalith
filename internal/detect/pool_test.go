package detect

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

type testPool struct {
	*Pool
	mu    sync.Mutex
	clock time.Duration
}

func newTestPool(size int) *testPool {
	tp := &testPool{Pool: NewPool(size)}
	tp.Mono = func() time.Duration { tp.mu.Lock(); defer tp.mu.Unlock(); return tp.clock }
	return tp
}

func (tp *testPool) advance(d time.Duration) {
	tp.mu.Lock()
	tp.clock += d
	tp.mu.Unlock()
}

// take acquires a worker that must be free now.
func (tp *testPool) take(t *testing.T, tenant string, current bool) func(time.Duration, error) {
	t.Helper()
	got := make(chan func(time.Duration, error), 1)
	go func() {
		done, _ := tp.Acquire(context.Background(), tenant, current)
		got <- done
	}()
	select {
	case done := <-got:
		return done
	case <-time.After(5 * time.Second):
		t.Fatalf("no free worker for %s", tenant)
		return nil
	}
}

type granted struct {
	name string
	done func(time.Duration, error)
}

// wait queues a run that waits for a worker, and sends it on got once it
// has one.
func (tp *testPool) wait(t *testing.T, ctx context.Context, name, tenant string, current bool, got chan<- granted) {
	t.Helper()
	tp.Pool.mu.Lock()
	n := len(tp.waiting)
	tp.Pool.mu.Unlock()
	go func() {
		done, err := tp.Acquire(ctx, tenant, current)
		if err == nil {
			got <- granted{name, done}
		}
	}()
	for {
		tp.Pool.mu.Lock()
		m := len(tp.waiting)
		tp.Pool.mu.Unlock()
		if m > n {
			return
		}
		runtime.Gosched()
	}
}

func next(t *testing.T, got <-chan granted) granted {
	t.Helper()
	select {
	case g := <-got:
		return g
	case <-time.After(5 * time.Second):
		t.Fatal("no run got a worker")
		return granted{}
	}
}

// TestPoolTakesTurns: free workers go to tenants in turn, and while
// another tenant waits no tenant holds more than half.
func TestPoolTakesTurns(t *testing.T) {
	ctx := context.Background()
	tp := newTestPool(4)
	var a []func(time.Duration, error)
	for range 4 {
		a = append(a, tp.take(t, "a", true))
	}
	got := make(chan granted, 4)
	tp.wait(t, ctx, "a1", "a", true, got)
	tp.wait(t, ctx, "b1", "b", true, got)
	tp.wait(t, ctx, "b2", "b", true, got)
	var order []string
	for i := range 3 {
		a[i](time.Second, nil)
		order = append(order, next(t, got).name)
	}
	if fmt.Sprint(order) != "[b1 b2 a1]" {
		t.Errorf("workers went to %v, want [b1 b2 a1]", order)
	}
	if s := tp.Stats(); s.Busy != 4 || s.Waiting != 0 {
		t.Errorf("stats %+v", s)
	}
}

// TestPoolCurrentFirst: current slots go before catch-up, and catch-up
// leaves a worker free.
func TestPoolCurrentFirst(t *testing.T) {
	ctx := context.Background()
	tp := newTestPool(3)
	c1 := tp.take(t, "a", false)
	tp.take(t, "a", false)
	got := make(chan granted, 4)
	tp.wait(t, ctx, "c3", "a", false, got)
	tp.take(t, "b", true)
	tp.wait(t, ctx, "cur", "b", true, got)
	c1(time.Second, nil)
	if g := next(t, got); g.name != "cur" {
		t.Fatalf("%s got the worker before the current slot", g.name)
	}
	select {
	case g := <-got:
		t.Fatalf("%s got a worker none was free for", g.name)
	default:
	}
}

// TestPoolCancel: a run that stops waiting leaves the queue.
func TestPoolCancel(t *testing.T) {
	tp := newTestPool(1)
	done := tp.take(t, "a", true)
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan granted, 1)
	tp.wait(t, ctx, "x", "a", true, got)
	cancel()
	for tp.Stats().Waiting != 0 {
		runtime.Gosched()
	}
	done(0, nil)
	if s := tp.Stats(); s.Busy != 0 {
		t.Errorf("busy %d after the only run ended", s.Busy)
	}
}

// TestPoolBacksOff: a busy refusal halves the workers, once per burst;
// they come back one a minute, and catch-up waits meanwhile.
func TestPoolBacksOff(t *testing.T) {
	tp := newTestPool(8)
	busy := &store.Error{Status: 429, Body: "rejected_execution_exception"}
	d1, d2 := tp.take(t, "a", true), tp.take(t, "a", true)
	d1(time.Second, fmt.Errorf("search: %w", busy))
	d2(time.Second, busy)
	if s := tp.Stats(); s.Limit != 4 || !s.Backoff {
		t.Fatalf("after a burst of refusals: %+v, want 4 workers", s)
	}
	tp.advance(poolCutGap)
	tp.take(t, "a", true)(time.Second, busy)
	if s := tp.Stats(); s.Limit != 2 {
		t.Fatalf("after another refusal later: %+v, want 2", s)
	}
	// One catch-up runs at a time while backing off.
	first := tp.take(t, "a", false)
	got := make(chan granted, 1)
	tp.wait(t, context.Background(), "catch-up", "a", false, got)
	tp.advance(poolRaiseEvery)
	if s := tp.Stats(); s.Limit != 3 {
		t.Fatalf("a minute later: %+v, want 3", s)
	}
	tp.take(t, "a", true)(time.Second, nil)
	select {
	case <-got:
		t.Fatal("a second catch-up ran while backing off")
	default:
	}
	first(time.Second, nil)
	tp.advance(5 * poolRaiseEvery)
	if s := tp.Stats(); s.Limit != 8 || s.Backoff {
		t.Fatalf("after backing off: %+v", s)
	}
	tp.take(t, "a", true)(time.Second, nil)
	next(t, got)
}

// TestPoolSlowdown: runs taking twice as long as before halve the pool,
// once for one slowdown.
func TestPoolSlowdown(t *testing.T) {
	tp := newTestPool(8)
	run := func(took time.Duration) { tp.take(t, "a", true)(took, nil) }
	for range 20 {
		run(100 * time.Millisecond)
	}
	tp.advance(poolRecent + time.Minute)
	for range 20 {
		run(150 * time.Millisecond)
	}
	tp.advance(poolCutGap)
	run(150 * time.Millisecond)
	if s := tp.Stats(); s.Limit != 8 {
		t.Fatalf("halved for runs 1.5 times as long: %+v", s)
	}
	for range 20 {
		run(400 * time.Millisecond)
	}
	tp.advance(poolCutGap)
	run(400 * time.Millisecond)
	if s := tp.Stats(); s.Limit != 4 {
		t.Fatalf("not halved for runs 4 times as long: %+v", s)
	}
	for range 20 {
		run(400 * time.Millisecond)
	}
	tp.advance(poolCutGap)
	run(400 * time.Millisecond)
	if s := tp.Stats(); s.Limit != 4 {
		t.Fatalf("halved again for the same slowdown: %+v", s)
	}
}

func TestPoolNotOverloaded(t *testing.T) {
	for _, err := range []error{nil, errors.New("bad query"), &store.Error{Status: 400, Body: "parse"}} {
		if overloaded(err) {
			t.Errorf("%v counted as overload", err)
		}
	}
}

func TestPoolSize(t *testing.T) {
	cases := []struct {
		shares []SpreadShare
		want   int
	}{
		{nil, DefaultPoolSize},
		{[]SpreadShare{{Mine: 32, Assigned: 64}}, DefaultPoolSize},
		{[]SpreadShare{{Mine: 32, Assigned: 64, Budget: 12}}, 6},
		{[]SpreadShare{{Mine: 21, Assigned: 64, Budget: 12}}, 4},
		{[]SpreadShare{{Mine: 0, Assigned: 64, Budget: 12}}, 1},
		{[]SpreadShare{{Mine: 64, Assigned: 64, Budget: 12}, {Mine: 0, Assigned: 64, Budget: 12}}, 6},
		{[]SpreadShare{{Mine: 64, Assigned: 64, Budget: 3}}, 3},
	}
	for _, c := range cases {
		if got := PoolSize(c.shares); got != c.want {
			t.Errorf("PoolSize(%+v) = %d, want %d", c.shares, got, c.want)
		}
	}
}

func TestPoolResize(t *testing.T) {
	tp := newTestPool(4)
	tp.SetSize(8)
	if s := tp.Stats(); s.Limit != 8 {
		t.Fatalf("%+v", s)
	}
	tp.take(t, "a", true)(time.Second, &store.Error{Status: 429})
	tp.SetSize(16)
	if s := tp.Stats(); s.Limit != 4 || !s.Backoff {
		t.Fatalf("a bigger budget ended backing off: %+v", s)
	}
	tp.SetSize(2)
	if s := tp.Stats(); s.Limit != 2 || s.Backoff {
		t.Fatalf("%+v", s)
	}
}

// TestPoolOneTenantSlow: when only one tenant's runs time out, only that
// tenant is held back; another tenant keeps its workers and its
// catch-up. When a second tenant's runs show it too, the pool halves.
func TestPoolOneTenantSlow(t *testing.T) {
	tp := newTestPool(8)
	busy := &store.Error{Status: 429, Body: "rejected_execution_exception"}
	tp.take(t, "b", true)(time.Second, nil)
	for range 4 {
		tp.take(t, "a", true)(time.Second, busy)
		tp.advance(poolCutGap + time.Second)
	}
	if s := tp.Stats(); s.Limit != 8 || s.Backoff {
		t.Fatalf("one tenant's timeouts held every tenant back: %+v", s)
	}
	if c := tp.tenants["a"].cap; c != 1 {
		t.Fatalf("a may still hold %d workers", c)
	}
	// b gets workers and catch-up as before.
	var held []func(time.Duration, error)
	for range 4 {
		held = append(held, tp.take(t, "b", true))
	}
	held = append(held, tp.take(t, "b", false))
	// a gets its one worker, and waits for a second though workers are
	// free.
	held = append(held, tp.take(t, "a", true))
	got := make(chan granted, 1)
	tp.wait(t, context.Background(), "a2", "a", true, got)
	held = append(held, tp.take(t, "b", true))
	select {
	case g := <-got:
		t.Fatalf("%s got a worker past a's cap", g.name)
	default:
	}
	for _, d := range held {
		d(time.Second, nil)
	}
	next(t, got).done(time.Second, nil)
	// A second tenant overloaded soon after: OpenSearch is slow for all.
	tp.take(t, "b", true)(time.Second, busy)
	if s := tp.Stats(); s.Limit != 4 || !s.Backoff {
		t.Fatalf("two tenants overloaded but the pool kept %+v", s)
	}
	// Backing off, one catch-up still runs.
	tp.take(t, "b", false)
	// a's cap comes back one a minute.
	tp.advance(3 * poolRaiseEvery)
	tp.Stats()
	if c := tp.tenants["a"]; c.cap != 0 {
		t.Errorf("a still held to %d workers after three minutes", c.cap)
	}
}
