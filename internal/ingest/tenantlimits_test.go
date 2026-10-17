package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// admitWaiter queues a request of p's tenant for a slot and reports on got
// who was given one, keeping the slot until release is closed.
func admitWaiter(p *Pipeline, sender string, got chan<- string, release <-chan struct{}) {
	r, err := p.Admit(context.Background(), 5*time.Second, sender)
	if err != nil {
		got <- "error " + err.Error()
		return
	}
	got <- p.Tenant + "/" + sender
	<-release
	r()
}

// TestAdmitSharesSlotsBetweenTenants: while more than one tenant waits, a
// freed slot goes first to a tenant under half the slots and a sender
// under a quarter, then to a tenant under half, then to the longest
// waiting.
func TestAdmitSharesSlotsBetweenTenants(t *testing.T) {
	l := NewLimits(4, 0) // a tenant's share is 2 slots, a sender's 1
	a := &Pipeline{Limits: l, Tenant: "a"}
	b := &Pipeline{Limits: l, Tenant: "b"}
	ctx := context.Background()
	var held []func()
	for _, p := range []*Pipeline{a, a, a, b} {
		sender := "busy"
		if p == b {
			sender = "x"
		}
		r, err := p.Admit(ctx, time.Second, sender)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, r)
	}
	got := make(chan string, 3)
	release := make(chan struct{})
	defer close(release)
	// In order: tenant a, over its share; b's sender x, over its own
	// share; and b's sender y, under both.
	go admitWaiter(a, "busy", got, release)
	waitFor(t, a, 1)
	go admitWaiter(b, "x", got, release)
	waitFor(t, a, 2)
	go admitWaiter(b, "y", got, release)
	waitFor(t, a, 3)

	held[0]() // a now holds 2, b 1
	if g := <-got; g != "b/y" {
		t.Errorf("first freed slot went to %q", g)
	}
	held[1]() // a holds 1, b 2: a is under its share, b at it
	if g := <-got; g != "a/busy" {
		t.Errorf("second freed slot went to %q", g)
	}
	held[3]() // only b waits now, so it may have every slot
	if g := <-got; g != "b/x" {
		t.Errorf("third freed slot went to %q", g)
	}
	held[2]()
}

// TestAdmitTenantAloneGetsEverySlot: one tenant sending alone, or while
// the others only hold slots, is not held to half of them.
func TestAdmitTenantAloneGetsEverySlot(t *testing.T) {
	l := NewLimits(4, 0)
	a := &Pipeline{Limits: l, Tenant: "a"}
	b := &Pipeline{Limits: l, Tenant: "b"}
	ctx := context.Background()
	var held []func()
	for i := range 4 {
		r, err := a.Admit(ctx, time.Second, fmt.Sprint("s", i))
		if err != nil {
			t.Fatalf("slot %d: %v", i+1, err)
		}
		held = append(held, r)
	}
	if _, err := b.Admit(ctx, 10*time.Millisecond, "x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("a fifth request in another tenant: %v", err)
	}
	// b holds one slot and waits for none; a, over half, still gets the
	// freed ones, its quiet sender first.
	held[0]()
	rb, err := b.Admit(ctx, time.Second, "x")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 2)
	release := make(chan struct{})
	go admitWaiter(a, "s1", got, release)
	waitFor(t, a, 1)
	go admitWaiter(a, "quiet", got, release)
	waitFor(t, a, 2)
	rb()
	if g := <-got; g != "a/quiet" {
		t.Errorf("freed slot went to %q", g)
	}
	held[1]()
	if g := <-got; g != "a/s1" {
		t.Errorf("then %q", g)
	}
	close(release)
	held[2]()
	held[3]()
	waitIdle(t, l)
}

// TestTenantPipelinesShareSlots: pipelines given the same Limits share its
// slots, so tenants together hold no more than MaxConcurrent.
func TestTenantPipelinesShareSlots(t *testing.T) {
	l := NewLimits(2, 0)
	var ps []*Pipeline
	for i := range 3 {
		ps = append(ps, &Pipeline{Limits: l, Tenant: fmt.Sprint("t", i), MaxConcurrent: 100})
	}
	ctx := context.Background()
	r0, err0 := ps[0].Admit(ctx, time.Second, "a")
	r1, err1 := ps[1].Admit(ctx, time.Second, "a")
	if err0 != nil || err1 != nil {
		t.Fatal(err0, err1)
	}
	if _, err := ps[2].Admit(ctx, 10*time.Millisecond, "a"); !errors.Is(err, ErrBusy) {
		t.Fatalf("a third tenant past the shared slots: %v", err)
	}
	r0()
	r2, err := ps[2].Admit(ctx, time.Second, "a")
	if err != nil {
		t.Fatal(err)
	}
	r1()
	r2()
	waitIdle(t, l)
}

// TestAdmitGivingUpLeavesNoSlotBehind: requests of many tenants and
// senders that time out or are cancelled while slots free leave nothing
// held or queued.
func TestAdmitGivingUpLeavesNoSlotBehind(t *testing.T) {
	l := NewLimits(3, 0)
	var wg sync.WaitGroup
	for i := range 200 {
		p := &Pipeline{Limits: l, Tenant: fmt.Sprint("t", i%4)}
		wg.Go(func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if i%3 == 0 {
				time.AfterFunc(time.Duration(rand.IntN(2000))*time.Microsecond, cancel)
			}
			r, err := p.Admit(ctx, time.Duration(rand.IntN(3000))*time.Microsecond, fmt.Sprint("s", i%5))
			if err == nil {
				time.Sleep(time.Duration(rand.IntN(500)) * time.Microsecond)
				r()
			}
		})
	}
	wg.Wait()
	waitIdle(t, l)
	// Every slot can still be taken.
	p := &Pipeline{Limits: l, Tenant: "t9"}
	for i := range 3 {
		if _, err := p.Admit(context.Background(), 0, "x"); err != nil {
			t.Fatalf("slot %d after: %v", i+1, err)
		}
	}
}

// waitIdle checks that, once the requests' goroutines finish, l has no
// slot held and no request queued.
func waitIdle(t *testing.T, l *Limits) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		l.slotsMu.Lock()
		s := l.slots
		idle := s.held == 0 && len(s.per) == 0 && len(s.perTenant) == 0 && len(s.waiting) == 0 && len(s.waitingBy) == 0
		state := fmt.Sprintf("held=%d per=%v tenants=%v waiting=%d by=%v", s.held, s.per, s.perTenant, len(s.waiting), s.waitingBy)
		l.slotsMu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("left %s", state)
		}
	}
}

// TestTenantPipelinesShareReceiveBudget: tenants' pipelines take bodies'
// memory from one budget; one tenant may hold half of it while another
// holds some, the same address in two tenants is counted apart, and
// everything is given back.
func TestTenantPipelinesShareReceiveBudget(t *testing.T) {
	l := NewLimits(0, 1<<20)
	a := &Pipeline{Limits: l, Tenant: "a", MaxReceiving: 64 << 20}
	b := &Pipeline{Limits: l, Tenant: "b"}
	body := func(n int) io.Reader { return bytes.NewReader(bytes.Repeat([]byte("x"), n)) }
	addr, other := netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("198.51.100.1")

	// Alone, a tenant may use more than half.
	var rels []func()
	for i := range 3 {
		_, rel, err := a.ReadBody(body(250<<10), netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 250<<10)
		if err != nil {
			t.Fatalf("tenant a alone, body %d: %v", i+1, err)
		}
		rels = append(rels, rel)
	}
	for _, rel := range rels {
		rel()
	}

	_, relA, err := a.ReadBody(body(200<<10), addr, -1) // 256 KB held, a quarter
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.ReadBody(body(10), addr, 10); !errors.Is(err, ErrSenderBusy) {
		t.Errorf("same address in the same tenant: %v", err)
	}
	// The same address in another tenant has a quarter of its own.
	_, relB, err := b.ReadBody(body(200<<10), addr, 200<<10)
	if err != nil {
		t.Fatalf("same address in another tenant: %v", err)
	}
	if total, by := b.receiving(); total != 256<<10+200<<10+1 || by[addr] != 200<<10+1 {
		t.Errorf("held %d (%v)", total, by)
	}
	// While b holds some, a may not grow past half.
	if _, _, err := a.ReadBody(body(300<<10), netip.Addr{}, 300<<10); !errors.Is(err, ErrBusy) {
		t.Errorf("tenant a past half: %v", err)
	}
	_, relA2, err := a.ReadBody(body(200<<10), netip.Addr{}, 200<<10)
	if err != nil {
		t.Fatalf("tenant a up to half: %v", err)
	}
	// Then the budget as a whole is the limit.
	if _, _, err := b.ReadBody(body(400<<10), other, 400<<10); !errors.Is(err, ErrBusy) {
		t.Errorf("over the shared total: %v", err)
	}
	if _, rel, err := b.ReadBody(body(100<<10), other, 100<<10); err != nil {
		t.Errorf("within the total: %v", err)
	} else {
		rel()
	}
	relA()
	relA2()
	relB()
	l.recvMu.Lock()
	defer l.recvMu.Unlock()
	if l.recvUsed != 0 || len(l.recvBy) != 0 || len(l.recvTenant) != 0 {
		t.Errorf("after every release: %d held (%v, %v)", l.recvUsed, l.recvBy, l.recvTenant)
	}
}

func TestTenantFillingBudgetAloneMakesRoom(t *testing.T) {
	l := NewLimits(0, 1<<20)
	clock := time.Unix(0, 0)
	l.now = func() time.Time { return clock }
	// Tenant a fills the budget alone, which it may.
	if err := l.reserve("a", netip.Addr{}, 1<<20); err != nil {
		t.Fatal(err)
	}
	// A newcomer is turned away, and that holds a to half for a while.
	if err := l.reserve("b", netip.Addr{}, 1); !errors.Is(err, errReceiveFull) {
		t.Fatalf("newcomer with the budget full: %v", err)
	}
	l.unreserve("a", netip.Addr{}, 1<<20)
	if err := l.reserve("a", netip.Addr{}, 600<<10); !errors.Is(err, errReceiveTenant) {
		t.Errorf("a past half right after: %v", err)
	}
	if err := l.reserve("a", netip.Addr{}, 512<<10); err != nil {
		t.Errorf("a up to half: %v", err)
	}
	if err := l.reserve("b", netip.Addr{}, 64<<10); err != nil {
		t.Errorf("newcomer once a is held to half: %v", err)
	}
	l.unreserve("a", netip.Addr{}, 512<<10)
	l.unreserve("b", netip.Addr{}, 64<<10)
	// Once the time is up, a alone may fill it again.
	clock = clock.Add(recvContendedFor + time.Second)
	if err := l.reserve("a", netip.Addr{}, 1<<20); err != nil {
		t.Errorf("a alone later: %v", err)
	}
}
