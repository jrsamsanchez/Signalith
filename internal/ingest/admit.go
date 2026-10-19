// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Limits are the ingest slots (see Admit) and the memory for request
// bodies arriving (see ReadBody) that pipelines share. In multi-tenant
// mode every tenant's pipeline is given the same Limits, so the server
// writes no more batches and holds no more memory however many tenants
// there are. Make one with NewLimits.
type Limits struct {
	slotsMu sync.Mutex
	slots   *slots

	// recvUsed is the receive budget in use; recvTenant is each tenant's
	// part of it and recvBy each sender address's, within its tenant.
	recvMax    int64
	recvMu     sync.Mutex
	recvUsed   int64
	recvTenant map[string]int64
	recvBy     map[recvKey]int64
	// recvContended is until when every tenant is held to half the
	// budget, set when a tenant is refused because others fill it: else a
	// tenant that fills the budget alone would turn every newcomer away.
	recvContended time.Time
	now           func() time.Time // for tests; nil is time.Now
}

// recvContendedFor is how long a tenant turned away for a full budget
// holds the others to half of it.
const recvContendedFor = 10 * time.Second

type recvKey struct {
	tenant string
	addr   netip.Addr
}

// NewLimits returns Limits of maxConcurrent ingest slots and maxReceiving
// bytes for bodies arriving; zero or less uses DefaultMaxConcurrent and
// DefaultMaxReceiving.
func NewLimits(maxConcurrent int, maxReceiving int64) *Limits {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrent
	}
	if maxReceiving <= 0 {
		maxReceiving = DefaultMaxReceiving
	}
	return &Limits{slots: newSlots(maxConcurrent), recvMax: maxReceiving}
}

// limits returns the pipeline's Limits: its Limits field, or else its
// own, made the first time from MaxConcurrent and MaxReceiving.
func (p *Pipeline) limits() *Limits {
	if p.Limits != nil {
		return p.Limits
	}
	p.ownLimitsOnce.Do(func() { p.ownLimits = NewLimits(p.MaxConcurrent, p.MaxReceiving) })
	return p.ownLimits
}

// slots hands out the ingest slots. A free slot is taken at once: when
// one is free nobody is waiting. While requests wait, a slot freed goes
// to the longest-waiting request whose tenant holds less than its share
// and whose sender, within that tenant, holds less than the sender share
// (a quarter of the slots); else to the longest-waiting request whose
// tenant holds less than its share; else to the longest-waiting request.
// The tenant share is half the slots while requests of more than one
// tenant are waiting, and all of them otherwise. So one token that sends
// many small batches cannot keep the others waiting, nor one tenant the
// other tenants, but a token or tenant sending alone still gets every
// slot.
type slots struct {
	n, share    int
	tenantShare int
	held        int
	per         map[slotKey]int
	perTenant   map[string]int
	waiting     []*slotWaiter
	// waitingBy counts the requests waiting from each tenant.
	waitingBy map[string]int
}

type slotKey struct {
	tenant, sender string
}

type slotWaiter struct {
	key     slotKey
	granted chan struct{}
	done    bool // granted, or given up
}

func newSlots(n int) *slots {
	return &slots{n: n, share: max(n/4, 1), tenantShare: max(n/2, 1),
		per: map[slotKey]int{}, perTenant: map[string]int{}, waitingBy: map[string]int{}}
}

// Admit waits up to wait for one of the ingest slots (see Limits) and
// returns the function that frees it, or ErrBusy. sender is what the
// request is counted under for its share within the pipeline's Tenant,
// such as its agent token's ID. Take a slot once the request body has
// arrived (see ReadBody) and hold it while the body is decoded and
// written: that bounds the OpenSearch writes ingest runs however many
// agents send at once, and a slow sender cannot hold a slot.
func (p *Pipeline) Admit(ctx context.Context, wait time.Duration, sender string) (func(), error) {
	l := p.limits()
	key := slotKey{p.Tenant, sender}
	l.slotsMu.Lock()
	s := l.slots
	release := func() {
		l.slotsMu.Lock()
		s.free(key)
		l.slotsMu.Unlock()
	}
	if s.held < s.n {
		s.take(key)
		l.slotsMu.Unlock()
		return release, nil
	}
	w := &slotWaiter{key: key, granted: make(chan struct{})}
	s.waiting = append(s.waiting, w)
	s.waitingBy[key.tenant]++
	l.slotsMu.Unlock()

	t := time.NewTimer(wait)
	defer t.Stop()
	var err error
	select {
	case <-w.granted:
		return release, nil
	case <-t.C:
		err = ErrBusy
	case <-ctx.Done():
		err = ctx.Err()
	}
	l.slotsMu.Lock()
	defer l.slotsMu.Unlock()
	if w.done {
		// Granted as the wait ended: hand it on.
		s.free(key)
		return nil, err
	}
	w.done = true
	s.drop(w)
	return nil, err
}

func (s *slots) take(k slotKey) {
	s.held++
	s.per[k]++
	s.perTenant[k.tenant]++
}

func (s *slots) free(k slotKey) {
	s.held--
	if s.per[k]--; s.per[k] <= 0 {
		delete(s.per, k)
	}
	if s.perTenant[k.tenant]--; s.perTenant[k.tenant] <= 0 {
		delete(s.perTenant, k.tenant)
	}
	for s.held < s.n && len(s.waiting) > 0 {
		i := s.next()
		w := s.waiting[i]
		s.remove(i)
		w.done = true
		s.take(w.key)
		close(w.granted)
	}
}

// next picks the waiting request a freed slot goes to (see slots).
func (s *slots) next() int {
	tenantShare := s.n
	if len(s.waitingBy) > 1 {
		tenantShare = s.tenantShare
	}
	underTenant := -1
	for i, w := range s.waiting {
		if s.perTenant[w.key.tenant] >= tenantShare {
			continue
		}
		if s.per[w.key] < s.share {
			return i
		}
		if underTenant < 0 {
			underTenant = i
		}
	}
	if underTenant >= 0 {
		return underTenant
	}
	return 0
}

func (s *slots) remove(i int) {
	t := s.waiting[i].key.tenant
	if s.waitingBy[t]--; s.waitingBy[t] <= 0 {
		delete(s.waitingBy, t)
	}
	s.waiting = append(s.waiting[:i], s.waiting[i+1:]...)
}

func (s *slots) drop(w *slotWaiter) {
	for i, x := range s.waiting {
		if x == w {
			s.remove(i)
			return
		}
	}
}
