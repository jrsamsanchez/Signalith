package detect

import (
	"context"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Pool is one server's detection workers while detections are spread,
// shared by every tenant's spread scheduler on it, so the server runs at
// most its share of the cluster's search budget however many tenants it
// serves. Waiting runs get workers in turns, a tenant at a time; while
// others wait, no tenant holds more than half the workers. Current slots
// go before catch-up, and catch-up always leaves one worker free.
//
// When a tenant's runs show OpenSearch overloaded (it refuses a search as
// busy, or does not answer in time) or their p95 time doubles over that of
// the 15 minutes before, that tenant alone is held to fewer workers: its
// cap halves, and grows back one a minute. Only when two or more tenants
// show it within poolSignalWindow (most of those it runs), or a single
// tenant runs here, is OpenSearch taken to be slow for everyone: the pool halves its workers,
// then gets one back a minute, and runs a single catch-up at a time until
// it has them all again. So one tenant's heavy rules slow only its own
// detections.
type Pool struct {
	// Mono is a monotonic clock; time.Since when nil.
	Mono func() time.Duration
	Log  *slog.Logger

	mu sync.Mutex
	// size is the workers the search budget gives this server, limit how
	// many it uses now (less while backing off).
	size, limit int
	// cutAt is when the pool last halved, raisedAt when it last got a
	// worker back.
	cutAt, raisedAt time.Duration
	cut             bool
	busy, catchUp   int
	held            map[string]int
	waiting         []*poolWaiter
	last            string
	tenants         map[string]*poolTenant
}

// poolTenant is what the pool knows of one tenant's runs.
type poolTenant struct {
	// seen is when the tenant last asked for a worker; signal when its
	// runs last showed OpenSearch overloaded.
	seen, signal time.Duration
	signalled    bool
	// cap, when above 0, is how many workers the tenant may hold while
	// its own runs are the slow ones; cutAt and raisedAt as for the pool.
	cap             int
	cutAt, raisedAt time.Duration
	samples         []poolSample
	checkedAt       time.Duration
}

type poolWaiter struct {
	tenant  string
	current bool
	ready   chan struct{}
	granted bool
}

type poolSample struct {
	at, took time.Duration
}

// Pool timing.
const (
	// DefaultPoolSize is a pool's size until the search budget is known.
	DefaultPoolSize = 4
	// poolRaiseEvery is how often a backing-off pool gets a worker back;
	// poolCutGap the least time between two halvings, so one burst of
	// refusals halves the pool once.
	poolRaiseEvery = time.Minute
	poolCutGap     = 30 * time.Second
	// Run times: the recent window is compared with the baseline before
	// it, each needing poolMinSamples runs.
	poolRecent     = 5 * time.Minute
	poolBaseline   = 15 * time.Minute
	poolMinSamples = 10
	poolMaxSamples = 4096
	// poolSignalWindow is how close together two tenants' signals must be
	// for the whole pool to halve.
	poolSignalWindow = 2 * time.Minute
)

// NewPool makes a pool of size workers.
func NewPool(size int) *Pool {
	size = max(size, 1)
	return &Pool{size: size, limit: size, held: map[string]int{}, tenants: map[string]*poolTenant{}}
}

func (p *Pool) mono() time.Duration {
	if p.Mono != nil {
		return p.Mono()
	}
	return time.Since(monoStart)
}

func (p *Pool) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.New(slog.DiscardHandler)
}

// SetSize sets how many workers the search budget gives this server.
func (p *Pool) SetSize(n int) {
	n = max(n, 1)
	p.mu.Lock()
	defer p.mu.Unlock()
	// Called every few seconds, it also gives a backing-off pool its
	// workers back while no run starts or ends.
	p.raise(p.mono())
	defer p.grant()
	if p.size == n {
		return
	}
	if !p.cut || p.limit > n {
		p.limit = n
	}
	p.size = n
	if p.limit >= p.size {
		p.cut = false
	}
}

// PoolStats is a pool's state.
type PoolStats struct {
	Size    int  `json:"size"`
	Limit   int  `json:"limit"`
	Busy    int  `json:"busy"`
	Waiting int  `json:"waiting"`
	Backoff bool `json:"backoff,omitempty"`
}

// Stats returns the pool's state.
func (p *Pool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raise(p.mono())
	p.grant()
	return PoolStats{Size: p.size, Limit: p.limit, Busy: p.busy, Waiting: len(p.waiting), Backoff: p.cut}
}

// Acquire waits for a worker for one of tenant's runs; current says the
// run is a rule's current slot rather than catch-up. The run calls done
// with how long it took and its error once it ends.
func (p *Pool) Acquire(ctx context.Context, tenant string, current bool) (done func(took time.Duration, err error), err error) {
	w := &poolWaiter{tenant: tenant, current: current, ready: make(chan struct{})}
	p.mu.Lock()
	now := p.mono()
	p.raise(now)
	p.tenant(tenant).seen = now
	p.waiting = append(p.waiting, w)
	p.grant()
	p.mu.Unlock()
	select {
	case <-w.ready:
	case <-ctx.Done():
		p.mu.Lock()
		granted := w.granted
		if !granted {
			p.waiting = slices.DeleteFunc(p.waiting, func(x *poolWaiter) bool { return x == w })
		}
		p.mu.Unlock()
		if granted {
			p.release(w, 0, nil)
		}
		return nil, ctx.Err()
	}
	var once sync.Once
	return func(took time.Duration, err error) { once.Do(func() { p.release(w, took, err) }) }, nil
}

func (p *Pool) release(w *poolWaiter, took time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.busy--
	if p.held[w.tenant]--; p.held[w.tenant] <= 0 {
		delete(p.held, w.tenant)
	}
	if !w.current {
		p.catchUp--
	}
	now := p.mono()
	p.record(w.tenant, now, took, err)
	p.raise(now)
	p.grant()
}

func (p *Pool) tenant(id string) *poolTenant {
	t := p.tenants[id]
	if t == nil {
		t = &poolTenant{}
		p.tenants[id] = t
	}
	return t
}

// grant hands free workers to waiting runs: current slots first, then
// catch-up, each class in turns over the tenants.
func (p *Pool) grant() {
	for p.busy < p.limit {
		w := p.pick(true)
		if w == nil && p.catchUpRoom() {
			w = p.pick(false)
		}
		if w == nil {
			return
		}
		p.waiting = slices.DeleteFunc(p.waiting, func(x *poolWaiter) bool { return x == w })
		w.granted = true
		p.busy++
		p.held[w.tenant]++
		if !w.current {
			p.catchUp++
		}
		p.last = w.tenant
		close(w.ready)
	}
}

// catchUpRoom reports whether a catch-up run may start: it always leaves
// a worker free, and runs one at a time while the pool backs off.
func (p *Pool) catchUpRoom() bool {
	if p.cut {
		return p.limit >= 2 && p.catchUp < 1
	}
	return p.catchUp < max(p.limit-1, 1)
}

// pick returns the first waiting run of the class (current or catch-up)
// of the next tenant in turn that may have another worker, or nil.
func (p *Pool) pick(current bool) *poolWaiter {
	first := map[string]*poolWaiter{}
	var tenants []string
	others := map[string]bool{}
	for _, w := range p.waiting {
		// For current slots, only other tenants' current slots limit a
		// tenant; for catch-up, any waiting run does.
		// A tenant held to its own cap does not count: it could not take
		// the worker anyway.
		if (current && w.current || !current) && !p.atCap(w.tenant) {
			others[w.tenant] = true
		}
		if w.current == current && first[w.tenant] == nil {
			first[w.tenant] = w
			tenants = append(tenants, w.tenant)
		}
	}
	if len(tenants) == 0 {
		return nil
	}
	sort.Strings(tenants)
	// Start after the tenant served last.
	i := sort.SearchStrings(tenants, p.last)
	if i < len(tenants) && tenants[i] == p.last {
		i++
	}
	limit := max(p.limit/2, 1)
	for k := range tenants {
		t := tenants[(i+k)%len(tenants)]
		waitingOthers := len(others) > 1 || len(others) == 1 && !others[t]
		if waitingOthers && p.held[t] >= limit {
			continue
		}
		if p.atCap(t) {
			continue
		}
		return first[t]
	}
	return nil
}

// overloaded reports whether err says OpenSearch is too busy.
func overloaded(err error) bool {
	return err != nil && (store.RefusalOf(err) == store.RefusedBusy || store.NoAnswer(err))
}

// record notes a finished run of tenant, and holds back that tenant, or
// the whole pool, when it shows OpenSearch overloaded.
func (p *Pool) record(tenant string, now, took time.Duration, err error) {
	t := p.tenant(tenant)
	switch {
	case overloaded(err):
		p.overload(tenant, t, now, "OpenSearch is too busy")
	case took > 0 && t.slowed(now, took):
		p.overload(tenant, t, now, "detection searches take twice as long as before")
	}
}

// slowed adds a run's time and reports whether the tenant's recent runs
// take twice as long as before.
func (t *poolTenant) slowed(now, took time.Duration) bool {
	t.samples = append(t.samples, poolSample{at: now, took: took})
	old := 0
	for old < len(t.samples) && now-t.samples[old].at > poolRecent+poolBaseline {
		old++
	}
	if extra := len(t.samples) - old - poolMaxSamples; extra > 0 {
		old += extra
	}
	t.samples = t.samples[old:]
	if now-t.checkedAt < poolCutGap {
		return false
	}
	t.checkedAt = now
	var recent, base []time.Duration
	for _, s := range t.samples {
		if now-s.at <= poolRecent {
			recent = append(recent, s.took)
		} else {
			base = append(base, s.took)
		}
	}
	if len(recent) < poolMinSamples || len(base) < poolMinSamples || p95(recent) <= 2*p95(base) {
		return false
	}
	// The slow runs become the next baseline, so one slowdown counts
	// once, not again every check while it lasts.
	t.samples = nil
	return true
}

// overload handles a sign of overload in tenant's runs. The whole pool
// halves when it runs a single tenant, or when most tenants served show
// it within poolSignalWindow (at least two); otherwise only tenant's cap
// does. A tenant already held to one worker does not count toward that:
// its slow runs are its own, and it could keep signalling forever.
func (p *Pool) overload(tenant string, t *poolTenant, now time.Duration, why string) {
	served, signalled := 0, 0
	if t.cap != 1 {
		signalled++
	}
	t.signal, t.signalled = now, true
	for id, o := range p.tenants {
		if id == tenant || now-o.seen <= poolRecent+poolBaseline {
			served++
		}
		if id != tenant && o.signalled && now-o.signal < poolSignalWindow && o.cap != 1 {
			signalled++
		}
	}
	if served <= 1 || signalled >= max(2, served/2+1) {
		p.halve(now, why)
		return
	}
	if t.cap > 0 && now-t.cutAt < poolCutGap {
		return
	}
	was := t.cap
	if was <= 0 {
		was = max(p.limit/2, 1)
	}
	t.cap = max(was/2, 1)
	t.cutAt, t.raisedAt = now, now
	p.log().Warn("running fewer of one tenant's detections at once while its searches are slow", "tenant", tenant, "why", why, "workers", t.cap)
}

// atCap reports whether tenant id is held back and holds all it may.
func (p *Pool) atCap(id string) bool {
	c := p.tenants[id]
	return c != nil && c.cap > 0 && p.held[id] >= c.cap
}

// inUse reports whether tenant id holds or waits for a worker.
func (p *Pool) inUse(id string) bool {
	if p.held[id] > 0 {
		return true
	}
	return slices.ContainsFunc(p.waiting, func(w *poolWaiter) bool { return w.tenant == id })
}

func p95(d []time.Duration) time.Duration {
	slices.Sort(d)
	return d[(len(d)*95-1)/100]
}

func (p *Pool) halve(now time.Duration, why string) {
	if p.cut && now-p.cutAt < poolCutGap {
		return
	}
	was := p.limit
	p.limit = max(p.limit/2, 1)
	p.cut, p.cutAt, p.raisedAt = p.limit < p.size, now, now
	if p.limit < was {
		p.log().Warn("running fewer detections at once while OpenSearch is slow", "why", why, "workers", p.limit, "of", p.size)
	}
}

// raise gives a backing-off pool, and each held-back tenant, one worker
// back a minute.
func (p *Pool) raise(now time.Duration) {
	for id, t := range p.tenants {
		for t.cap > 0 && now-t.raisedAt >= poolRaiseEvery {
			t.cap++
			t.raisedAt += poolRaiseEvery
			if t.cap >= max(p.limit/2, 1) {
				t.cap = 0
				p.log().Info("running a tenant's detections at the full rate again", "tenant", id)
			}
		}
		if t.cap <= 0 && !p.inUse(id) && now-t.seen > poolRecent+poolBaseline && (!t.signalled || now-t.signal > poolSignalWindow) {
			// A tenant gone for long is forgotten.
			delete(p.tenants, id)
		}
	}
	for p.cut && now-p.raisedAt >= poolRaiseEvery {
		p.limit++
		p.raisedAt += poolRaiseEvery
		if p.limit >= p.size {
			p.limit, p.cut = p.size, false
			p.log().Info("running detections at the full rate again", "workers", p.limit)
		}
	}
}
