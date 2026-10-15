package clusterinstall

import (
	"sync"
	"time"
)

// Gate limits downloads of the program, which is large, by the address
// they come from: one at a time from each address, and PerHour in an
// hour.
type Gate struct {
	// PerHour is how many downloads one address may start in an hour;
	// zero is 10.
	PerHour int
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu    sync.Mutex
	addrs map[string]*gateAddr
}

type gateAddr struct {
	busy   bool
	starts []time.Time
}

// Take starts a download from addr and returns the function that ends
// it, or false when addr has one running or has used its downloads for
// the hour.
func (g *Gate) Take(addr string) (func(), bool) {
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	limit := g.PerHour
	if limit <= 0 {
		limit = 10
	}
	t := now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.addrs == nil {
		g.addrs = map[string]*gateAddr{}
	}
	// Addresses with nothing in the last hour are forgotten.
	for k, a := range g.addrs {
		a.starts = recent(a.starts, t)
		if !a.busy && len(a.starts) == 0 {
			delete(g.addrs, k)
		}
	}
	a := g.addrs[addr]
	if a == nil {
		a = &gateAddr{}
		g.addrs[addr] = a
	}
	if a.busy || len(a.starts) >= limit {
		return nil, false
	}
	a.busy = true
	a.starts = append(a.starts, t)
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			a.busy = false
			g.mu.Unlock()
		})
	}, true
}

func recent(starts []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(starts) && now.Sub(starts[i]) >= time.Hour {
		i++
	}
	return starts[i:]
}
