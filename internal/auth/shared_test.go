package auth

import (
	"bytes"
	"testing"
	"time"
)

// V15: with three servers taking sign-ins, each locks an address and
// account after ceil(10/3) = 4 failures, an address after 10, and slows
// strangers after 10; alone, or with no divisor, the limits stay.
func TestLimiterDivisor(t *testing.T) {
	c := &clock{time.Now()}
	servers := 3
	l := NewLimiter()
	l.Now, l.Divisor = c.now, func() int { return servers }
	for i := 1; i <= 3; i++ {
		if fail(t, l, addr("10.0.0.1"), "admin").Locked {
			t.Fatalf("locked after %d failures", i)
		}
	}
	if !fail(t, l, addr("10.0.0.1"), "admin").Locked {
		t.Fatal("not locked after 4 failures with 3 servers")
	}
	if ok, rf := allowed(l, addr("10.0.0.1"), "admin"); ok || rf.Reason != ReasonLocked {
		t.Fatalf("after the lock: %v %+v", ok, rf)
	}

	if got := share(10, 3); got != 4 {
		t.Errorf("share(10, 3) = %d", got)
	}
	for _, tc := range []struct{ base, n, want int }{{30, 3, 10}, {10, 10, 3}, {2, 5, 2}, {10, 1, 10}, {10, 0, 10}, {0, 3, 0}} {
		if got := share(tc.base, tc.n); got != tc.want {
			t.Errorf("share(%d, %d) = %d, want %d", tc.base, tc.n, got, tc.want)
		}
	}

	// Alone: the base limits.
	servers = 1
	for i := 1; i < 10; i++ {
		if fail(t, l, addr("10.0.0.2"), "admin").Locked {
			t.Fatalf("alone, locked after %d failures", i)
		}
	}
	if !fail(t, l, addr("10.0.0.2"), "admin").Locked {
		t.Fatal("alone, not locked after 10 failures")
	}
}

// OnLock reports each lock with a key every server computes alike, and
// External makes another server refuse it until it ends.
func TestLimiterSharedLocks(t *testing.T) {
	c := &clock{time.Now()}
	type lock struct {
		scope, key string
		until      time.Time
	}
	var got []lock
	a, b := NewLimiter(), NewLimiter()
	a.Now, b.Now = c.now, c.now
	a.Max, b.Max = 3, 3
	a.OnLock = func(scope, key string, until time.Time) { got = append(got, lock{scope, key, until}) }
	for range 3 {
		fail(t, a, addr("10.0.0.1"), "admin")
	}
	if len(got) != 1 || got[0].scope != ScopeAddressAccount || got[0].key != LockKey(nil, "p\x0010.0.0.1\x00admin") || !got[0].until.Equal(c.t.Add(15*time.Minute)) {
		t.Fatalf("locks %+v", got)
	}
	ext := map[string]time.Time{}
	for _, k := range got {
		ext[k.key] = k.until
	}
	b.External(ext)
	if ok, rf := allowed(b, addr("10.0.0.1"), "Admin"); ok || rf.Reason != ReasonLocked || rf.Wait != 15*time.Minute {
		t.Fatalf("b, same address and account: %v %+v", ok, rf)
	}
	if ok, _ := allowed(b, addr("10.0.0.9"), "admin"); !ok {
		t.Error("b refused another address")
	}
	c.t = c.t.Add(15 * time.Minute)
	if ok, _ := allowed(b, addr("10.0.0.1"), "admin"); !ok {
		t.Error("b still refuses after the lock ended")
	}

	// Strangers' wait reaching MaxSlow is reported once it does (1s, 2s,
	// then 4s), and slows the account on b too.
	got = nil
	a.MaxPerAccount, b.MaxPerAccount, a.MaxSlow, b.MaxSlow = 2, 2, 4*time.Second, 4*time.Second
	for i := range 5 {
		fail(t, a, addr("10.0.1."+string(rune('1'+i))), "carol")
		c.t = c.t.Add(time.Minute)
	}
	var slow []lock
	for _, k := range got {
		if k.scope == ScopeSlow {
			slow = append(slow, k)
		}
	}
	if len(slow) == 0 || slow[0].key != LockKey(nil, "u\x00carol") {
		t.Fatalf("slow locks %+v", got)
	}
	b.External(map[string]time.Time{slow[len(slow)-1].key: c.t.Add(time.Minute)})
	if ok, rf := allowed(b, addr("10.0.2.1"), "carol"); ok || rf.Reason != ReasonSlowed {
		t.Errorf("b, slowed account: %v %+v", ok, rf)
	}
	// A known browser is not a stranger.
	if ok, _ := allowed(b, Client{Address: "10.0.2.1", Browser: "known"}, "carol"); !ok {
		t.Error("b slowed a known browser")
	}
	// An address shared by many is never locked as one client.
	got = nil
	shared := Client{Address: "10.9.9.9", Shared: true}
	for i := range 6 {
		fail(t, a, shared, "user"+string(rune('a'+i)))
	}
	for _, k := range got {
		if k.scope != ScopeSlow {
			t.Errorf("lock for a shared address: %+v", k)
		}
	}
}

// Sessions keep what they started with; a browser key made of the same
// raw bytes knows the same browsers.
func TestSessionStartAndBrowserKeyFrom(t *testing.T) {
	s := NewSessions(time.Hour)
	tok := s.Start(NewSession{User: "jlee", Remember: true, Version: "v1", Epoch: 4, Method: "local", Client: "10.0.0.1"})
	ss, ok := s.Lookup(tok)
	if !ok || ss.User != "jlee" || !ss.Remember || ss.Version != "v1" || ss.Epoch != 4 || ss.Method != "local" || ss.Degraded {
		t.Errorf("session %+v %v", ss, ok)
	}
	raw := bytes.Repeat([]byte{7}, 32)
	a, b := NewBrowserKeyFrom(raw), NewBrowserKeyFrom(bytes.Clone(raw))
	now := time.Now()
	v := a.Issue("jlee", "v1", now)
	if _, ok := b.Check("jlee", "v1", v, now); !ok || a.CookieSuffix("jlee") != b.CookieSuffix("jlee") {
		t.Error("a key made of the same bytes does not know the browser")
	}
	if _, ok := NewBrowserKey().Check("jlee", "v1", v, now); ok {
		t.Error("another key knows the browser")
	}
}
