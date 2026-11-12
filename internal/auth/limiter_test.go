// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func addr(a string) Client { return Client{Address: a} }

// fail makes one failed attempt and says what it led to.
func fail(t *testing.T, l *Limiter, c Client, account string) Failure {
	t.Helper()
	a, err := l.Begin(c, account)
	if err != nil {
		t.Fatalf("%+v/%s refused (%v) before failing", c, account, err)
	}
	return a.Fail()
}

// allowed reports whether an attempt may start, and if not, why.
func allowed(l *Limiter, c Client, account string) (bool, *Refusal) {
	a, err := l.Begin(c, account)
	if err != nil {
		var rf *Refusal
		if !errors.As(err, &rf) {
			panic(err)
		}
		return false, rf
	}
	a.Done()
	return true, nil
}

func succeed(t *testing.T, l *Limiter, c Client, account string) {
	t.Helper()
	a, err := l.Begin(c, account)
	if err != nil {
		t.Fatalf("%+v/%s refused: %v", c, account, err)
	}
	a.Succeed()
}

func TestLimiter(t *testing.T) {
	c := &clock{time.Now()}
	l := NewLimiter()
	l.Now, l.Max = c.now, 3
	for i := 0; i < 2; i++ {
		if fail(t, l, addr("10.0.0.1"), "admin").Locked {
			t.Fatal("locked out too early")
		}
	}
	if ok, _ := allowed(l, addr("10.0.0.1"), "admin"); !ok {
		t.Fatal("refused before the limit")
	}
	if !fail(t, l, addr("10.0.0.1"), "Admin ").Locked {
		t.Fatal("not locked out at the limit (account names ignore case)")
	}
	if ok, rf := allowed(l, addr("10.0.0.1"), "admin"); ok || rf.Wait != 15*time.Minute || rf.Reason != ReasonLocked {
		t.Errorf("allow = %v %+v", ok, rf)
	}
	if ok, _ := allowed(l, addr("10.0.0.2"), "admin"); !ok {
		t.Error("another client was refused")
	}
	if ok, _ := allowed(l, addr("10.0.0.1"), "vera"); !ok {
		t.Error("another account from the same client was refused")
	}
	c.t = c.t.Add(16 * time.Minute)
	if ok, _ := allowed(l, addr("10.0.0.1"), "admin"); !ok {
		t.Error("still refused after the lockout")
	}
	// Failures outside the window do not count.
	fail(t, l, addr("10.0.0.3"), "admin")
	fail(t, l, addr("10.0.0.3"), "admin")
	c.t = c.t.Add(16 * time.Minute)
	if fail(t, l, addr("10.0.0.3"), "admin").Locked {
		t.Error("old failures counted")
	}
	succeed(t, l, addr("10.0.0.3"), "admin")
	fail(t, l, addr("10.0.0.3"), "admin")
	fail(t, l, addr("10.0.0.3"), "admin")
	if ok, _ := allowed(l, addr("10.0.0.3"), "admin"); !ok {
		t.Error("success did not clear its own failures")
	}
}

// A successful sign-in to one account must not reset the count against
// another: otherwise anyone with an account could guess the admin's
// password forever.
func TestLimiterSuccessClearsOnlyItsOwnAccount(t *testing.T) {
	l := NewLimiter()
	for i := 0; i < l.Max-1; i++ {
		fail(t, l, addr("10.0.0.9"), "admin")
	}
	succeed(t, l, addr("10.0.0.9"), "vera")
	if !fail(t, l, addr("10.0.0.9"), "admin").Locked {
		t.Error("vera's sign-in reset the failures against admin")
	}
	if ok, _ := allowed(l, addr("10.0.0.9"), "admin"); ok {
		t.Error("admin not locked for this address")
	}
	if ok, _ := allowed(l, addr("10.0.0.9"), "vera"); !ok {
		t.Error("vera locked out by guesses against admin")
	}
}

func TestLimiterPerAddress(t *testing.T) {
	l := NewLimiter()
	l.Max, l.MaxPerAddress, l.MaxPerAccount = 3, 5, 6
	// One address trying many accounts.
	var f Failure
	for i := 0; i < 5; i++ {
		f = fail(t, l, addr("10.0.0.1"), fmt.Sprintf("user%d", i))
	}
	if !f.AddressLocked {
		t.Error("the failure that locked the address did not say so")
	}
	if ok, rf := allowed(l, addr("10.0.0.1"), "someone-else"); ok || rf.Reason != ReasonLocked {
		t.Errorf("address not locked after trying many accounts: %+v", rf)
	}
	// A browser that signed in to the account before is not: its cookie
	// is good for that one account only, so the lock, which stops one
	// address trying many accounts, need not hold it. Someone who puts
	// another person's address in front of their guesses cannot keep that
	// person's browser out.
	if ok, rf := allowed(l, Client{Address: "10.0.0.1", Browser: "b1"}, "someone-else"); !ok {
		t.Errorf("a known browser at a locked address was refused: %+v", rf)
	}
	// Its failures do not count toward the address either.
	for i := 0; i < l.Max-1; i++ {
		fail(t, l, Client{Address: "10.0.0.2", Browser: "b2"}, "ann")
	}
	if ok, _ := allowed(l, addr("10.0.0.2"), "ann"); !ok {
		t.Error("a known browser's failures counted toward its address")
	}
}

// An address nobody listed as shared, locked by someone guessing many
// accounts from it, still lets in the people who signed in from it
// before with their current password; everyone else stays refused.
func TestLimiterAddressLockSparesKnownAddresses(t *testing.T) {
	l := NewLimiter()
	l.Max, l.MaxPerAddress = 3, 5
	nat := Client{Address: "198.51.100.7", Version: "v1"}
	succeed(t, l, nat, "alice")
	for i := 0; i < l.MaxPerAddress; i++ {
		fail(t, l, nat, fmt.Sprintf("guess%d", i))
	}
	if ok, rf := allowed(l, nat, "bob"); ok || rf.Reason != ReasonLocked {
		t.Errorf("a stranger at the locked address was let in: %+v", rf)
	}
	if ok, rf := allowed(l, nat, "alice"); !ok {
		t.Errorf("alice, who signed in from this address before, was refused: %+v", rf)
	}
	// Her own account is still held to its own count.
	for i := 0; i < l.Max; i++ {
		fail(t, l, nat, "alice")
	}
	if ok, rf := allowed(l, nat, "alice"); ok || rf.Reason != ReasonLocked {
		t.Errorf("alice's account was not locked for the address after Max failures: %+v", rf)
	}
}

// Many addresses guessing one account slow it down for strangers, with a
// wait that doubles after each failure, but never lock it.
func TestLimiterSlowsAnAccountDown(t *testing.T) {
	c := &clock{time.Now()}
	l := NewLimiter()
	l.Now = c.now
	n := 0
	for ; n < l.MaxPerAccount; n++ {
		f := fail(t, l, addr(fmt.Sprintf("10.1.%d.%d", n/200, n%200)), "admin")
		if f.LockedOut() != (n == l.MaxPerAccount-1) {
			t.Fatalf("failure %d: %+v", n+1, f)
		}
	}
	want := time.Second
	for i := 0; i < 11; i++ {
		ok, rf := allowed(l, addr("10.2.0.1"), "admin")
		if ok || rf.Reason != ReasonSlowed || rf.Wait != want {
			t.Fatalf("after %d failures: allowed %v, %+v; want a wait of %v", n, ok, rf, want)
		}
		if ok, _ := allowed(l, addr("10.2.0.1"), "vera"); !ok {
			t.Fatal("another account was slowed down")
		}
		c.t = c.t.Add(want)
		f := fail(t, l, addr(fmt.Sprintf("10.3.0.%d", i)), "admin")
		n++
		want = min(2*want, l.MaxSlow)
		if f.Slowed != want {
			t.Fatalf("failure %d: slowed %v, want %v", n, f.Slowed, want)
		}
	}
	if want != 15*time.Minute {
		t.Fatalf("the wait reached only %v", want)
	}
	// An hour without failures ends it.
	c.t = c.t.Add(time.Hour)
	if ok, _ := allowed(l, addr("10.2.0.1"), "admin"); !ok {
		t.Error("still slowed down an hour after the last failure")
	}
}

// A browser that signed in to an account before is not slowed down by
// guesses from elsewhere, and neither is an address that did.
func TestLimiterKnownBrowsersAndAddresses(t *testing.T) {
	c := &clock{time.Now()}
	l := NewLimiter()
	l.Now = c.now
	succeed(t, l, addr("192.0.2.10"), "admin") // the admin's desk
	for i := 0; i < 40; i++ {
		c.t = c.t.Add(20 * time.Minute)
		if ok, _ := allowed(l, addr(fmt.Sprintf("10.9.%d.1", i)), "admin"); ok {
			fail(t, l, addr(fmt.Sprintf("10.9.%d.1", i)), "admin")
		}
		for j := 0; j < l.MaxPerAccount; j++ {
			if ok, _ := allowed(l, addr(fmt.Sprintf("10.8.%d.%d", i, j)), "admin"); ok {
				fail(t, l, addr(fmt.Sprintf("10.8.%d.%d", i, j)), "admin")
			}
		}
	}
	if ok, rf := allowed(l, addr("10.7.0.1"), "admin"); ok || rf.Reason != ReasonSlowed {
		t.Fatalf("a stranger was not slowed down: %v %+v", ok, rf)
	}
	if ok, rf := allowed(l, Client{Address: "10.7.0.1", Browser: "laptop"}, "admin"); !ok {
		t.Errorf("a known browser was refused: %+v", rf)
	}
	if ok, rf := allowed(l, addr("192.0.2.10"), "admin"); !ok {
		t.Errorf("the address the admin signed in from was refused: %+v", rf)
	}
	// An address is known only for the account that signed in from it.
	if ok, _ := allowed(l, addr("192.0.2.10"), "vera"); !ok {
		t.Error("vera, not attacked, was refused")
	}
	// A known browser's own mistakes lock only that browser.
	for i := 0; i < l.Max; i++ {
		fail(t, l, Client{Address: "10.7.0.1", Browser: "laptop"}, "admin")
	}
	if ok, rf := allowed(l, Client{Address: "10.7.0.2", Browser: "laptop"}, "admin"); ok || rf.Reason != ReasonLocked {
		t.Errorf("a browser that failed %d times is not locked: %+v", l.Max, rf)
	}
	if ok, _ := allowed(l, Client{Address: "10.7.0.1", Browser: "phone"}, "admin"); !ok {
		t.Error("another known browser was locked by the first one's mistakes")
	}
	// A shared address is never known: someone else behind it could use
	// that.
	nat := Client{Address: "198.51.100.1", Shared: true}
	succeed(t, l, nat, "vera")
	for i := 0; i < l.MaxPerAccount; i++ {
		fail(t, l, addr(fmt.Sprintf("10.5.0.%d", i)), "vera")
	}
	if ok, _ := allowed(l, nat, "vera"); ok {
		t.Error("a shared address became known")
	}
	// Known addresses are forgotten after KnownFor.
	c.t = c.t.Add(l.KnownFor)
	for i := 0; i < l.MaxPerAccount; i++ {
		fail(t, l, addr(fmt.Sprintf("10.6.1.%d", i)), "admin")
	}
	if ok, _ := allowed(l, addr("192.0.2.10"), "admin"); ok {
		t.Error("an address was still known after KnownFor")
	}
}

// Known addresses have a budget of their own, apart from known browsers':
// anyone at an address the user once signed in from (a NAT, a hotel
// network) can use the addresses' budget up, but that does not make the
// user's own browser a stranger.
func TestLimiterKnownAddressesCannotUseUpTheBrowsersBudget(t *testing.T) {
	c := &clock{time.Now()}
	l := NewLimiter()
	l.Now = c.now
	office := addr("203.0.113.5")
	succeed(t, l, office, "alice")
	// Someone else at the office guesses as fast as the limits allow, for
	// 45 minutes: 30 guesses.
	for i := 0; i < 3; i++ {
		for j := 0; j < l.Max; j++ {
			if ok, _ := allowed(l, office, "alice"); ok {
				fail(t, l, office, "alice")
			}
		}
		c.t = c.t.Add(l.Lockout)
	}
	// Outside addresses slow the account down for strangers.
	for i := 0; i < l.MaxPerAccount; i++ {
		if ok, _ := allowed(l, addr(fmt.Sprintf("10.4.0.%d", i)), "alice"); ok {
			fail(t, l, addr(fmt.Sprintf("10.4.0.%d", i)), "alice")
		}
	}
	if ok, rf := allowed(l, office, "alice"); ok || rf.Reason != ReasonSlowed {
		t.Fatalf("the office address, past the known addresses' budget, = %v %+v; want slowed like a stranger", ok, rf)
	}
	if ok, rf := allowed(l, Client{Address: "198.51.100.20", Browser: "alice-laptop"}, "alice"); !ok {
		t.Errorf("alice's own browser was refused after the office used up the known addresses' budget: %+v", rf)
	}
}

// An address is known for an account only with the password it signed in
// with: after a change or reset it is a stranger until it signs in again.
func TestLimiterKnownAddressEndsWithThePassword(t *testing.T) {
	l := NewLimiter()
	l.MaxPerAccount = 3
	home := Client{Address: "192.0.2.10", Version: "v1"}
	succeed(t, l, home, "alice")
	for i := 0; i < l.MaxPerAccount; i++ {
		fail(t, l, Client{Address: fmt.Sprintf("10.5.0.%d", i), Version: "v1"}, "alice")
	}
	if ok, rf := allowed(l, home, "alice"); !ok {
		t.Fatalf("the known address was refused: %+v", rf)
	}
	home.Version = "v2"
	if ok, rf := allowed(l, home, "alice"); ok || rf.Reason != ReasonSlowed {
		t.Errorf("the address was still known after the password changed: %v %+v", ok, rf)
	}
}

// Many people behind one shared address (a proxy or NAT) cannot lock each
// other out: there is no per-address limit, and one account's failures
// only slow that account down.
func TestLimiterSharedAddress(t *testing.T) {
	l := NewLimiter()
	l.MaxPerShared = 1000 // TestLimiterSharedCeiling
	nat := Client{Address: "203.0.113.5", Shared: true}
	for i := 0; i < 200; i++ {
		if f := fail(t, l, nat, fmt.Sprintf("nobody%d", i)); f.LockedOut() {
			t.Fatalf("failure %d against a new account from a shared address: %+v", i+1, f)
		}
	}
	for i := 0; i < l.Max; i++ {
		fail(t, l, nat, "ann")
	}
	if ok, rf := allowed(l, nat, "bob"); !ok {
		t.Errorf("bob was refused because of guesses against other accounts: %+v", rf)
	}
	if ok, _ := allowed(l, nat, "ann"); !ok {
		t.Error("ann was locked after Max failures from a shared address")
	}
	// Concurrent sign-ins from a shared address are not held back as one
	// client's.
	var open []*Attempt
	for i := 0; i < 100; i++ {
		a, err := l.Begin(nat, fmt.Sprintf("user%d", i))
		if err != nil {
			t.Fatalf("sign-in %d at once refused: %v", i+1, err)
		}
		open = append(open, a)
	}
	for _, a := range open {
		a.Done()
	}
}

// AUTHRT-02: a shared address has a ceiling of failures a minute, so it
// cannot be used to guess across accounts as fast as the server checks
// passwords. It waits; it is never locked, and other addresses are not
// held back.
func TestLimiterSharedCeiling(t *testing.T) {
	c := &clock{time.Now()}
	l := NewLimiter()
	l.Now = c.now
	l.MaxPerShared = 20
	nat := Client{Address: "203.0.113.5", Shared: true}
	for i := range 20 {
		if f := fail(t, l, nat, fmt.Sprintf("made-up%d", i)); f.LockedOut() {
			t.Fatalf("failure %d locked something: %+v", i+1, f)
		}
		c.t = c.t.Add(time.Second)
	}
	// Past the ceiling, attempts are paced to 20 a minute: one every
	// 3 seconds after the last failure.
	ok, rf := allowed(l, nat, "made-up-more")
	if ok || rf.Reason != ReasonBusy || rf.Wait > 3*time.Second {
		t.Fatalf("past the ceiling: %v %+v", ok, rf)
	}
	c.t = c.t.Add(2 * time.Second)
	fail(t, l, nat, "made-up-paced")
	if ok, _ := allowed(l, nat, "made-up-more"); ok {
		t.Fatal("a paced failure did not start the pace again")
	}
	if ok, _ := allowed(l, addr("198.51.100.1"), "made-up-more"); !ok {
		t.Error("another address was held back")
	}
	if ok, _ := allowed(l, Client{Address: "198.51.100.2", Shared: true}, "x"); !ok {
		t.Error("another shared address was held back")
	}
	c.t = c.t.Add(time.Minute)
	if ok, _ := allowed(l, nat, "made-up-more"); !ok {
		t.Error("still refused a minute later")
	}
}

// RT-01/AUTHRT-02: junk-name failures through a shared address must not
// keep out the people behind it who signed in before: a known browser and
// an account signed in to from that address are not held to its ceiling.
// Such an account is still slowed for strangers.
func TestLimiterSharedCeilingSparesKnownUsers(t *testing.T) {
	c := &clock{time.Now()}
	l := NewLimiter()
	l.Now = c.now
	l.MaxPerShared = 20
	nat := Client{Address: "203.0.113.5", Shared: true, Version: "v1"}
	a, err := l.Begin(nat, "dana")
	if err != nil {
		t.Fatal(err)
	}
	a.Succeed()
	for i := range 20 {
		fail(t, l, nat, fmt.Sprintf("junk%d", i))
	}
	if ok, _ := allowed(l, nat, "someone-new"); ok {
		t.Fatal("the ceiling did not hold a new account name")
	}
	if ok, rf := allowed(l, nat, "dana"); !ok {
		t.Errorf("an account signed in to from the shared address was held back: %+v", rf)
	}
	if ok, rf := allowed(l, Client{Address: nat.Address, Shared: true, Browser: "known-browser"}, "erin"); !ok {
		t.Errorf("a known browser was held back: %+v", rf)
	}
	// A new password makes the pair unknown again.
	if ok, _ := allowed(l, Client{Address: nat.Address, Shared: true, Version: "v2"}, "dana"); ok {
		t.Error("the pair stayed known after a password change")
	}
	// The pair is not known for anything else: dana's strangers' count
	// still slows her account down.
	for range l.MaxPerAccount {
		fail(t, l, nat, "dana")
	}
	if ok, rf := allowed(l, nat, "dana"); ok || rf.Reason != ReasonSlowed {
		t.Errorf("the shared address's known pair skipped the slow-down: %v %+v", ok, rf)
	}
}

// Attempts still being checked count, so a burst of parallel guesses
// cannot pass the limit before the first failure is recorded.
func TestLimiterCountsPendingAttempts(t *testing.T) {
	l := NewLimiter()
	var open []*Attempt
	for {
		a, err := l.Begin(addr("10.0.0.5"), "admin")
		if err != nil {
			var rf *Refusal
			if !errors.As(err, &rf) || rf.Wait != Busy || rf.Reason != ReasonBusy {
				t.Errorf("refusal = %v, want %v busy", err, Busy)
			}
			break
		}
		open = append(open, a)
		if len(open) > 100 {
			t.Fatal("no limit on attempts in progress")
		}
	}
	if len(open) != l.Max {
		t.Errorf("%d attempts in progress, want %d", len(open), l.Max)
	}
	for _, a := range open {
		a.Done()
		a.Done() // ending twice does nothing
	}
	if ok, _ := allowed(l, addr("10.0.0.5"), "admin"); !ok {
		t.Error("finished attempts still counted")
	}
	// From many addresses at once, the account takes MaxPerAccount.
	open = open[:0]
	for i := 0; ; i++ {
		a, err := l.Begin(Client{Address: "198.51.100.1", Shared: true}, "admin")
		if err != nil {
			break
		}
		open = append(open, a)
		if i > 100 {
			t.Fatal("no limit on attempts in progress for one account")
		}
	}
	if len(open) != l.MaxPerAccount {
		t.Errorf("%d attempts in progress for one account, want %d", len(open), l.MaxPerAccount)
	}
	for _, a := range open {
		a.Done()
	}
}

// However the guesses are spread, from fresh addresses, shared ones, or
// browsers that once signed in, an account takes a bounded number of
// them per hour.
func TestLimiterBoundsGuessesPerAccount(t *testing.T) {
	for _, tc := range []struct {
		name string
		from func(i int) Client
		max  int
	}{
		// MaxPerAccount, then waits of 1s, 2s, ... 512s and three of 15
		// minutes: 42 in the first hour.
		{"fresh addresses", func(i int) Client { return addr(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)) }, 45},
		{"one shared address", func(int) Client { return Client{Address: "203.0.113.5", Shared: true} }, 45},
		// Known browsers add at most MaxPerAccount an hour, and so do
		// known addresses.
		{"many known browsers", func(i int) Client {
			return Client{Address: fmt.Sprintf("10.0.%d.%d", i>>8&255, i&255), Browser: fmt.Sprint("b", i)}
		}, 45 + 30},
		{"many known addresses", func(i int) Client { return knownAddr(i) }, 45 + 30},
		{"known browsers and addresses", func(i int) Client {
			if i%2 == 0 {
				return knownAddr(i)
			}
			return Client{Address: fmt.Sprintf("10.0.%d.%d", i>>8&255, i&255), Browser: fmt.Sprint("b", i)}
		}, 45 + 30 + 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &clock{time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)}
			l := NewLimiter()
			l.Now = c.now
			// Every address the known-address cases use signed in before.
			for i := 0; i < 4096; i++ {
				succeed(t, l, knownAddr(i), "admin")
			}
			var times []time.Time
			end := c.t.Add(3 * time.Hour)
			for i := 0; c.t.Before(end); i++ {
				a, err := l.Begin(tc.from(i), "admin")
				if err != nil {
					var rf *Refusal
					errors.As(err, &rf)
					c.t = c.t.Add(rf.Wait)
					continue
				}
				a.Fail()
				times = append(times, c.t)
			}
			// The most guesses within any hour.
			most := 0
			for i := range times {
				n := 0
				for j := i; j < len(times) && times[j].Sub(times[i]) < time.Hour; j++ {
					n++
				}
				most = max(most, n)
			}
			t.Logf("%d guesses in 3 hours, at most %d in one hour", len(times), most)
			if most > tc.max {
				t.Errorf("%d guesses in one hour, want at most %d", most, tc.max)
			}
		})
	}
}

// knownAddr is the i-th of 4096 addresses that signed in to the account
// before, in TestLimiterBoundsGuessesPerAccount.
func knownAddr(i int) Client { return addr(fmt.Sprintf("10.200.%d.%d", i>>8&15, i&255)) }

// Only the failure that starts an account's slow-down says so.
func TestFailureSlowStarted(t *testing.T) {
	l := NewLimiter()
	c := &clock{time.Now()}
	l.Now = c.now
	started := 0
	for i := range l.MaxPerAccount + 3 {
		f := fail(t, l, addr(fmt.Sprintf("10.1.%d.1", i)), "carol")
		if f.SlowStarted {
			started++
			if f.Slowed == 0 {
				t.Error("started a slow-down of nothing")
			}
		}
		c.t = c.t.Add(time.Hour / 2 / time.Duration(l.MaxPerAccount))
		c.t = c.t.Add(l.slowWait(i+1, l.MaxPerAccount))
	}
	if started != 1 {
		t.Errorf("%d failures started the slow-down, want 1", started)
	}
}
