package auth

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Limiter slows password guessing without giving anyone a way to keep the
// real user out. It counts failed sign-ins in these buckets:
//
//   - per address: MaxPerAddress failures within Window, whatever the
//     accounts, lock the address for Lockout (one address trying many
//     accounts). A known browser is not held to it, since its cookie is
//     only good for its own account;
//   - per address and account: Max failures within Window lock that
//     account for that address;
//   - per account, from browsers and addresses that have not signed in to
//     it before: after MaxPerAccount failures within SlowWindow, from any
//     addresses, each further try must wait, 1 second after the first
//     and twice as long after each failure since, up to MaxSlow. The
//     account is never locked: it is only slowed down for strangers;
//   - per known browser: a browser that signed in to the account before
//     (Client.Browser) is not slowed by that count. It has a bucket of
//     its own instead, where Max failures lock it for that account.
//     Known browsers together have MaxPerAccount failures within
//     SlowWindow; past that they count as strangers until those failures
//     are older than that, so the guesses an account can take stay
//     bounded however many browsers once signed in to it;
//   - per known address: an address that signed in to the account within
//     KnownFor, with the same password (Client.Version), is not slowed by
//     the strangers' count either. Known addresses together have a budget
//     of their own of MaxPerAccount failures within SlowWindow, apart from
//     the browsers', since anyone else at such an address (a NAT, a hotel
//     network) could use it up: that must not make the user's own browser
//     a stranger.
//
// An address that stands for many people (Client.Shared: a proxy, load
// balancer or NAT) has neither of the first two buckets and is never known:
// its sign-ins are counted per account, so nobody behind it can lock the
// others out.
//
// A successful sign-in clears only the failures of its own address (or
// browser) and account, so signing in to one account never helps guess
// another. Attempts still being checked count too, so parallel requests
// cannot all slip in before the first failure is recorded.
type Limiter struct {
	Max           int
	MaxPerAddress int
	MaxPerAccount int
	Window        time.Duration
	Lockout       time.Duration
	// SlowWindow is how long a failure from a stranger counts toward
	// slowing the account down, and MaxSlow the longest wait.
	SlowWindow time.Duration
	MaxSlow    time.Duration
	// KnownFor is how long an address stays known for an account after a
	// successful sign-in from it.
	KnownFor time.Duration
	Now      func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
	known   map[string]time.Time // address and account: last sign-in
}

type bucket struct {
	failures    []time.Time
	pending     int
	lockedUntil time.Time
	window      time.Duration
}

// NewLimiter allows 10 failures per address and account and 30 per address
// within 15 minutes, then refuses for 15 minutes; and slows an account down
// for browsers and addresses that never signed in to it after 30 failures
// within an hour, up to a 15 minute wait.
func NewLimiter() *Limiter {
	return &Limiter{Max: 10, MaxPerAddress: 30, MaxPerAccount: 30, Window: 15 * time.Minute, Lockout: 15 * time.Minute,
		SlowWindow: time.Hour, MaxSlow: 15 * time.Minute, KnownFor: 30 * 24 * time.Hour,
		Now: time.Now, buckets: map[string]*bucket{}, known: map[string]time.Time{}}
}

// Client is who a sign-in attempt comes from.
type Client struct {
	// Address is what the client is counted under, such as its IPv4
	// address or its IPv6 /64 network.
	Address string
	// Shared is set when Address stands for many people (a proxy, load
	// balancer or NAT), so it is never locked or limited as one client.
	Shared bool
	// Browser names a browser that signed in to the account before, from
	// its known-browser cookie, or a signed-in session; "" for anyone
	// else.
	Browser string
	// Version stands for the account's current password. An address is
	// known for an account only while the password it signed in with is
	// the current one.
	Version string
}

// Busy is the wait Begin reports when the limit is only reached by attempts
// still being checked: the client should try again in a moment.
const Busy = 5 * time.Second

// slowStart is the first wait once an account is slowed down; each
// failure after it doubles the wait, up to MaxSlow.
const slowStart = time.Second

// Why an attempt was refused (Refusal.Reason).
const (
	// ReasonBusy: too many attempts are being checked at once.
	ReasonBusy = "busy"
	// ReasonLocked: too many failures from this address, or from this
	// address or browser for this account.
	ReasonLocked = "locked"
	// ReasonSlowed: too many failures for this account from browsers and
	// addresses that have not signed in to it before.
	ReasonSlowed = "slowed"
)

// Refusal is the error Begin returns when an attempt may not start yet.
type Refusal struct {
	Wait   time.Duration
	Reason string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("sign-in refused (%s) for %s", r.Reason, r.Wait.Round(time.Second))
}

// Failure is what one wrong password led to.
type Failure struct {
	// Locked is set when it locked the address, or the account for this
	// address or browser.
	Locked bool
	// AddressLocked is set when it locked the address for every account.
	AddressLocked bool
	// Slowed is how long strangers must now wait before trying this
	// account again; 0 when they need not.
	Slowed time.Duration
}

// LockedOut reports whether further tries are refused or slowed for a
// while.
func (f Failure) LockedOut() bool { return f.Locked || f.Slowed > 0 }

// Bucket kinds.
const (
	kindLock  = iota // locks for Lockout at its limit
	kindKnown        // known browsers' or known addresses' failures for an account
	kindSlow         // strangers' failures for an account
)

type slot struct {
	key    string
	kind   int
	limit  int
	window time.Duration
}

// Attempt is one sign-in being checked. End it with exactly one of Fail,
// Succeed or Done.
type Attempt struct {
	l       *Limiter
	slots   []slot
	own     string // the address-and-account or browser bucket
	address string // known after a success; "" for a shared address
	account string
	version string
	done    bool
}

// Begin starts an attempt to sign in to account from c, or returns a
// *Refusal saying how long until one is allowed. Account names ignore case
// and spacing.
func (l *Limiter) Begin(c Client, account string) (*Attempt, error) {
	account = strings.ToLower(strings.TrimSpace(account))
	now := l.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]*bucket{}
	}
	if len(l.buckets) > 50000 {
		l.pruneLocked(now)
	}
	a := &Attempt{l: l, account: account, version: c.Version}
	if !c.Shared {
		a.address = c.Address
		if c.Browser == "" {
			a.slots = append(a.slots, slot{"a\x00" + c.Address, kindLock, l.MaxPerAddress, l.Window})
		}
	}
	switch {
	case c.Browser != "":
		a.own = "b\x00" + c.Browser + "\x00" + account
	case !c.Shared:
		a.own = "p\x00" + c.Address + "\x00" + account
	}
	if a.own != "" {
		a.slots = append(a.slots, slot{a.own, kindLock, l.Max, l.Window})
	}
	// Known browsers and known addresses each have MaxPerAccount guesses
	// per SlowWindow; past that they count as strangers.
	budget := ""
	switch {
	case c.Browser != "":
		budget = "k\x00" + account
	case !c.Shared && l.knownLocked(c.Address, account, c.Version, now):
		budget = "n\x00" + account
	}
	if b := l.buckets[budget]; budget != "" && b != nil && l.MaxPerAccount > 0 && len(b.recent(now))+b.pending >= l.MaxPerAccount {
		budget = ""
	}
	if budget != "" {
		a.slots = append(a.slots, slot{budget, kindKnown, l.MaxPerAccount, l.SlowWindow})
	} else {
		a.slots = append(a.slots, slot{"u\x00" + account, kindSlow, l.MaxPerAccount, l.SlowWindow})
	}

	var refused *Refusal
	refuse := func(wait time.Duration, reason string) {
		if refused == nil || wait > refused.Wait {
			refused = &Refusal{Wait: wait, Reason: reason}
		}
	}
	for _, s := range a.slots {
		b, ok := l.buckets[s.key]
		if !ok || s.limit <= 0 {
			continue
		}
		n := len(b.recent(now))
		switch s.kind {
		case kindLock:
			if w := b.lockedUntil.Sub(now); w > 0 {
				refuse(w, ReasonLocked)
			} else if n+b.pending >= s.limit {
				refuse(Busy, ReasonBusy)
			}
		case kindSlow:
			if n+b.pending < s.limit {
				continue
			}
			if b.pending > 0 {
				// Once slowed, one try at a time.
				refuse(Busy, ReasonBusy)
			} else if w := b.failures[n-1].Add(l.slowWait(n)).Sub(now); w > 0 {
				refuse(w, ReasonSlowed)
			}
		}
	}
	if refused != nil {
		return nil, refused
	}
	for _, s := range a.slots {
		b, ok := l.buckets[s.key]
		if !ok {
			b = &bucket{window: s.window}
			l.buckets[s.key] = b
		}
		b.pending++
	}
	return a, nil
}

// slowWait is how long a stranger waits after the n-th failure counted for
// an account (n >= MaxPerAccount).
func (l *Limiter) slowWait(n int) time.Duration {
	steps := min(max(n-l.MaxPerAccount, 0), 30)
	w := slowStart << steps
	if l.MaxSlow > 0 && w > l.MaxSlow {
		w = l.MaxSlow
	}
	return w
}

// knownLocked reports whether account was signed in to from address
// within KnownFor, with the password version stands for; the caller
// holds l.mu.
func (l *Limiter) knownLocked(address, account, version string, now time.Time) bool {
	t, ok := l.known[knownKey(address, account, version)]
	return ok && now.Sub(t) < l.KnownFor
}

// knownKey is the key of l.known for an address, account and password
// version.
func knownKey(address, account, version string) string {
	return address + "\x00" + account + "\x00" + version
}

// endLocked releases the attempt's place and reports whether it was
// still open; the caller holds l.mu.
func (a *Attempt) endLocked() bool {
	if a == nil || a.done {
		return false
	}
	a.done = true
	for _, s := range a.slots {
		if b, ok := a.l.buckets[s.key]; ok && b.pending > 0 {
			b.pending--
		}
	}
	return true
}

// Fail records a wrong password and says what it led to.
func (a *Attempt) Fail() Failure {
	var f Failure
	if a == nil {
		return f
	}
	l := a.l
	now := l.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !a.endLocked() {
		return f
	}
	for _, s := range a.slots {
		b := l.buckets[s.key]
		if b == nil {
			b = &bucket{window: s.window}
			l.buckets[s.key] = b
		}
		b.failures = append(b.recent(now), now)
		if s.limit <= 0 {
			continue
		}
		switch n := len(b.failures); {
		case s.kind == kindLock && n >= s.limit:
			b.lockedUntil = now.Add(l.Lockout)
			b.failures = nil
			f.Locked = true
			f.AddressLocked = f.AddressLocked || strings.HasPrefix(s.key, "a\x00")
		case s.kind == kindSlow && n >= s.limit:
			f.Slowed = l.slowWait(n)
		}
	}
	return f
}

// Succeed ends an attempt with the right password. It clears the failures
// of this address (or browser) and account only, and from then on the
// address is known for the account while its password stays the same,
// unless the address is shared.
func (a *Attempt) Succeed() {
	if a == nil {
		return
	}
	l := a.l
	now := l.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !a.endLocked() {
		return
	}
	if b, ok := l.buckets[a.own]; ok && a.own != "" {
		b.failures = nil
		if b.pending == 0 && b.lockedUntil.IsZero() {
			delete(l.buckets, a.own)
		}
	}
	if a.address == "" {
		return
	}
	if l.known == nil {
		l.known = map[string]time.Time{}
	}
	if len(l.known) >= 50000 {
		for k, t := range l.known {
			if now.Sub(t) >= l.KnownFor {
				delete(l.known, k)
			}
		}
		// Still full: forget some, so the newest is always kept.
		for k := range l.known {
			if len(l.known) < 45000 {
				break
			}
			delete(l.known, k)
		}
	}
	l.known[knownKey(a.address, a.account, a.version)] = now
}

// Done ends an attempt that neither failed nor succeeded, such as one the
// directory could not answer.
func (a *Attempt) Done() {
	if a == nil {
		return
	}
	a.l.mu.Lock()
	defer a.l.mu.Unlock()
	a.endLocked()
}

// recent returns the failures still inside the bucket's window.
func (b *bucket) recent(now time.Time) []time.Time {
	keep := b.failures[:0]
	for _, t := range b.failures {
		if now.Sub(t) < b.window {
			keep = append(keep, t)
		}
	}
	b.failures = keep
	return keep
}

func (l *Limiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.pending == 0 && len(b.recent(now)) == 0 && !now.Before(b.lockedUntil) {
			delete(l.buckets, k)
		}
	}
}
