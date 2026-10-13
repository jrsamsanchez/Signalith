// Package auth keeps sign-in sessions for the web UI and limits password
// guessing. Sessions live in memory: a restart from the Settings page keeps
// them, but stopping the server signs everyone out; API clients can keep
// using HTTP Basic auth.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"strings"
	"sync"
	"time"
)

// Session is one signed-in browser.
type Session struct {
	User     string
	Created  time.Time
	LastSeen time.Time
	// Remember keeps the session through idle periods up to MaxAge, for a
	// "keep me signed in" sign-in.
	Remember bool
	// Version identifies the password the user signed in with ("" when
	// there is none to follow), so a session can end when the password
	// changes on another server that shares the users file.
	Version string
}

// Sessions stores sessions by a hash of their token, so the tokens
// themselves are never kept.
type Sessions struct {
	// Idle ends a session after this long without a request.
	Idle time.Duration
	// MaxAge ends any session this long after sign-in.
	MaxAge time.Duration
	// Limit bounds how many sessions are kept; the least recently used go
	// first.
	Limit int
	Now   func() time.Time

	mu   sync.Mutex
	byID map[[32]byte]*Session
}

// NewSessions returns a store with the given idle timeout and a 7 day
// maximum age.
func NewSessions(idle time.Duration) *Sessions {
	return &Sessions{Idle: idle, MaxAge: 7 * 24 * time.Hour, Limit: 10000, Now: time.Now, byID: map[[32]byte]*Session{}}
}

func hash(token string) [32]byte { return sha256.Sum256([]byte(token)) }

// Create starts a session and returns its token.
func (s *Sessions) Create(user string, remember bool) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if len(s.byID) >= s.Limit {
		s.evictLocked(len(s.byID) - s.Limit + 1)
	}
	s.byID[hash(token)] = &Session{User: user, Created: now, LastSeen: now, Remember: remember}
	return token
}

// Lookup returns the session for a token and marks it used. Expired
// sessions are removed and not returned.
func (s *Sessions) Lookup(token string) (Session, bool) {
	return s.lookup(token, true)
}

// Peek returns the session for a token like Lookup, but does not mark it
// used: for requests a page makes on its own, such as a refresh every
// 30 seconds, which must not keep an unattended browser signed in past
// the idle timeout.
func (s *Sessions) Peek(token string) (Session, bool) {
	return s.lookup(token, false)
}

func (s *Sessions) lookup(token string, used bool) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	id := hash(token)
	ss, ok := s.byID[id]
	if !ok {
		return Session{}, false
	}
	if s.expired(ss, now) {
		delete(s.byID, id)
		return Session{}, false
	}
	if used {
		ss.LastSeen = now
	}
	return *ss, true
}

// SetIdle changes how long a session lasts without a request, for every
// session, the current ones included.
func (s *Sessions) SetIdle(idle time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Idle = idle
}

// SetVersion records which password a session's user has now (see
// Session.Version).
func (s *Sessions) SetVersion(token, version string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss, ok := s.byID[hash(token)]; ok {
		ss.Version = version
	}
}

// Delete ends a session.
func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, hash(token))
}

// EndUser ends every session of a user except the one with token keep
// ("" keeps none), and reports how many ended. Usernames ignore case.
func (s *Sessions) EndUser(user, keep string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	keepID := hash(keep)
	n := 0
	for id, ss := range s.byID {
		if strings.EqualFold(ss.User, user) && (keep == "" || id != keepID) {
			delete(s.byID, id)
			n++
		}
	}
	return n
}

// Users lists the users with a session that has not expired, each once,
// in lower case.
func (s *Sessions) Users() []string {
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	out := []string{}
	for _, ss := range s.byID {
		u := strings.ToLower(ss.User)
		if !s.expired(ss, now) && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	sort.Strings(out)
	return out
}

// Len reports how many sessions are stored.
func (s *Sessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}

func (s *Sessions) expired(ss *Session, now time.Time) bool {
	if now.Sub(ss.Created) >= s.MaxAge {
		return true
	}
	return !ss.Remember && now.Sub(ss.LastSeen) >= s.Idle
}

func (s *Sessions) pruneLocked(now time.Time) {
	for id, ss := range s.byID {
		if s.expired(ss, now) {
			delete(s.byID, id)
		}
	}
}

func (s *Sessions) evictLocked(n int) {
	type entry struct {
		id   [32]byte
		seen time.Time
	}
	all := make([]entry, 0, len(s.byID))
	for id, ss := range s.byID {
		all = append(all, entry{id, ss.LastSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen.Before(all[j].seen) })
	for _, e := range all[:min(n, len(all))] {
		delete(s.byID, e.id)
	}
}

// Limiter slows password guessing. It counts failed sign-ins three ways,
// each within Window, and a count that reaches its limit locks for Lockout:
//
//   - per address and account: Max failures lock that account for that
//     address;
//   - per address: MaxPerAddress failures, whatever the accounts, lock the
//     address (one address trying many accounts);
//   - per account: MaxPerAccount failures, from any address, lock the
//     account everywhere (many addresses guessing one account). It is above
//     Max, so one address alone cannot lock someone else out.
//
// A successful sign-in clears only its own address-and-account count, so
// signing in to one account never helps guess another. Attempts still being
// checked count too, so parallel requests cannot all slip in before the
// first failure is recorded.
type Limiter struct {
	Max           int
	MaxPerAddress int
	MaxPerAccount int
	Window        time.Duration
	Lockout       time.Duration
	Now           func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	failures    []time.Time
	pending     int
	lockedUntil time.Time
}

// NewLimiter allows 10 failures per address and account, 30 per address
// and 30 per account within 15 minutes, then refuses for 15 minutes.
func NewLimiter() *Limiter {
	return &Limiter{Max: 10, MaxPerAddress: 30, MaxPerAccount: 30, Window: 15 * time.Minute, Lockout: 15 * time.Minute,
		Now: time.Now, buckets: map[string]*bucket{}}
}

// Attempt is one sign-in being checked. End it with exactly one of Fail,
// Succeed or Done.
type Attempt struct {
	l    *Limiter
	keys [3]string
	pair string
	done bool
}

// Busy is the wait Begin reports when the limit is only reached by attempts
// still being checked: the client should try again in a moment.
const Busy = 5 * time.Second

// Begin starts an attempt to sign in to account from client, or reports
// how long until one is allowed. Account names ignore case and spacing.
func (l *Limiter) Begin(client, account string) (*Attempt, bool, time.Duration) {
	account = strings.ToLower(strings.TrimSpace(account))
	pair := "p\x00" + client + "\x00" + account
	keys := [3]string{pair, "a\x00" + client, "u\x00" + account}
	limits := [3]int{l.Max, l.MaxPerAddress, l.MaxPerAccount}
	now := l.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]*bucket{}
	}
	if len(l.buckets) > 50000 {
		l.pruneLocked(now)
	}
	var wait time.Duration
	for i, k := range keys {
		b, ok := l.buckets[k]
		if !ok {
			continue
		}
		if w := b.lockedUntil.Sub(now); w > 0 {
			wait = max(wait, w)
			continue
		}
		if limits[i] > 0 && len(b.recent(now, l.Window))+b.pending >= limits[i] {
			wait = max(wait, Busy)
		}
	}
	if wait > 0 {
		return nil, false, wait
	}
	for _, k := range keys {
		b, ok := l.buckets[k]
		if !ok {
			b = &bucket{}
			l.buckets[k] = b
		}
		b.pending++
	}
	return &Attempt{l: l, keys: keys, pair: pair}, true, 0
}

// endLocked releases the attempt's place and reports whether it was
// still open; the caller holds l.mu.
func (a *Attempt) endLocked() bool {
	if a == nil || a.done {
		return false
	}
	a.done = true
	for _, k := range a.keys {
		if b, ok := a.l.buckets[k]; ok && b.pending > 0 {
			b.pending--
		}
	}
	return true
}

// Fail records a wrong password and reports whether this locked out the
// account, the address, or both.
func (a *Attempt) Fail() bool {
	if a == nil {
		return false
	}
	l := a.l
	now := l.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !a.endLocked() {
		return false
	}
	limits := [3]int{l.Max, l.MaxPerAddress, l.MaxPerAccount}
	locked := false
	for i, k := range a.keys {
		b := l.buckets[k]
		if b == nil {
			b = &bucket{}
			l.buckets[k] = b
		}
		b.failures = append(b.recent(now, l.Window), now)
		if limits[i] > 0 && len(b.failures) >= limits[i] {
			b.lockedUntil = now.Add(l.Lockout)
			b.failures = nil
			locked = true
		}
	}
	return locked
}

// Succeed ends an attempt with the right password. It clears the failures
// of this address and account only.
func (a *Attempt) Succeed() {
	if a == nil {
		return
	}
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if !a.endLocked() {
		return
	}
	if b, ok := l.buckets[a.pair]; ok {
		b.failures = nil
		if b.pending == 0 && b.lockedUntil.IsZero() {
			delete(l.buckets, a.pair)
		}
	}
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

// recent returns the failures still inside the window.
func (b *bucket) recent(now time.Time, window time.Duration) []time.Time {
	keep := b.failures[:0]
	for _, t := range b.failures {
		if now.Sub(t) < window {
			keep = append(keep, t)
		}
	}
	b.failures = keep
	return keep
}

func (l *Limiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.pending == 0 && len(b.recent(now, l.Window)) == 0 && !now.Before(b.lockedUntil) {
			delete(l.buckets, k)
		}
	}
}
