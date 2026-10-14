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
	// Epoch is the user's session epoch at sign-in (users.User.
	// SessionEpoch): a session made in an older epoch has ended.
	Epoch int64
	// Method is how the user signed in: local, directory or builtin.
	Method string
	// Degraded marks a session made while OpenSearch could not be
	// reached, kept by one server only until it can be written through.
	Degraded bool
}

// NewSession is what a session starts with.
type NewSession struct {
	User     string
	Remember bool
	// Version, Epoch and Method are as in Session.
	Version string
	Epoch   int64
	Method  string
	// Client is the address the user signed in from.
	Client string
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
	return s.Start(NewSession{User: user, Remember: remember})
}

// Start starts the session n and returns its token.
func (s *Sessions) Start(n NewSession) string {
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
	s.byID[hash(token)] = &Session{User: n.User, Created: now, LastSeen: now, Remember: n.Remember, Version: n.Version, Epoch: n.Epoch, Method: n.Method}
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
