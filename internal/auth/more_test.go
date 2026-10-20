// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionSettersAndExpiry(t *testing.T) {
	c := &clock{time.Now()}
	s := NewSessions(time.Hour)
	s.Now = c.now
	if _, ok := s.Lookup(""); ok {
		t.Error("an empty token was found")
	}
	tok := s.Create("alice", false)
	s.SetVersion("", "v0")
	s.SetVersion(tok, "v2")
	s.SetVersion("other", "v3")
	if s.SetTenant("", "acme") || s.SetTenant("other", "acme") || !s.SetTenant(tok, "acme") {
		t.Error("SetTenant answers")
	}
	ss, ok := s.Peek(tok)
	if !ok || ss.Version != "v2" || ss.Tenant != "acme" {
		t.Errorf("session = %+v %v", ss, ok)
	}
	// A shorter idle time applies to the sessions already there.
	s.SetIdle(time.Minute)
	c.t = c.t.Add(2 * time.Minute)
	if _, ok := s.Lookup(tok); ok {
		t.Error("an idle session lasted")
	}
	// Starting a session removes the expired ones.
	old := s.Create("bob", false)
	c.t = c.t.Add(2 * time.Minute)
	s.Create("carol", false)
	if s.Len() != 1 {
		t.Errorf("Len = %d", s.Len())
	}
	if _, ok := s.Peek(old); ok {
		t.Error("an expired session was kept")
	}
}

func TestLimiterOddCalls(t *testing.T) {
	var a *Attempt
	if f := a.Fail(); f != (Failure{}) {
		t.Errorf("nil Fail = %+v", f)
	}
	a.Succeed()
	a.Done()

	l := NewLimiter()
	at, err := l.Begin(addr("10.0.0.1"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	at.Fail()
	// Ending an attempt twice counts once.
	if f := at.Fail(); f != (Failure{}) {
		t.Errorf("second Fail = %+v", f)
	}
	at.Succeed()
	at, _ = l.Begin(addr("10.0.0.2"), "admin")
	at.Succeed()
	at.Succeed()

	r := &Refusal{Wait: 90*time.Second + 400*time.Millisecond, Reason: ReasonLocked}
	if got := r.Error(); got != fmt.Sprintf("sign-in refused (%s) for 1m30s", ReasonLocked) {
		t.Errorf("Error = %q", got)
	}
	if scopeOf("s\x00x") != ScopeSlow || scopeOf("a\x00x") != ScopeAddress {
		t.Error("scopeOf")
	}
	plain, keyed := LockKey(nil, "a\x0010.0.0.1"), LockKey([]byte("cluster secret"), "a\x0010.0.0.1")
	if plain == keyed || len(keyed) != 64 || strings.Contains(keyed, "10.0.0.1") {
		t.Errorf("keys %s %s", plain, keyed)
	}
	// A lock another server reports is keyed with the shared secret and
	// cut to this limiter's longest.
	l.SetLockSecret([]byte("cluster secret"))
	far := map[string]time.Time{keyed: time.Now().Add(24 * time.Hour)}
	l.External(far)
	if !far[keyed].Before(time.Now().Add(l.longestLock() + time.Minute)) {
		t.Errorf("lock not cut: %v", far[keyed])
	}
	if ok, rf := allowed(l, addr("10.0.0.1"), "anyone"); ok || rf.Reason != ReasonLocked {
		t.Errorf("external lock = %v %+v", ok, rf)
	}
}

func TestLimiterBounds(t *testing.T) {
	c := &clock{time.Now()}
	l := NewLimiter()
	l.Now = c.now
	// Too many buckets: those with nothing left in them go.
	l.mu.Lock()
	for i := range 50001 {
		l.buckets[fmt.Sprintf("a\x00old%d", i)] = &bucket{window: time.Minute, failures: []time.Time{c.t.Add(-time.Hour)}}
	}
	l.buckets["a\x00busy"] = &bucket{window: time.Hour, failures: []time.Time{c.t}}
	l.mu.Unlock()
	if ok, _ := allowed(l, addr("10.0.0.9"), "admin"); !ok {
		t.Fatal("refused")
	}
	l.mu.Lock()
	n, busy := len(l.buckets), l.buckets["a\x00busy"] != nil
	l.mu.Unlock()
	if n > 10 || !busy {
		t.Errorf("buckets after pruning = %d, busy kept %v", n, busy)
	}

	// Too many known addresses: old ones go, then enough others, and the
	// newest is kept.
	l.mu.Lock()
	for i := range 50000 {
		at := c.t
		if i%2 == 0 {
			at = c.t.Add(-2 * l.KnownFor)
		}
		l.known[fmt.Sprintf("k%d", i)] = at
	}
	l.mu.Unlock()
	succeed(t, l, addr("10.0.0.10"), "admin")
	l.mu.Lock()
	n = len(l.known)
	_, kept := l.known[knownKey("10.0.0.10", "admin", "")]
	l.mu.Unlock()
	if n > 45001 || !kept {
		t.Errorf("known after pruning = %d, newest kept %v", n, kept)
	}
}

func TestBrowserKeyOddInputs(t *testing.T) {
	k := NewBrowserKey()
	now := time.Now()
	good := k.Issue("admin", "v", now)
	// The right length, but not base64.
	bad := browserPrefix + strings.Repeat("*", len(good)-len(browserPrefix))
	if _, ok := k.Check("admin", "v", bad, now); ok {
		t.Error("a value that is not base64 was taken")
	}
	rc := k.IssueRecheck("admin", "sess", now)
	if k.CheckRecheck("admin", "sess", recheckPrefix+strings.Repeat("*", len(rc)-len(recheckPrefix)), now) {
		t.Error("a recheck value that is not base64 was taken")
	}
	m1, m2 := k.MAC("sso", []byte("state")), k.MAC("other", []byte("state"))
	if bytes.Equal(m1, m2) || !bytes.Equal(m1, k.MAC("sso", []byte("state"))) || len(m1) != 32 {
		t.Error("MAC")
	}

	dir := t.TempDir()
	if _, _, err := LoadBrowserKey(dir); err == nil {
		t.Error("a folder was read as the key")
	}
	blocker := filepath.Join(dir, "blocker")
	os.WriteFile(blocker, nil, 0o600)
	if _, _, err := LoadBrowserKey(filepath.Join(blocker, "signin.key")); err == nil {
		t.Error("made a key under a file")
	}
}
