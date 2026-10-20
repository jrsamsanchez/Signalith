// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestSessions(t *testing.T) {
	c := &clock{time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)}
	s := NewSessions(time.Hour)
	s.Now = c.now
	tok := s.Create("admin", false)
	if len(tok) < 40 {
		t.Fatalf("token %q is too short", tok)
	}
	if ss, ok := s.Lookup(tok); !ok || ss.User != "admin" {
		t.Fatalf("lookup = %v %v", ss, ok)
	}
	if _, ok := s.Lookup(tok + "x"); ok {
		t.Error("a wrong token was accepted")
	}
	// Use keeps the session alive; an hour idle ends it.
	c.t = c.t.Add(50 * time.Minute)
	if _, ok := s.Lookup(tok); !ok {
		t.Fatal("session ended while in use")
	}
	c.t = c.t.Add(61 * time.Minute)
	if _, ok := s.Lookup(tok); ok || s.Len() != 0 {
		t.Error("idle session still valid")
	}

	// A remembered session survives idle time but not the maximum age,
	// 24 hours by default.
	if s.MaxAge != 24*time.Hour {
		t.Errorf("default max age %v", s.MaxAge)
	}
	keep := s.Create("admin", true)
	c.t = c.t.Add(20 * time.Hour)
	if _, ok := s.Lookup(keep); !ok {
		t.Error("remembered session ended while idle")
	}
	c.t = c.t.Add(4 * time.Hour)
	if _, ok := s.Lookup(keep); ok {
		t.Error("remembered session outlived MaxAge")
	}

	other := s.Create("admin", false)
	s.Delete(other)
	if _, ok := s.Lookup(other); ok {
		t.Error("deleted session still valid")
	}
}

// SetMaxAge applies to the sessions there are already, remembered or not,
// and a session in use still ends at the maximum age.
func TestSetMaxAge(t *testing.T) {
	c := &clock{time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)}
	s := NewSessions(time.Hour)
	s.Now = c.now
	keep := s.Create("admin", true)
	used := s.Create("admin", false)
	s.SetMaxAge(2 * time.Hour)
	if s.MaxAgeNow() != 2*time.Hour {
		t.Fatalf("max age %v", s.MaxAgeNow())
	}
	for range 3 {
		c.t = c.t.Add(30 * time.Minute)
		if _, ok := s.Lookup(used); !ok {
			t.Fatal("session in use ended before the maximum age")
		}
	}
	c.t = c.t.Add(30 * time.Minute)
	if _, ok := s.Lookup(used); ok {
		t.Error("session in use outlived the maximum age")
	}
	if _, ok := s.Lookup(keep); ok {
		t.Error("remembered session outlived the maximum age")
	}
}

func TestSessionLimitEvictsLeastRecentlyUsed(t *testing.T) {
	c := &clock{time.Now()}
	s := NewSessions(time.Hour)
	s.Now, s.Limit = c.now, 2
	a := s.Create("admin", false)
	c.t = c.t.Add(time.Second)
	b := s.Create("admin", false)
	c.t = c.t.Add(time.Second)
	s.Lookup(a)
	c.t = c.t.Add(time.Second)
	s.Create("admin", false)
	if _, ok := s.Lookup(b); ok {
		t.Error("least recently used session was kept")
	}
	if _, ok := s.Lookup(a); !ok {
		t.Error("recently used session was evicted")
	}
}

func TestEndUser(t *testing.T) {
	s := NewSessions(time.Hour)
	a1, a2 := s.Create("ann", false), s.Create("ann", true)
	b := s.Create("ben", false)
	if n := s.EndUser("ANN", a2); n != 1 {
		t.Errorf("ended %d", n)
	}
	if _, ok := s.Lookup(a1); ok {
		t.Error("other session of ann survived")
	}
	if _, ok := s.Lookup(a2); !ok {
		t.Error("kept session ended")
	}
	if got := s.Users(); len(got) != 2 || got[0] != "ann" || got[1] != "ben" {
		t.Errorf("users = %v", got)
	}
	if n := s.EndUser("ann", ""); n != 1 {
		t.Errorf("ended %d", n)
	}
	if _, ok := s.Lookup(b); !ok {
		t.Error("ben's session ended")
	}
}

// TestPeekDoesNotKeepSessionAlive: a page's own refreshes (Peek) see the
// session but do not count as use, so a tab that only polls signs out at
// the idle timeout.
func TestPeekDoesNotKeepSessionAlive(t *testing.T) {
	c := &clock{time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)}
	s := NewSessions(5 * time.Minute)
	s.Now = c.now
	tok := s.Create("admin", false)
	for i := 0; i < 9; i++ { // every 30 seconds for 4.5 minutes
		c.t = c.t.Add(30 * time.Second)
		if _, ok := s.Peek(tok); !ok {
			t.Fatalf("session ended after %v of polling", time.Duration(i+1)*30*time.Second)
		}
	}
	c.t = c.t.Add(30 * time.Second)
	if _, ok := s.Peek(tok); ok {
		t.Fatal("a session that only polled outlived the idle timeout")
	}
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("expired session still usable")
	}
}

func TestForward(t *testing.T) {
	s := NewSessions(time.Hour)
	before := s.Start(NewSession{User: "admin"})
	var got []Held
	s.Forward(func(h Held) { got = append(got, h) })
	after := s.Start(NewSession{User: "jlee", Method: "local"})
	if len(got) != 1 || got[0].User != "jlee" || got[0].Hash != hash(after) || got[0].Method != "local" {
		t.Fatalf("forwarded %+v", got)
	}
	if _, ok := s.Lookup(after); ok {
		t.Error("a forwarded session is kept here too")
	}
	if held := s.Take(); len(held) != 1 || held[0].Hash != hash(before) {
		t.Errorf("taken %+v", held)
	}
	s.Forward(nil)
	again := s.Start(NewSession{User: "kim"})
	if _, ok := s.Lookup(again); !ok || len(got) != 1 {
		t.Error("a session started after Forward(nil) is not kept")
	}
}
