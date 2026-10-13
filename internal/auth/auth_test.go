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

	// A remembered session survives idle time but not the maximum age.
	keep := s.Create("admin", true)
	c.t = c.t.Add(3 * 24 * time.Hour)
	if _, ok := s.Lookup(keep); !ok {
		t.Error("remembered session ended while idle")
	}
	c.t = c.t.Add(5 * 24 * time.Hour)
	if _, ok := s.Lookup(keep); ok {
		t.Error("remembered session outlived MaxAge")
	}

	other := s.Create("admin", false)
	s.Delete(other)
	if _, ok := s.Lookup(other); ok {
		t.Error("deleted session still valid")
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
