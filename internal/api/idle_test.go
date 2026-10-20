// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
)

// TestBackgroundRequestsDoNotKeepSessionAlive: an open tab's timers mark
// their requests as background, so a tab that only polls still signs out
// at the idle timeout, while one that is used stays signed in.
func TestBackgroundRequestsDoNotKeepSessionAlive(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	ts, _ := newUsersServer(t, func(s *Server) {
		s.Sessions = auth.NewSessions(5 * time.Minute)
		s.Sessions.Now = clock
	})
	get := func(c *http.Cookie, bg bool) int {
		t.Helper()
		req, _ := http.NewRequest("GET", ts.URL+"/api/health", nil)
		req.AddCookie(c)
		if bg {
			req.Header.Set(backgroundHeader, "1")
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	_, _, polled := login(t, ts, "admin", adminPass)
	_, _, used := login(t, ts, "admin", adminPass)
	if polled == nil || used == nil {
		t.Fatal("no session cookie")
	}
	for elapsed := 30 * time.Second; elapsed <= 6*time.Minute+30*time.Second; elapsed += 30 * time.Second {
		advance(30 * time.Second)
		code := get(polled, true)
		if elapsed < 5*time.Minute && code != 200 {
			t.Fatalf("polling session refused after %v: %d", elapsed, code)
		}
		if elapsed >= 5*time.Minute && code != 401 {
			t.Fatalf("polling-only session still valid after %v (idle timeout 5m): %d", elapsed, code)
		}
		if code := get(used, false); code != 200 {
			t.Fatalf("session in use refused after %v: %d", elapsed, code)
		}
	}
}
