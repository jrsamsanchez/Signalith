package api

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// The recheck refuses what it cannot check, answers requests that sent
// the password themselves at once, and stops taking guesses once the
// sign-in limits lock the account.
func TestRecheckEdges(t *testing.T) {
	var back atomic.Int64
	ts, s := newUsersServer(t, func(s *Server) {
		s.Sessions = auth.NewSessions(12 * time.Hour)
		s.Sessions.Now = func() time.Time { return time.Now().Add(-time.Duration(back.Load())) }
	})
	if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "ann", Role: users.Admin, Password: "Harbor-maple-63"}); err != nil {
		t.Fatal(err)
	}
	// HTTP Basic sent the password with the request.
	if code, out, _ := call(t, ts, "POST", "/api/me/recheck", `{}`, "ann", "Harbor-maple-63", nil); code != http.StatusOK || out["minutes"] != float64(auth.RecheckAge.Minutes()) {
		t.Errorf("basic: %d %v", code, out)
	}
	back.Store(int64(20 * time.Minute))
	_, _, old := login(t, ts, "ann", "Harbor-maple-63")
	back.Store(0)
	if code, _, _ := callWith(t, ts.URL, "POST", "/api/me/recheck", `{`, old); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/me/recheck", `{"code":"  "}`, old); code != http.StatusBadRequest || out["error"] != "Enter your password." {
		t.Errorf("nothing entered: %d %v", code, out)
	}
	// A two-step code from a user without two-step sign-in is a wrong
	// guess.
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/me/recheck", `{"code":"123456"}`, old); code != http.StatusBadRequest || out["code"] != "mfa_wrong" {
		t.Errorf("code without two-step: %d %v", code, out)
	}
	// A passkey answer that is not one is refused.
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/me/recheck", `{"passkey":{"id":"bm9wZQ"}}`, old); code < 400 || code >= 500 {
		t.Errorf("bogus passkey: %d %v", code, out)
	}
	// Wrong passwords lock the account for a while: then even the right
	// one is refused, 429 with when to try again.
	var code int
	var out map[string]any
	for i := 0; i < 30; i++ {
		if code, out, _ = callWith(t, ts.URL, "POST", "/api/me/recheck", `{"password":"nope"}`, old); code == http.StatusTooManyRequests {
			break
		}
	}
	if code != http.StatusTooManyRequests || out["code"] != "locked_out" {
		t.Fatalf("after many wrong passwords: %d %v", code, out)
	}
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/me/recheck", `{"password":"Harbor-maple-63"}`, old); code != http.StatusTooManyRequests {
		t.Errorf("right password while locked: %d %v", code, out)
	}
}
