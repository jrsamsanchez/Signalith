package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// With shared users, turning two-step sign-in on ends the user's other
// sessions and this one too, and the browser gets a new session in its
// place.
func TestMFAOnRenewsSharedSession(t *testing.T) {
	c := newMemberCluster(t, nil)
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	if code, out, _ := c.a.call("POST", "/api/users", `{"username":"jlee","password":"first-password-1","role":"analyst"}`, admin, nil); code != http.StatusCreated {
		t.Fatalf("add jlee: %d %v", code, out)
	}
	mine, _ := c.a.signIn("jlee", "first-password-1")
	other, _ := c.a.signIn("jlee", "first-password-1")
	if mine == nil || other == nil {
		t.Fatal("jlee cannot sign in")
	}
	code, out, _ := c.a.call("POST", "/api/me/mfa/setup", "{}", mine, nil)
	if code != http.StatusOK {
		t.Fatalf("setup: %d %v", code, out)
	}
	now, _ := users.TOTP(strings.ReplaceAll(out["secret"].(string), " ", ""), time.Now())
	code, out, resp := c.a.call("POST", "/api/me/mfa/confirm", `{"code":"`+now+`"}`, mine, nil)
	if code != http.StatusOK || out["recovery_codes"] == nil {
		t.Fatalf("confirm: %d %v", code, out)
	}
	var fresh *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie && ck.Value != "" {
			fresh = ck
		}
	}
	if fresh == nil || fresh.Value == mine.Value {
		t.Fatal("no new session cookie")
	}
	if got := c.a.me(fresh); got != http.StatusOK {
		t.Errorf("the new session: %d", got)
	}
	for name, ck := range map[string]*http.Cookie{"the old session": mine, "the other session": other} {
		if got := c.a.me(ck); got != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, got)
		}
	}
}
