package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// Turning the app off: a set-up never confirmed stops without a code; a
// confirmed one needs a code from the app or a recovery code, a wrong
// one refused. An admin resets someone else's, never their own.
func TestMFAOffAndReset(t *testing.T) {
	ts, s := newUsersServer(t, nil)
	if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "ann", Role: users.Admin, Password: "Harbor-maple-63"}); err != nil {
		t.Fatal(err)
	}
	_, _, ann := login(t, ts, "ann", "Harbor-maple-63")
	off := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "POST", "/api/me/mfa/off", body, "", "", ann)
		return code, out
	}
	if code, _ := off(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, _, raw := call(t, ts, "POST", "/api/me/mfa/setup", "{}", "", "", ann); code != http.StatusOK {
		t.Fatalf("setup: %d %s", code, raw)
	}
	if code, out := off(`{}`); code != http.StatusOK || out["mfa"].(map[string]any)["on"] != false {
		t.Errorf("stop an unconfirmed set-up: %d %v", code, out)
	}

	_, codes := setUpMFA(t, ts, ann)
	if code, out := off(`{"code":"000000"}`); code != http.StatusBadRequest || out["code"] != "mfa_wrong" {
		t.Errorf("wrong code: %d %v", code, out)
	}
	if code, out := off(`{"passkey":{"token":"x"}}`); code < 400 || code >= 500 {
		t.Errorf("a passkey answer that is not one: %d %v", code, out)
	}
	if code, out := off(`{"code":"` + codes[0] + `"}`); code != http.StatusOK || out["mfa"].(map[string]any)["on"] != false {
		t.Errorf("recovery code: %d %v", code, out)
	}
	if s.Users.MFAOn("ann") {
		t.Error("two-step sign-in still on")
	}

	reset := func(name string) int {
		t.Helper()
		code, _, _ := call(t, ts, "DELETE", "/api/users/"+name+"/mfa", "", "", "", ann)
		return code
	}
	if code := reset("ann"); code != http.StatusConflict {
		t.Errorf("own: %d", code)
	}
	if code := reset("nobody"); code != http.StatusNotFound {
		t.Errorf("unknown: %d", code)
	}
	code, out, _ := call(t, ts, "DELETE", "/api/users/admin/mfa", "", "", "", ann)
	if code != http.StatusOK || !strings.EqualFold(out["username"].(string), "admin") || out["mfa"] != false {
		t.Errorf("built-in admin: %d %v", code, out)
	}
}
