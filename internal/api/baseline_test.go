package api

import (
	"strings"
	"testing"
	"time"
)

// auth.session_max_age applies at once to the sessions there are, and a
// remembered session's cookie lasts no longer than it.
func TestSessionMaxAgeIsLive(t *testing.T) {
	ts, srv, _ := newSettingsServer(t, "server:\n  listen: 127.0.0.1:8080\n  tls:\n    mode: off\n", nil)
	if srv.sessions().MaxAge() != 24*time.Hour {
		t.Fatalf("default max age %v", srv.sessions().MaxAge())
	}
	code, out, _ := call(t, ts, "PUT", "/api/settings", `{"values":{"auth.session_max_age":"31d"}}`, "admin", "s3cret-pass", nil)
	if fields, _ := out["fields"].(map[string]any); code != 400 || !strings.Contains(fields["auth.session_max_age"].(string), "from 1h to 30d") {
		t.Fatalf("31d: %d %v", code, out)
	}
	code, out, _ = call(t, ts, "PUT", "/api/settings", `{"values":{"auth.session_max_age":"8h"}}`, "admin", "s3cret-pass", nil)
	if code != 200 || srv.sessions().MaxAge() != 8*time.Hour {
		t.Fatalf("8h: %d %v %v", code, out, srv.sessions().MaxAge())
	}
}

// New passwords on the Users page and from the user menu are checked
// against the common password list and the username.
func TestWeakNewPasswordsAreRefused(t *testing.T) {
	ts, _ := newUsersServer(t, nil)
	for body, want := range map[string]string{
		`{"username":"dana","role":"viewer","password":"password1"}`:     "on a list of commonly used passwords; choose another",
		`{"username":"dana","role":"viewer","password":"dana-is-here"}`:  "contains the username",
		`{"username":"dana","role":"viewer","password":"Signalith2026"}`: "signalith",
	} {
		code, out := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/users", body)
		if msg, _ := out["error"].(string); code != 400 || !strings.Contains(msg, want) || out["field"] != "password" {
			t.Errorf("%s: %d %v", body, code, out)
		}
	}
	code, out := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/users", `{"username":"dana","role":"viewer","password":"a-fine-pass-here","must_change_password":false}`)
	if code != 201 && code != 200 {
		t.Fatalf("add: %d %v", code, out)
	}
	code, out = doAs(t, ts, "dana", "a-fine-pass-here", "POST", "/api/me/password", `{"current_password":"a-fine-pass-here","new_password":"12345678"}`)
	if msg, _ := out["error"].(string); code != 400 || out["field"] != "new_password" || !strings.Contains(msg, "choose another") {
		t.Errorf("own change: %d %v", code, out)
	}
}
