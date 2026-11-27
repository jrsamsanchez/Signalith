// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// Passkeys are offered only where a browser accepts them: by name, over
// HTTPS or on localhost. A challenge for a user with no passkey, the
// removal of one they do not have, and a sign-in with an answer that is
// not a passkey's are each refused, and nothing changes.
func TestPasskeyRefusals(t *testing.T) {
	ts, s := newUsersServer(t, nil)
	if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "ann", Role: users.Analyst, Password: "Harbor-maple-63"}); err != nil {
		t.Fatal(err)
	}
	_, _, cs := pkCall(t, ts, "POST", "/api/login", map[string]any{"username": "ann", "password": "Harbor-maple-63"})
	ann := sessionOf(cs)
	if ann == nil {
		t.Fatal("no session")
	}
	for _, c := range []struct {
		host, method, path, body string
		status                   int
		code                     string
		want                     string
	}{
		{"siem.example.com", "POST", "/api/me/passkeys/options", "{}", 409, "passkey_unavailable", "only over HTTPS"},
		{"192.0.2.10", "POST", "/api/me/passkeys/challenge", "{}", 409, "passkey_unavailable", "not by an IP address"},
		{"localhost", "POST", "/api/me/passkeys/challenge", "{}", 409, "passkey_none", "no passkey"},
		{"localhost", "DELETE", "/api/me/passkeys/AAAAAAAA", "", 404, "passkey_unknown", ""},
		{"localhost", "POST", "/api/me/passkeys", `{`, 400, "", "must be JSON"},
	} {
		code, out, _ := pkCallAt(t, ts, c.host, c.method, c.path, c.body, ann)
		msg, _ := out["error"].(string)
		if code != c.status || (c.code != "" && out["code"] != c.code) || !strings.Contains(msg, c.want) {
			t.Errorf("%s %s at %s: %d %v", c.method, c.path, c.host, code, out)
		}
	}
	// Signing in with a passkey: the options only by name, and an answer
	// that is not a passkey's is refused.
	if code, out, _ := pkCallAt(t, ts, "192.0.2.10", "POST", "/api/login/passkey/options", "{}"); code != 409 {
		t.Errorf("login options by IP: %d %v", code, out)
	}
	code, opts, _ := pkCall(t, ts, "POST", "/api/login/passkey/options", "{}")
	if code != 200 || opts["token"] == "" {
		t.Fatalf("login options: %d %v", code, opts)
	}
	if code, out, cs := pkCall(t, ts, "POST", "/api/login/passkey", map[string]any{"token": opts["token"], "credential": map[string]any{"id": "x"}}); code < 400 || sessionOf(cs) != nil {
		t.Errorf("login with a bad answer: %d %v", code, out)
	}
	if code, _, _ := pkCall(t, ts, "POST", "/api/login/passkey", `{`); code != 400 {
		t.Errorf("login with bad JSON: %d", code)
	}
	if m, _ := s.Users.MFA("ann"); len(m.Passkeys) != 0 {
		t.Errorf("passkeys %v", m.Passkeys)
	}
}
