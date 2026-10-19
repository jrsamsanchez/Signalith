// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// pkPost is a POST at localhost with extra headers.
func pkPost(t *testing.T, url, path, body string, header map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", url+path, strings.NewReader(body))
	req.Host = "localhost"
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Each way adding a passkey can go wrong is refused with what to do,
// and adds nothing.
func TestAddPasskeyRefusals(t *testing.T) {
	ts, s := newUsersServer(t, nil)
	if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "ann", Role: users.Admin, Password: "Harbor-maple-63"}); err != nil {
		t.Fatal(err)
	}
	_, _, cs := pkCall(t, ts, "POST", "/api/login", map[string]any{"username": "ann", "password": "Harbor-maple-63"})
	ann := sessionOf(cs)
	if ann == nil {
		t.Fatal("no session")
	}
	a := newAuthenticator(t)
	options := func() map[string]any {
		t.Helper()
		code, opts, _ := pkCall(t, ts, "POST", "/api/me/passkeys/options", "{}", ann)
		if code != http.StatusOK {
			t.Fatalf("options: %d %v", code, opts)
		}
		return opts
	}
	opts := options()
	cred, _ := a.create(opts)

	if code, _, _ := pkCall(t, ts, "POST", "/api/me/passkeys", "{", ann); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	// By IP address browsers make no passkeys.
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/me/passkeys", `{"token":"x"}`, ann); code != http.StatusConflict || out["code"] != "passkey_unavailable" {
		t.Errorf("by IP: %d %v", code, out)
	}
	for _, c := range []struct {
		body any
		want string
	}{
		{map[string]any{"token": "not-a-token", "credential": cred}, "That took too long"},
		{map[string]any{"token": opts["token"], "credential": strings.Repeat("x", passkeyAnswerMax+1)}, "too large"},
		{map[string]any{"token": opts["token"], "credential": map[string]any{"id": "x"}}, "could not be read"},
	} {
		code, out, _ := pkCall(t, ts, "POST", "/api/me/passkeys", c.body, ann)
		if msg, _ := out["error"].(string); code != http.StatusBadRequest || out["code"] != "passkey_wrong" || !strings.Contains(msg, c.want) {
			t.Errorf("want %q: %d %v", c.want, code, out)
		}
	}
	// A passkey made for another site does not check.
	a.origin = "http://evil.localhost"
	other, _ := a.create(opts)
	a.origin = "http://localhost"
	code, out, _ := pkCall(t, ts, "POST", "/api/me/passkeys", map[string]any{"token": opts["token"], "credential": other}, ann)
	if msg, _ := out["error"].(string); code != http.StatusBadRequest || !strings.Contains(msg, "could not be checked") {
		t.Errorf("other origin: %d %v", code, out)
	}
	if m, _ := s.Users.MFA("ann"); len(m.Passkeys) != 0 {
		t.Errorf("passkeys added: %v", m.Passkeys)
	}
}

// Signing in with a passkey alone is refused from another site, by IP
// address, and with answers that are not a passkey's; a disabled user's
// passkey signs nobody in.
func TestPasskeyLoginRefusals(t *testing.T) {
	ts, s := newUsersServer(t, nil)
	if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "ann", Role: users.Admin, Password: "Harbor-maple-63"}); err != nil {
		t.Fatal(err)
	}
	cross := map[string]string{"Sec-Fetch-Site": "cross-site"}
	for _, path := range []string{"/api/login/passkey/options", "/api/login/passkey"} {
		if code := pkPost(t, ts.URL, path, "{}", cross); code != http.StatusForbidden {
			t.Errorf("%s from another site: %d", path, code)
		}
	}
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/login/passkey/options", "{}"); code != http.StatusConflict || out["code"] != "passkey_unavailable" {
		t.Errorf("options by IP: %d %v", code, out)
	}
	if code, _, _ := pkCall(t, ts, "POST", "/api/login/passkey", "{"); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/login/passkey", `{"token":"x"}`); code != http.StatusUnauthorized || out["code"] != "passkey_wrong" {
		t.Errorf("by IP: %d %v", code, out)
	}
	_, lo, _ := pkCall(t, ts, "POST", "/api/login/passkey/options", "{}")
	if code, out, _ := pkCall(t, ts, "POST", "/api/login/passkey", map[string]any{"token": lo["token"], "credential": map[string]any{"id": "x"}}); code != http.StatusUnauthorized || out["code"] != "passkey_wrong" {
		t.Errorf("not an answer: %d %v", code, out)
	}

	// ann adds a passkey, then is turned off.
	_, _, cs := pkCall(t, ts, "POST", "/api/login", map[string]any{"username": "ann", "password": "Harbor-maple-63"})
	ann := sessionOf(cs)
	a := newAuthenticator(t)
	_, opts, _ := pkCall(t, ts, "POST", "/api/me/passkeys/options", "{}", ann)
	cred, key := a.create(opts)
	if code, out, _ := pkCall(t, ts, "POST", "/api/me/passkeys", map[string]any{"name": "Laptop", "token": opts["token"], "credential": cred}, ann); code != http.StatusOK {
		t.Fatalf("add: %d %v", code, out)
	}
	// A passkey of no account counts as a wrong guess.
	stranger := *key
	stranger.handle = []byte("no-such-account-handle")
	_, lo, _ = pkCall(t, ts, "POST", "/api/login/passkey/options", "{}")
	if code, out, _ := pkCall(t, ts, "POST", "/api/login/passkey", map[string]any{"token": lo["token"], "credential": a.get(lo, &stranger)}); code != http.StatusUnauthorized || out["code"] != "passkey_wrong" {
		t.Errorf("no account's passkey: %d %v", code, out)
	}
	key.count = stranger.count
	off := true
	if _, err := s.Users.Update(context.Background(), "ann", users.Change{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	_, lo, _ = pkCall(t, ts, "POST", "/api/login/passkey/options", "{}")
	code, out, cs := pkCall(t, ts, "POST", "/api/login/passkey", map[string]any{"token": lo["token"], "credential": a.get(lo, key)})
	if code == http.StatusOK || sessionOf(cs) != nil {
		t.Errorf("disabled user: %d %v", code, out)
	}
}

// The built-in admin signs in with a passkey alone too.
func TestBuiltinAdminPasskey(t *testing.T) {
	ts, _ := newUsersServer(t, nil)
	_, _, cs := pkCall(t, ts, "POST", "/api/login", map[string]any{"username": "admin", "password": "s3cret-pass"})
	admin := sessionOf(cs)
	if admin == nil {
		t.Fatal("no session")
	}
	a := newAuthenticator(t)
	_, opts, _ := pkCall(t, ts, "POST", "/api/me/passkeys/options", "{}", admin)
	cred, key := a.create(opts)
	if code, out, _ := pkCall(t, ts, "POST", "/api/me/passkeys", map[string]any{"name": "Key", "token": opts["token"], "credential": cred}, admin); code != http.StatusOK {
		t.Fatalf("add: %d %v", code, out)
	}
	_, lo, _ := pkCall(t, ts, "POST", "/api/login/passkey/options", "{}")
	code, out, cs := pkCall(t, ts, "POST", "/api/login/passkey", map[string]any{"token": lo["token"], "credential": a.get(lo, key), "remember": true})
	if code != http.StatusOK || out["username"] != "admin" || sessionOf(cs) == nil {
		t.Errorf("admin's passkey: %d %v", code, out)
	}
}
