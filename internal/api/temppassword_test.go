// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// A temporary password from Add user or Reset password works for
// auth.temp_password_max_age (24 hours by default), then never again.
func TestTemporaryPasswordsExpire(t *testing.T) {
	store := users.NewMemory()
	at := time.Now().Add(-25 * time.Hour)
	store.Now = func() time.Time { return at }
	ts, s := newUsersServer(t, func(s *Server) { s.Users = store })
	admin := func(method, path, body string) (int, map[string]any, string) {
		return call(t, ts, method, path, body, "admin", adminPass, nil)
	}

	// Made 25 hours ago: too old to sign in with.
	code, body, _ := admin("POST", "/api/users", `{"username":"old","role":"viewer"}`)
	if code != 201 {
		t.Fatalf("create = %d %v", code, body)
	}
	oldTemp := body["temporary_password"].(string)
	if code, body, _ := login(t, ts, "old", oldTemp); code != 403 || body["code"] != "temporary_password_expired" {
		t.Errorf("sign-in with an expired temporary password = %d %v", code, body)
	}
	// A wrong password is still just wrong.
	if code, body, _ := login(t, ts, "old", "not-the-password-1"); code != 401 || body["code"] != "wrong_credentials" {
		t.Errorf("wrong password = %d %v", code, body)
	}
	// The Users page says so.
	_, list, _ := admin("GET", "/api/users", "")
	found := false
	for _, it := range list["users"].([]any) {
		if u := it.(map[string]any); u["username"] == "old" {
			found = true
			if u["temp_password_expired"] != true {
				t.Errorf("listed as %v, want temp_password_expired", u)
			}
		}
	}
	if !found {
		t.Fatal("the user is not listed")
	}

	// A reset gives a new one that works.
	at = time.Now()
	code, body, _ = admin("POST", "/api/users/old/password", `{}`)
	if code != 200 {
		t.Fatalf("reset = %d %v", code, body)
	}
	newTemp := body["temporary_password"].(string)
	code, me, c := login(t, ts, "old", newTemp)
	if code != 200 || me["must_change_password"] != true {
		t.Fatalf("sign-in with a fresh temporary password = %d %v", code, me)
	}

	// Signed in while it worked, but it expired before the change: the
	// change is refused too.
	s.Config.Auth.TempSignInMaxAge = "1h"
	at = time.Now().Add(-2 * time.Hour)
	code, body, _ = admin("POST", "/api/users", `{"username":"slow","role":"viewer"}`)
	if code != 201 {
		t.Fatalf("create = %d %v", code, body)
	}
	slowTemp := body["temporary_password"].(string)
	s.Config.Auth.TempSignInMaxAge = "24h"
	code, _, slowCookie := login(t, ts, "slow", slowTemp)
	if code != 200 {
		t.Fatalf("sign-in within 24h = %d", code)
	}
	s.Config.Auth.TempSignInMaxAge = "1h"
	if code, body, _ := call(t, ts, "POST", "/api/me/password", `{"current_password":"`+slowTemp+`","new_password":"a-brand-new-pass"}`, "", "", slowCookie); code != 403 || body["code"] != "temporary_password_expired" {
		t.Errorf("change with an expired temporary password = %d %v", code, body)
	}

	// The fresh one is still in time, and choosing a password ends the
	// clock: the user's own password never expires.
	s.Config.Auth.TempSignInMaxAge = ""
	if code, body, _ := call(t, ts, "POST", "/api/me/password", `{"current_password":"`+newTemp+`","new_password":"my-own-new-pass"}`, "", "", c); code != 200 || body["must_change_password"] != false {
		t.Fatalf("change = %d %v", code, body)
	}
	at = time.Now().Add(-48 * time.Hour)
	if code, body, _ := login(t, ts, "old", "my-own-new-pass"); code != 200 {
		t.Errorf("sign-in with the chosen password = %d %v", code, body)
	}
}
