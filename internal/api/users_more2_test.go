// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// What the Users page offers follows who is looking: a single sign-on
// admin may change no part of their own row, and others' rows offer
// turning them off or on.
func TestUserActionsForSSOAdmin(t *testing.T) {
	ts, s := newSSOSessionServer(t)
	if _, err := s.Users.Create(t.Context(), users.NewUser{Username: "andy", Role: users.Analyst, Password: "role-password"}); err != nil {
		t.Fatal(err)
	}
	c := ssoSession(t, s, "sam", users.Admin)
	code, out, raw := call(t, ts, "GET", "/api/users", "", "", "", c)
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, raw)
	}
	rows := map[string]map[string]any{}
	for _, u := range out["users"].([]any) {
		m := u.(map[string]any)
		rows[m["username"].(string)] = m
	}
	if a, ok := rows["sam"]["actions"].([]any); !ok || len(a) != 0 {
		t.Errorf("own row actions %v", rows["sam"]["actions"])
	}
	if a, _ := rows["andy"]["actions"].([]any); len(a) == 0 {
		t.Errorf("andy's actions %v", rows["andy"])
	}
}

// Turning a user off and on again is recorded each way; the built-in
// admin asked to stay on while signed in as itself is left as it is;
// a user that does not exist cannot be deleted.
func TestUserDisableEnable(t *testing.T) {
	ts, s := newRoleServer(t)
	for _, c := range []struct {
		body     string
		disabled bool
	}{{`{"disabled":true}`, true}, {`{"disabled":false}`, false}} {
		code, out := do(t, ts, "PUT", "/api/users/andy", c.body, true)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", c.body, code, out)
		}
		if u, _ := s.Users.Get("andy"); u.Disabled != c.disabled {
			t.Errorf("%s: disabled %v", c.body, u.Disabled)
		}
	}
	if code, out := do(t, ts, "PUT", "/api/users/admin", `{"disabled":false}`, true); code != http.StatusOK || out["user"] == nil {
		t.Errorf("built-in admin stays on: %d %v", code, out)
	}
	if code, _ := do(t, ts, "PUT", "/api/users/admin", `{"disabled":true}`, true); code != http.StatusConflict {
		t.Errorf("built-in admin turns itself off: %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/users/nobody", "", true); code != http.StatusNotFound {
		t.Errorf("delete unknown: %d", code)
	}
	if code, _ := do(t, ts, "PUT", "/api/users/nobody", `{"name":"x"}`, true); code != http.StatusNotFound {
		t.Errorf("update unknown: %d", code)
	}
}
