// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
	"github.com/jrsamsanchez/signalith/internal/users/ldaptest"
)

// Looking a directory user up: a username is needed and the settings
// must be whole; a right password is checked, and the built-in admin's
// name is never asked about at sign-in.
func TestTestDirectoryUserMore(t *testing.T) {
	srv, err := ldaptest.Start(ldaptest.Options{TLS: true, ActiveDirectory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ldaptest.LoadActiveDirectory(srv)
	ts, _ := newUsersServer(t, nil)
	test := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "POST", "/api/auth/directory/test-user", body, "admin", adminPass, nil)
		return code, out
	}
	settings := adSettingsJSON(srv, "")
	if code, _ := test(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, out := test(`{"username":"  ","settings":` + settings + `}`); code != http.StatusBadRequest || out["fields"].(map[string]any)["username"] == nil {
		t.Errorf("no username: %d %v", code, out)
	}
	if code, out := test(`{"username":"bob","settings":{"enabled":true,"type":"ad","url":"http://x"}}`); code != http.StatusBadRequest || out["fields"] == nil {
		t.Errorf("bad settings: %d %v", code, out)
	}
	code, out := test(`{"username":"bob","password":"` + ldaptest.Password + `","settings":` + settings + `}`)
	if code != http.StatusOK || out["ok"] != true || out["password_checked"] != true {
		t.Errorf("right password: %d %v", code, out)
	}
	code, out = test(`{"username":"admin","settings":` + settings + `}`)
	if w, _ := out["warning"].(string); code != http.StatusOK || !strings.Contains(w, "built-in admin") {
		t.Errorf("the built-in admin's name: %d %v", code, out)
	}
}

// An admin's password reset: bad bodies, a user that is not there, and
// their own account are refused.
func TestResetPasswordRefusals(t *testing.T) {
	ts, s := newUsersServer(t, nil)
	for _, u := range []string{"ann", "bob"} {
		if _, err := s.Users.Create(context.Background(), users.NewUser{Username: u, Role: users.Admin, Password: "Harbor-maple-63"}); err != nil {
			t.Fatal(err)
		}
	}
	reset := func(name, body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "POST", "/api/users/"+name+"/password", body, "ann", "Harbor-maple-63", nil)
		return code, out
	}
	if code, _ := reset("bob", `{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, _ := reset("nobody", `{}`); code != http.StatusNotFound {
		t.Errorf("unknown user: %d", code)
	}
	if code, out := reset("ann", `{}`); code != http.StatusConflict || !strings.Contains(out["error"].(string), "Change password in your user menu") {
		t.Errorf("own: %d %v", code, out)
	}
	if code, out := reset("bob", `{"password":"x"}`); code != http.StatusBadRequest {
		t.Errorf("too short: %d %v", code, out)
	}
	code, out := reset("bob", "")
	if code != http.StatusOK || out["user"].(map[string]any)["must_change_password"] != true {
		t.Errorf("generated: %d %v", code, out)
	}

	// Changing one's own password: the body must be JSON, and guesses
	// at the current one lock the account for a while.
	_, _, ann := login(t, ts, "ann", "Harbor-maple-63")
	own := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "POST", "/api/me/password", body, "", "", ann)
		return code, out
	}
	if code, _ := own(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, out := own(`{"current_password":"Harbor-maple-63","new_password":"Harbor-maple-63"}`); code != http.StatusBadRequest || out["code"] != "same_password" {
		t.Errorf("same: %d %v", code, out)
	}
	var code2 int
	var last map[string]any
	for i := 0; i < 30 && code2 != http.StatusTooManyRequests; i++ {
		code2, last = own(`{"current_password":"wrong","new_password":"Quartz-meadow-28"}`)
	}
	if code2 != http.StatusTooManyRequests || last["code"] != "locked_out" {
		t.Errorf("after many wrong passwords: %d %v", code2, last)
	}
}
