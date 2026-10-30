// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// Another admin turns the built-in admin off: its sessions end, it cannot
// sign in by any means, and an admin turns it on again.
func TestTurningOffTheBuiltinAdmin(t *testing.T) {
	ts, s := newUsersServer(t, func(s *Server) {
		s.Users.Create(context.Background(), users.NewUser{Username: "ann", Role: users.Admin, Password: "a-password-one"})
	})
	ann := func(method, path, body string) (int, map[string]any) {
		return doAs(t, ts, "ann", "a-password-one", method, path, body)
	}
	builtinRow := func() map[string]any {
		_, body := ann("GET", "/api/users", "")
		for _, u := range body["users"].([]any) {
			if u := u.(map[string]any); u["source"] == "builtin" {
				return u
			}
		}
		t.Fatal("no built-in admin listed")
		return nil
	}
	actions := func(u map[string]any) string {
		b, _ := json.Marshal(u["actions"])
		return string(b)
	}
	if u := builtinRow(); u["disabled"] != false || actions(u) != `["disable"]` {
		t.Errorf("built-in admin row = %v", u)
	}

	// It cannot turn itself off.
	if code, body := doAs(t, ts, "admin", adminPass, "PUT", "/api/users/admin", `{"disabled":true}`); code != 409 || !strings.Contains(body["error"].(string), "signed in with") {
		t.Errorf("built-in admin turns itself off = %d %v", code, body)
	}
	// Nothing else about it changes here.
	if code, _ := ann("PUT", "/api/users/admin", `{"name":"Root","disabled":true}`); code != 409 {
		t.Errorf("name and disabled = %d", code)
	}

	_, _, c := login(t, ts, "admin", adminPass)
	if c == nil {
		t.Fatal("no session for the built-in admin")
	}
	if code, body := ann("PUT", "/api/users/admin", `{"disabled":true}`); code != 200 || body["user"].(map[string]any)["disabled"] != true {
		t.Fatalf("turn off = %d %v", code, body)
	}
	if !s.userStore().BuiltinDisabled() {
		t.Fatal("not turned off")
	}
	if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != 401 {
		t.Errorf("session after turning off = %d", code)
	}
	if code, body, _ := login(t, ts, "admin", adminPass); code != 403 || body["code"] != "disabled" || !strings.Contains(body["error"].(string), "signalith passwd") {
		t.Errorf("sign-in while off = %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", adminPass, "GET", "/api/me", ""); code != 403 {
		t.Errorf("basic while off = %d", code)
	}
	if code, _, _ := login(t, ts, "admin", "wrong-password"); code != 401 {
		t.Errorf("wrong password while off = %d (should not reveal the state)", code)
	}
	if u := builtinRow(); u["disabled"] != true || actions(u) != `["enable"]` {
		t.Errorf("built-in admin row while off = %v", u)
	}
	// ann is the last enabled admin now.
	if code, _ := ann("PUT", "/api/users/ann", `{"role":"viewer"}`); code != 409 {
		t.Errorf("ann changes own role = %d", code)
	}

	if code, _ := ann("PUT", "/api/users/admin", `{"disabled":false}`); code != 200 {
		t.Fatalf("turn on = %d", code)
	}
	if code, _, _ := login(t, ts, "admin", adminPass); code != 200 {
		t.Errorf("sign-in after turning on = %d", code)
	}
}

// On the servers of a cluster, turning the built-in admin off on one
// ends its sessions and sign-ins on the others; it waits for every server
// to support it.
func TestTurningOffTheSharedBuiltinAdmin(t *testing.T) {
	var below atomic.Bool
	c := newMemberCluster(t, func(s *Server) {
		s.SharedUsers.BuiltinOff = func() string {
			if below.Load() {
				return "upgrade the others first"
			}
			return ""
		}
	})
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	c.a.addUser(admin, "ann", "tide-pool-lantern-7", users.Admin)
	onB, _ := c.b.signIn("admin", "s3cret-pass")
	if onB == nil {
		t.Fatal("no session on B")
	}
	ann, _ := c.a.signIn("ann", "tide-pool-lantern-7")

	// Below the level that supports it, it stays on.
	below.Store(true)
	if code, out, _ := c.a.call("PUT", "/api/users/admin", `{"disabled":true}`, ann, nil); code != 409 || !strings.Contains(stringOf(out), "upgrade the others") {
		t.Errorf("below the level: %d %v", code, out)
	}
	below.Store(false)

	if code, out, _ := c.a.call("PUT", "/api/users/admin", `{"disabled":true}`, ann, nil); code != 200 {
		t.Fatalf("turn off: %d %v", code, out)
	}
	if !strings.Contains(c.a.logs.String(), "user disabled") {
		t.Errorf("no audit record:\n%s", c.a.logs.String())
	}
	c.b.cycle()
	waitFor(t, "the built-in admin's session on B to end", func() bool { return c.b.me(onB) == http.StatusUnauthorized })
	if _, code := c.b.signIn("admin", "s3cret-pass"); code != http.StatusForbidden {
		t.Errorf("sign-in on B while off: %d", code)
	}
	if code := c.b.basic("admin", "s3cret-pass"); code != http.StatusForbidden {
		t.Errorf("basic on B while off: %d", code)
	}
	if code, out, _ := c.a.call("PUT", "/api/users/admin", `{"disabled":false}`, ann, nil); code != 200 {
		t.Fatalf("turn on: %d %v", code, out)
	}
	c.b.cycle()
	if cookie, code := c.b.signIn("admin", "s3cret-pass"); cookie == nil {
		t.Errorf("sign-in on B after turning on: %d", code)
	}
}
