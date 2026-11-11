// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jrsamsanchez/signalith/internal/users"
)

type sessionRow struct {
	ID       string `json:"id"`
	Client   string `json:"client"`
	Remember bool   `json:"remember"`
	Current  bool   `json:"current"`
}

func listSessions(t *testing.T, base string, c *http.Cookie) (int, []sessionRow, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/api/me/sessions", nil)
	req.AddCookie(c)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Sessions []sessionRow `json:"sessions"`
	}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out.Sessions, string(raw)
}

// A user sees their sessions, named by a hash, ends one or all the
// others; an admin ends every session of another user without disabling
// them. Each end is audited.
func TestOwnSessionsAndAdminEnd(t *testing.T) {
	logs := &syncBuffer{}
	ts, s := newUsersServer(t, func(s *Server) {
		s.Log = slog.New(slog.NewTextHandler(logs, nil))
	})
	if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "kim", Role: users.Viewer, Password: "orchid-lantern-42"}); err != nil {
		t.Fatal(err)
	}
	_, _, c1 := login(t, ts, "kim", "orchid-lantern-42")
	_, _, c2 := login(t, ts, "kim", "orchid-lantern-42")
	_, _, c3 := login(t, ts, "kim", "orchid-lantern-42")
	if c1 == nil || c2 == nil || c3 == nil {
		t.Fatal("no session")
	}
	code, list, raw := listSessions(t, ts.URL, c1)
	if code != 200 || len(list) != 3 || !list[0].Current || list[1].Current || list[2].Current || list[0].Client == "" {
		t.Fatalf("list = %d %s", code, raw)
	}
	for _, c := range []*http.Cookie{c1, c2, c3} {
		if strings.Contains(raw, c.Value) {
			t.Fatal("the list gives away a session cookie")
		}
	}
	if code, _, _ := call(t, ts, "DELETE", "/api/me/sessions/"+list[0].ID, "", "", "", c1); code != 409 {
		t.Errorf("ending the current session = %d, want 409", code)
	}
	if code, _, _ := call(t, ts, "DELETE", "/api/me/sessions/"+list[1].ID, "", "", "", c1); code != 200 {
		t.Errorf("ending a session = %d", code)
	}
	if code, _, _ := call(t, ts, "DELETE", "/api/me/sessions/"+list[1].ID, "", "", "", c1); code != 404 {
		t.Errorf("ending it again = %d, want 404", code)
	}
	if _, list, _ := listSessions(t, ts.URL, c1); len(list) != 2 {
		t.Errorf("%d sessions left, want 2", len(list))
	}
	code, out, _ := call(t, ts, "DELETE", "/api/me/sessions", "", "", "", c1)
	if code != 200 || out["ended"] != 1.0 {
		t.Errorf("sign out other sessions = %d %v", code, out)
	}
	for _, c := range []*http.Cookie{c2, c3} {
		if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != 401 {
			t.Errorf("an ended session answers %d", code)
		}
	}
	if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", c1); code != 200 {
		t.Errorf("the current session answers %d", code)
	}

	// An admin signs kim out everywhere; kim can sign in again.
	_, _, c4 := login(t, ts, "kim", "orchid-lantern-42")
	if code, _, _ := call(t, ts, "DELETE", "/api/users/kim/sessions", "", "kim", "orchid-lantern-42", nil); code != 403 {
		t.Errorf("a viewer ended sessions: %d", code)
	}
	code, out, _ = call(t, ts, "DELETE", "/api/users/KIM/sessions", "", "admin", adminPass, nil)
	if code != 200 || out["ended"] != 2.0 || out["username"] != "kim" {
		t.Errorf("admin end = %d %v", code, out)
	}
	for _, c := range []*http.Cookie{c1, c4} {
		if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != 401 {
			t.Errorf("a session outlived the admin's end: %d", code)
		}
	}
	if code, _, _ := login(t, ts, "kim", "orchid-lantern-42"); code != 200 {
		t.Errorf("kim cannot sign in again: %d", code)
	}
	if code, _, _ := call(t, ts, "DELETE", "/api/users/admin/sessions", "", "admin", adminPass, nil); code != 409 {
		t.Errorf("admin ending their own = %d, want 409", code)
	}
	if code, _, _ := call(t, ts, "DELETE", "/api/users/nobody/sessions", "", "admin", adminPass, nil); code != 404 {
		t.Errorf("unknown user = %d, want 404", code)
	}
	l := logs.String()
	for _, msg := range []string{`msg="session ended"`, `msg="other sessions ended"`, `msg="user's sessions ended"`} {
		if !strings.Contains(l, msg) {
			t.Errorf("not audited: %s", msg)
		}
	}
	if !strings.Contains(l, "sessions_ended=2") {
		t.Error("the admin's end does not say how many ended")
	}
}

// auth.keep_signed_in false hides Keep me signed in, and the server
// refuses it to a request that asks anyway.
func TestKeepSignedInCanBeTurnedOff(t *testing.T) {
	off := false
	ts, _ := newUsersServer(t, func(s *Server) {
		s.Config.Auth.KeepSignedIn = &off
		s.UI = fstest.MapFS{"index.html": {Data: []byte("<h1>app</h1>")},
			"login.html": {Data: []byte(`<label class="check auth__remember" id="remember-row"><input type="checkbox" id="remember"></label>`)}}
	})
	resp := send(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"s3cret-pass","remember":true}`, nil)
	c := sessionFrom(t, resp)
	if c.MaxAge != 0 {
		t.Errorf("cookie max-age = %d, want a session cookie", c.MaxAge)
	}
	if _, list, raw := listSessions(t, ts.URL, c); len(list) != 1 || list[0].Remember {
		t.Errorf("session kept signed in: %s", raw)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/login", nil)
	r, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(page), `id="remember-row" hidden`) {
		t.Errorf("the box is shown: %s", page)
	}
}
