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
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// callWith is call with several cookies, returning the cookies set.
func callWith(t *testing.T, url, method, path, body string, cookies ...*http.Cookie) (int, map[string]any, []*http.Cookie) {
	t.Helper()
	req, _ := http.NewRequest(method, url+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Cookies()
}

func TestRecheckBeforeSensitiveChanges(t *testing.T) {
	// Sessions made now look 20 minutes old.
	var back atomic.Int64
	ts, s := newUsersServer(t, func(s *Server) {
		s.Sessions = auth.NewSessions(12 * time.Hour)
		s.Sessions.Now = func() time.Time { return time.Now().Add(-time.Duration(back.Load())) }
	})
	ctx := context.Background()
	if _, err := s.Users.Create(ctx, users.NewUser{Username: "ann", Role: users.Admin, Password: "Harbor-maple-63"}); err != nil {
		t.Fatal(err)
	}

	// Just signed in: no need to enter it again.
	_, _, fresh := login(t, ts, "ann", "Harbor-maple-63")
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/users", `{"username":"bob","password":"Quartz-meadow-28"}`, fresh); code != 201 {
		t.Fatalf("fresh session = %d %v", code, out)
	}

	back.Store(int64(20 * time.Minute))
	_, _, old := login(t, ts, "ann", "Harbor-maple-63")
	back.Store(0)
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/users", `{"username":"carl"}`},
		{"PUT", "/api/users/bob", `{"role":"admin"}`},
		{"POST", "/api/users/bob/password", `{}`},
		{"DELETE", "/api/users/bob", ""},
		{"POST", "/api/api-tokens", `{"name":"x","role":"viewer"}`},
		{"POST", "/api/agent-tokens", `{"name":"x"}`},
		{"PUT", "/api/settings", `{"values":{"auth.mfa_required":"off"}}`},
		{"PUT", "/api/settings", `{"reset":["server.tls.mode"]}`},
		{"PUT", "/api/settings", `{"reset_all":true}`},
		{"PUT", "/api/settings", `{"values":{"opensearch.tls_skip_verify":true}}`},
		{"PUT", "/api/settings", `{"values":{"syslog.udp":"0.0.0.0:514","syslog.tcp":"0.0.0.0:514"}}`},
		{"PUT", "/api/settings", `{"values":5}`},
		{"POST", "/api/me/mfa/setup", `{}`},
		{"PUT", "/api/retention/guard", `{}`},
		{"POST", "/api/cluster/rotate-key", `{}`},
		{"PUT", "/api/notify", `{}`},
		{"POST", "/api/endpoints/queries", `{"sql":"select 1","all":true}`},
	} {
		if code, out, _ := callWith(t, ts.URL, c.method, c.path, c.body, old); code != 403 || out["code"] != "recheck_required" || out["with"] != "password" {
			t.Errorf("%s %s = %d %v", c.method, c.path, code, out)
		}
	}
	// Other settings and checks without saving don't ask.
	if code, out, _ := callWith(t, ts.URL, "PUT", "/api/settings", `{"check_only":true,"values":{"auth.mfa_required":"off"}}`, old); out["code"] == "recheck_required" {
		t.Errorf("check only = %d %v", code, out)
	}
	if code, out, _ := callWith(t, ts.URL, "PUT", "/api/settings", `{"values":{"search.max_events":5000}}`, old); out["code"] == "recheck_required" {
		t.Errorf("other setting = %d %v", code, out)
	}

	// A wrong password counts toward the limits, and changes nothing.
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/me/recheck", `{"password":"nope"}`, old); code != 400 || out["code"] != "wrong_password" {
		t.Errorf("wrong password = %d %v", code, out)
	}
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/me/recheck", `{"password":"Quartz-meadow-28"}`, old); code != 400 || out["code"] != "wrong_password" {
		t.Errorf("another account's password = %d %v", code, out)
	}
	code, out, set := callWith(t, ts.URL, "POST", "/api/me/recheck", `{"password":"Harbor-maple-63"}`, old)
	if code != 200 || len(set) != 1 || set[0].Name != recheckCookie || set[0].MaxAge != 900 || !set[0].HttpOnly {
		t.Fatalf("recheck = %d %v %v", code, out, set)
	}
	if code, out, _ := callWith(t, ts.URL, "PUT", "/api/users/bob", `{"role":"analyst"}`, old, set[0]); code != 200 {
		t.Errorf("after recheck = %d %v", code, out)
	}
	// The cookie is good for its own session only.
	back.Store(int64(20 * time.Minute))
	_, _, other := login(t, ts, "ann", "Harbor-maple-63")
	back.Store(0)
	if code, out, _ := callWith(t, ts.URL, "PUT", "/api/users/bob", `{"role":"viewer"}`, other, set[0]); code != 403 || out["code"] != "recheck_required" {
		t.Errorf("other session = %d %v", code, out)
	}

	// With two-step sign-in, a code works too (here a recovery code). Turning it on signed out
	// every other session.
	secret, codes := setUpMFA(t, ts, fresh)
	back.Store(int64(20 * time.Minute))
	first, _ := users.TOTP(secret, time.Now().Add(30*time.Second))
	_, _, other = loginCode(t, ts, "ann", "Harbor-maple-63", first)
	back.Store(0)
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/users", `{"username":"dan"}`, other); code != 403 || out["with"] != "password_or_code" {
		t.Errorf("with two-step = %d %v", code, out)
	}
	next := codes[0]
	if code, out, set := callWith(t, ts.URL, "POST", "/api/me/recheck", `{"code":"`+next+`"}`, other); code != 200 || len(set) != 1 {
		t.Errorf("code = %d %v", code, out)
	}
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/me/recheck", `{"code":"`+next+`"}`, other); code != 400 || out["code"] != "mfa_wrong" {
		t.Errorf("same code again = %d %v", code, out)
	}

	// HTTP Basic sends the password every time.
	if code, out, _ := call(t, ts, "POST", "/api/users", `{"username":"erin"}`, "bob", "Quartz-meadow-28", nil); code == 403 && out["code"] == "recheck_required" {
		t.Errorf("basic = %d %v", code, out)
	}
}

// Running a response action and approving a playbook step ask for the
// password or code entered within auth.ActionRecheckAge, shorter than
// other sensitive changes; rejecting a step does not ask.
func TestRecheckBeforeResponseActions(t *testing.T) {
	var back atomic.Int64
	ts, s := newUsersServer(t, func(s *Server) {
		s.Sessions = auth.NewSessions(12 * time.Hour)
		s.Sessions.Now = func() time.Time { return time.Now().Add(-time.Duration(back.Load())) }
	})
	ctx := context.Background()
	for _, u := range []users.NewUser{{Username: "ann", Role: users.Admin, Password: "Harbor-maple-63"},
		{Username: "sam", Role: users.Analyst, Password: "Copper-lantern-47"}} {
		if _, err := s.Users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	actions := []struct{ method, path, body string }{
		{"POST", "/api/respond/run", `{"action":"x","target":"10.0.0.1","reason":"test"}`},
		{"POST", "/api/playbooks/runs/r1/approve", `{}`},
	}
	asks := func(c ...*http.Cookie) []string {
		var asked []string
		for _, a := range actions {
			if code, out, _ := callWith(t, ts.URL, a.method, a.path, a.body, c...); code == 403 && out["code"] == "recheck_required" {
				if out["minutes"] != float64(auth.ActionRecheckAge.Minutes()) {
					t.Errorf("%s %s asks within %v minutes", a.method, a.path, out["minutes"])
				}
				asked = append(asked, a.path)
			}
		}
		return asked
	}

	// Signed in four minutes ago: no need to enter it again.
	back.Store(int64(4 * time.Minute))
	_, _, fresh := login(t, ts, "sam", "Copper-lantern-47")
	back.Store(int64(6 * time.Minute))
	_, _, old := login(t, ts, "sam", "Copper-lantern-47")
	_, _, oldAdmin := login(t, ts, "ann", "Harbor-maple-63")
	back.Store(0)
	if asked := asks(fresh); len(asked) != 0 {
		t.Errorf("a four-minute-old session was asked for %v", asked)
	}
	// Six minutes: asked, though other sensitive changes are not.
	if asked := asks(old); len(asked) != len(actions) {
		t.Errorf("a six-minute-old session was asked only for %v", asked)
	}
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/users", `{"username":"bob"}`, oldAdmin); code != 201 {
		t.Errorf("other sensitive change in a six-minute-old session = %d %v", code, out)
	}
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/playbooks/runs/r1/reject", `{}`, old); out["code"] == "recheck_required" {
		t.Errorf("reject = %d %v", code, out)
	}
	// A password entered again six minutes ago is too old here.
	stale := &http.Cookie{Name: recheckCookie, Value: s.browserKey().IssueRecheck("sam", old.Value, time.Now().Add(-6*time.Minute))}
	if asked := asks(old, stale); len(asked) != len(actions) {
		t.Errorf("a six-minute-old recheck was taken for %v", actions)
	}
	// Entered now, it is taken. A wrong one counts toward the limits.
	if code, out, _ := callWith(t, ts.URL, "POST", "/api/me/recheck", `{"password":"nope"}`, old); code != 400 || out["code"] != "wrong_password" {
		t.Errorf("wrong password = %d %v", code, out)
	}
	code, out, set := callWith(t, ts.URL, "POST", "/api/me/recheck", `{"password":"Copper-lantern-47"}`, old)
	if code != 200 || len(set) != 1 {
		t.Fatalf("recheck = %d %v %v", code, out, set)
	}
	if asked := asks(old, set[0]); len(asked) != 0 {
		t.Errorf("still asked after the recheck: %v", asked)
	}
	// API tokens can only read, so they never run an action.
	for _, p := range []string{"POST /api/respond/run", "POST /api/playbooks/runs/{id}/approve"} {
		if tokenMayUse(route{Pattern: p}) {
			t.Errorf("an API token may use %s", p)
		}
	}
}

func TestProtectedSettings(t *testing.T) {
	for key, want := range map[string]bool{
		"auth.mfa_required": true, "auth.session_timeout": true, "server.tls.mode": true, "server.tls.plaintext_ingest": true,
		"server.trusted_proxies": true, "syslog.allow": true, "server.tls_cert": true, "server.tls_key": true, "auth.oidc.issuer": true,
		"opensearch.url": true, "opensearch.tls_skip_verify": true, "cluster.opensearch_url": true, "syslog.tls": true,
		"intel.allow_loopback_feeds": true, "server.listen": true, "assistant.url": true, "okta.domain": true, "m365.tenant_id": true,
		"server.public_url": false, "search.max_events": false, "authx": false, "syslog.udp": true, "syslog.tcp": true, "assistant.model": false,
		"backup.snapshots": true, "backup.snapshot_repository": true, "backup.snapshot_keep": true, "backup.snapshot_every": true,
		"backupx": false,
	} {
		if protectedSetting(key) != want {
			t.Errorf("%s: %v", key, !want)
		}
	}
}

// Turning scheduled snapshots off, or changing what they keep, asks for
// the password again, as a save from the Settings page.
func TestBackupSettingsRecheck(t *testing.T) {
	for body, want := range map[string]bool{
		`{"values":{"backup.snapshots":false}}`:                   true,
		`{"values":{"backup.snapshot_repository":"elsewhere"}}`:   true,
		`{"values":{"backup.snapshot_keep":1}}`:                   true,
		`{"reset":["backup.snapshot_keep"]}`:                      true,
		`{"values":{"backup.snapshots":false},"check_only":true}`: false,
		`{"values":{"search.max_events":500}}`:                    false,
	} {
		if got := settingsSaveRecheck(json.RawMessage(body)); got != want {
			t.Errorf("%s: %v", body, got)
		}
	}
}
