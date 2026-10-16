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
		{"PUT", "/api/settings", `{"values":5}`},
		{"POST", "/api/me/mfa/setup", `{}`},
		{"PUT", "/api/retention/guard", `{}`},
		{"POST", "/api/cluster/rotate-key", `{}`},
		{"PUT", "/api/notify", `{}`},
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

func TestProtectedSettings(t *testing.T) {
	for key, want := range map[string]bool{
		"auth.mfa_required": true, "auth.session_timeout": true, "server.tls.mode": true, "server.tls.plaintext_ingest": true,
		"server.trusted_proxies": true, "syslog.allow": true, "server.tls_cert": true, "server.tls_key": true, "auth.oidc.issuer": true,
		"opensearch.url": true, "opensearch.tls_skip_verify": true, "cluster.opensearch_url": true, "syslog.tls": true,
		"intel.allow_loopback_feeds": true, "server.listen": true, "assistant.url": true, "okta.domain": true, "m365.tenant_id": true,
		"server.public_url": false, "search.max_events": false, "authx": false, "syslog.udp": false, "assistant.model": false,
	} {
		if protectedSetting(key) != want {
			t.Errorf("%s: %v", key, !want)
		}
	}
}
