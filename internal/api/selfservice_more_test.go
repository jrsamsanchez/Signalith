// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// ssoSession makes a single sign-on user and a session for them, as a
// sign-in through the identity provider does.
func ssoSession(t *testing.T, s *Server, name string, role users.Role) *http.Cookie {
	t.Helper()
	u, err := s.Users.SeeSSOUser(t.Context(), users.SSOUser{Username: name, Subject: users.SSOSubject("https://idp.example.com", name), Role: role}, true)
	if err != nil {
		t.Fatal(err)
	}
	if u.Source != users.SourceSSO {
		t.Fatalf("source %q", u.Source)
	}
	tok, err := s.startSession(httptest.NewRequest("GET", "/", nil), principalFromUser(u), false)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: sessionCookie, Value: tok}
}

// newSSOSessionServer starts a server with single sign-on on, whose users can
// use their sessions.
func newSSOSessionServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Users = users.NewMemory()
		s.Config.Auth.OIDC.Enabled = true
		s.Config.Auth.OIDC.Issuer = "https://idp.example.com"
	})
	return ts, srv
}

// A single sign-on user has no password or second step here: every
// self-service route that would change one says where it is managed,
// and changes nothing.
func TestSSOUserCannotChangeCredentialsHere(t *testing.T) {
	ts, s := newSSOSessionServer(t)
	c := ssoSession(t, s, "sam", users.Analyst)
	for _, tc := range []struct {
		method, path, body string
		status             int
		code               string
	}{
		{"POST", "/api/me/password", `{"current":"x","new":"Another-long-pass-1"}`, 400, "sso"},
		{"POST", "/api/me/mfa/setup", `{}`, 400, "mfa_elsewhere"},
		{"POST", "/api/me/mfa/confirm", `{"code":"123456"}`, 400, "mfa_elsewhere"},
		{"POST", "/api/me/mfa/off", `{}`, 400, "mfa_elsewhere"},
		{"POST", "/api/me/passkeys/options", `{}`, 400, "mfa_elsewhere"},
		{"DELETE", "/api/me/passkeys/abc", ``, 400, "mfa_elsewhere"},
		{"POST", "/api/me/recheck", `{"password":"x"}`, 409, "recheck_sign_in"},
	} {
		code, out, raw := call(t, ts, tc.method, tc.path, tc.body, "", "", c)
		if code != tc.status || out["code"] != tc.code {
			t.Errorf("%s %s: %d %s, want %d %s", tc.method, tc.path, code, raw, tc.status, tc.code)
		}
	}
	if m, _ := s.Users.MFA("sam"); s.Users.MFAOn("sam") || m.Pending || len(m.Passkeys) > 0 {
		t.Errorf("mfa changed: %+v", m)
	}
	// The account menu still reads.
	if code, out, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != 200 || out["username"] != "sam" {
		t.Errorf("me: %d %v", code, out)
	}
}

// Signing out is refused from another site, so a page elsewhere cannot
// end the session; from this site it works.
func TestLogoutRefusesCrossSite(t *testing.T) {
	ts, s := newSSOSessionServer(t)
	c := ssoSession(t, s, "sam", users.Viewer)
	req, _ := http.NewRequest("POST", ts.URL+"/api/logout", nil)
	req.AddCookie(c)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site logout: %d", resp.StatusCode)
	}
	if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != 200 {
		t.Errorf("the session ended: %d", code)
	}
	if code, _, _ := call(t, ts, "POST", "/api/logout", "", "", "", c); code >= 300 {
		t.Errorf("logout: %d", code)
	}
	if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != 401 {
		t.Errorf("after logout: %d", code)
	}
}

// The certificate authority download takes which=current, next or both,
// and nothing else; without HTTPS there is nothing to download.
func TestCAPEMWhich(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, tc := range []struct {
		which  string
		status int
		want   string
	}{
		{"bogus", 400, "which must be"},
		{"", 404, "does not serve HTTPS"},
		{"current", 404, "does not serve HTTPS"},
	} {
		code, out := do(t, ts, "GET", "/api/tls/ca.pem?which="+tc.which, "", false)
		if msg, _ := out["error"].(string); code != tc.status || !strings.Contains(msg, tc.want) {
			t.Errorf("which=%q: %d %v", tc.which, code, out)
		}
	}
}
