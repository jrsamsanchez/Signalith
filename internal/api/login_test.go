// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func newLoginServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.UI = fstest.MapFS{
			"index.html":         {Data: []byte("<h1>app</h1>")},
			"login.html":         {Data: []byte("<h1>sign in</h1>")},
			"assets/app.css":     {Data: []byte("body{}")},
			"assets/favicon.svg": {Data: []byte("<svg/>")},
		}
	})
	return ts
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func send(t *testing.T, method, url, body string, hdr map[string]string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func sessionFrom(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie in %v", resp.Header)
	return nil
}

func TestSignInFlow(t *testing.T) {
	ts := newLoginServer(t)

	// Signed-out browsers are sent to the sign-in page; its assets are public.
	resp := send(t, "GET", ts.URL+"/findings?x=1", "", map[string]string{"Accept": "text/html", "Sec-Fetch-Mode": "navigate"})
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/login?next=%2Ffindings%3Fx%3D1" {
		t.Errorf("signed-out page = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := send(t, "GET", ts.URL+"/", "", map[string]string{"Accept": "text/html"}); resp.Header.Get("Location") != "/login" {
		t.Errorf("root redirect = %s", resp.Header.Get("Location"))
	}
	if resp := send(t, "GET", ts.URL+"/login", "", nil); resp.StatusCode != 200 {
		t.Errorf("login page = %d", resp.StatusCode)
	}
	if resp := send(t, "GET", ts.URL+"/assets/app.css", "", nil); resp.StatusCode != 200 {
		t.Errorf("public asset = %d", resp.StatusCode)
	}
	// A browser's API call gets 401 without the Basic challenge, which would
	// pop up the native dialog; other clients get the challenge.
	resp = send(t, "GET", ts.URL+"/api/health", "", map[string]string{"Sec-Fetch-Mode": "cors"})
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("browser api = %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if resp := send(t, "GET", ts.URL+"/api/health", "", nil); resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("API client got no Basic challenge")
	}

	if resp := send(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"wrong-pass"}`, nil); resp.StatusCode != 401 {
		t.Errorf("wrong password = %d", resp.StatusCode)
	}
	resp = send(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"s3cret-pass"}`, map[string]string{"Origin": ts.URL})
	if resp.StatusCode != 200 {
		t.Fatalf("sign in = %d", resp.StatusCode)
	}
	c := sessionFrom(t, resp)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 0 {
		t.Errorf("cookie = %+v", c)
	}

	if resp := send(t, "GET", ts.URL+"/api/health", "", nil, c); resp.StatusCode != 200 {
		t.Errorf("health with session = %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/me", nil)
	req.AddCookie(c)
	r2, _ := http.DefaultClient.Do(req)
	var me map[string]string
	_ = json.NewDecoder(r2.Body).Decode(&me)
	r2.Body.Close()
	if me["user"] != "admin" || me["auth"] != "session" {
		t.Errorf("me = %v", me)
	}
	// The app page is never stored, so a copy is not shown after signing
	// out.
	if resp := send(t, "GET", ts.URL+"/", "", nil, c); resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("app page = %d, Cache-Control %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	if resp := send(t, "GET", ts.URL+"/login", "", nil, c); resp.StatusCode != 303 {
		t.Errorf("login page while signed in = %d", resp.StatusCode)
	}

	// State-changing requests from another site are refused even with the cookie.
	body := `{"title":"x"}`
	if resp := send(t, "POST", ts.URL+"/api/cases", body, map[string]string{"Origin": "https://evil.example"}, c); resp.StatusCode != 403 {
		t.Errorf("cross-origin post = %d", resp.StatusCode)
	}
	if resp := send(t, "POST", ts.URL+"/api/cases", body, map[string]string{"Sec-Fetch-Site": "cross-site"}, c); resp.StatusCode != 403 {
		t.Errorf("cross-site post = %d", resp.StatusCode)
	}
	if resp := send(t, "POST", ts.URL+"/api/cases", body, map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": ts.URL}, c); resp.StatusCode != 201 {
		t.Errorf("same-origin post = %d", resp.StatusCode)
	}
	if resp := send(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"s3cret-pass"}`, map[string]string{"Sec-Fetch-Site": "cross-site"}); resp.StatusCode != 403 {
		t.Errorf("cross-site sign-in = %d", resp.StatusCode)
	}

	if resp := send(t, "POST", ts.URL+"/api/logout", "", nil, c); resp.StatusCode != 200 {
		t.Errorf("logout = %d", resp.StatusCode)
	}
	if resp := send(t, "GET", ts.URL+"/api/health", "", nil, c); resp.StatusCode != 401 {
		t.Errorf("health after logout = %d", resp.StatusCode)
	}

	// Keep me signed in sets a persistent cookie.
	resp = send(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"s3cret-pass","remember":true}`, nil)
	if c := sessionFrom(t, resp); c.MaxAge < 86400 {
		t.Errorf("remembered cookie max-age = %d", c.MaxAge)
	}
}

func TestSignInLockout(t *testing.T) {
	ts := newLoginServer(t)
	for i := 0; i < 10; i++ {
		send(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"guess"}`, nil)
	}
	resp := send(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"s3cret-pass"}`, nil)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("after 10 failures = %d", resp.StatusCode)
	}
	// Basic auth guesses share the limit.
	req, _ := http.NewRequest("GET", ts.URL+"/api/health", nil)
	req.SetBasicAuth("admin", "another-guess")
	r, _ := http.DefaultClient.Do(req)
	r.Body.Close()
	if r.StatusCode != 429 {
		t.Errorf("basic during lockout = %d", r.StatusCode)
	}
}

func TestBasicAuthStillWorks(t *testing.T) {
	ts := newLoginServer(t)
	if code, _ := do(t, ts, "GET", "/api/health", "", true); code != 200 {
		t.Errorf("basic = %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/cases", `{"title":"From a script"}`, true); code != 201 {
		t.Errorf("basic post = %d", code)
	}
}
