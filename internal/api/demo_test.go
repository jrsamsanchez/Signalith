// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// newDemoServer starts a public demo (demo.enabled) with a viewer (vera)
// and an analyst (andy), both with the password "role-password", and the
// sign-in and app pages. Password sign-in works from adminNetworks.
func newDemoServer(t *testing.T, adminNetworks ...string) (*httptest.Server, *Server) {
	t.Helper()
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Config.Demo.Enabled = true
		s.Config.Demo.AdminNetworks = adminNetworks
		s.Users = users.NewMemory()
		for name, role := range map[string]users.Role{"vera": users.Viewer, "andy": users.Analyst} {
			if _, err := s.Users.Create(context.Background(), users.NewUser{Username: name, Role: role, Password: "role-password"}); err != nil {
				t.Fatal(err)
			}
		}
		s.UI = fstest.MapFS{
			"index.html": {Data: []byte(`<main><div id="demo-banner" hidden>Public demo</div></main>`)},
			"login.html": {Data: []byte(`<form><div id="demo" hidden>Explore the demo</div></form>`)},
		}
	})
	return ts, srv
}

// demoVisit signs a visitor in to the demo and returns the session cookie.
func demoVisit(t *testing.T, ts *httptest.Server) *http.Cookie {
	t.Helper()
	resp := send(t, "POST", ts.URL+"/api/demo", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("demo sign-in = %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 0 {
				t.Errorf("the visitor's cookie is %+v; want HttpOnly, SameSite=Strict and gone with the browser", c)
			}
			return c
		}
	}
	t.Fatal("the demo sign-in set no session cookie")
	return nil
}

// Visitors sign in with one click, with no password, as an analyst that is
// marked as the demo's.
func TestDemoVisitorSignsInAsAnAnalyst(t *testing.T) {
	ts, s := newDemoServer(t)
	c := demoVisit(t, ts)
	code, me, _ := call(t, ts, "GET", "/api/me", "", "", "", c)
	if code != http.StatusOK || me["role"] != string(users.Analyst) || me["demo"] != true || me["source"] != sourceDemo ||
		me["can_change_password"] != false || me["username"] != demoUser {
		t.Fatalf("the visitor's /api/me = %d %v", code, me)
	}
	// The visitor's session is kept apart from the users' sessions.
	if got := s.sessions().Users(context.Background()); len(got) != 0 {
		t.Errorf("the users' sessions hold %v", got)
	}
	// A cross-site page cannot sign a browser in to the demo.
	resp := send(t, "POST", ts.URL+"/api/demo", "", map[string]string{"Sec-Fetch-Site": "cross-site"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a cross-site demo sign-in = %d, want 403", resp.StatusCode)
	}
	// Signing out ends the visitor's session.
	resp = send(t, "POST", ts.URL+"/api/logout", "", nil, c)
	resp.Body.Close()
	if code, _, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != http.StatusUnauthorized {
		t.Errorf("/api/me after signing out = %d, want 401", code)
	}
}

// The visitor reaches only the routes for viewers and analysts that only
// read: no admin route, and nothing that changes anything, its own
// password, two-step sign-in, passkeys, API tokens and setup guide
// included.
func TestDemoVisitorOnlyReads(t *testing.T) {
	ts, s := newDemoServer(t)
	c := demoVisit(t, ts)
	wildcard := regexp.MustCompile(`\{[^}]+\}`)
	allowed := 0
	for _, rt := range s.routes {
		method, path, _ := strings.Cut(rt.Pattern, " ")
		path = wildcard.ReplaceAllString(path, "x")
		code, body, raw := call(t, ts, method, path, "{}", "", "", c)
		refused := code == http.StatusForbidden && (body["code"] == "demo_read_only" || body["code"] == "demo_off")
		readOnly := (rt.Role == users.Viewer || rt.Role == users.Analyst) && !rt.Recheck && !rt.Unclassified &&
			(method == http.MethodGet || method == http.MethodHead || slices.Contains(demoReads, rt.Pattern)) &&
			!demoOff(rt, method)
		if refused == readOnly {
			t.Errorf("visitor %s: status %d, refused=%v, want refused=%v (%s)", rt.Pattern, code, refused, !readOnly, raw)
		}
		if !refused {
			allowed++
		}
	}
	if allowed < 30 {
		t.Errorf("the visitor may use only %d routes; is the test still working?", allowed)
	}
	for _, p := range []string{
		"POST /api/me/password", "POST /api/me/mfa/setup", "POST /api/me/passkeys/options", "POST /api/api-tokens",
		"PUT /api/me/setup", "PUT /api/me/finding-views", "POST /api/chat/link", "POST /api/cases", "PATCH /api/findings/x", "POST /api/sample/load",
		"PUT /api/settings", "POST /api/users", "POST /api/agent-tokens", "POST /api/tenants/switch",
		"GET /api/settings", "GET /api/users", "GET /api/audit", "POST /api/vulns/networks/x/scan", "POST /api/notebooks",
	} {
		method, path, _ := strings.Cut(p, " ")
		if code, body, _ := call(t, ts, method, path, "{}", "", "", c); code != http.StatusForbidden {
			t.Errorf("visitor %s = %d %v, want 403", p, code, body)
		}
	}
	// The analysts' pages read: Vulnerabilities, Endpoints and Ask.
	for _, p := range []string{"GET /api/vulns", "GET /api/endpoints"} {
		method, path, _ := strings.Cut(p, " ")
		if code, body, _ := call(t, ts, method, path, "", "", "", c); code == http.StatusForbidden || code == http.StatusUnauthorized {
			t.Errorf("visitor %s = %d %v", p, code, body)
		}
	}
	if code, body, _ := call(t, ts, "POST", "/api/ask", `{"question":"failed logins today"}`, "", "", c); code != http.StatusOK {
		t.Errorf("visitor Ask = %d %v", code, body)
	}
	// Searching works.
	if code, body, _ := call(t, ts, "POST", "/api/search", `{"query":"*"}`, "", "", c); code == http.StatusForbidden || code == http.StatusUnauthorized {
		t.Errorf("visitor search = %d %v", code, body)
	}
}

// Password sign-in works only from demo.admin_networks: the sign-in page,
// HTTP Basic and the users' sessions. Nobody else can try passwords.
func TestDemoPasswordSignInOnlyFromAdminNetworks(t *testing.T) {
	ts, _ := newDemoServer(t)
	if code, out, c := login(t, ts, "vera", "role-password"); code != http.StatusForbidden || out["code"] != "demo_password_off" || c != nil {
		t.Errorf("password sign-in outside the admin networks = %d %v", code, out)
	}
	if code, _ := doAs(t, ts, "andy", "role-password", "GET", "/api/findings", ""); code != http.StatusUnauthorized {
		t.Errorf("Basic auth outside the admin networks = %d, want 401", code)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/settings", ""); code != http.StatusUnauthorized {
		t.Errorf("the built-in admin outside the admin networks = %d, want 401", code)
	}

	// The test client is 127.0.0.1.
	ts, _ = newDemoServer(t, "127.0.0.1/32")
	code, _, c := login(t, ts, "andy", "role-password")
	if code != http.StatusOK || c == nil {
		t.Fatalf("password sign-in from an admin network = %d", code)
	}
	if code, me, _ := call(t, ts, "GET", "/api/me", "", "", "", c); code != http.StatusOK || me["role"] != string(users.Analyst) || me["demo"] != false {
		t.Errorf("an analyst's /api/me in demo mode = %d %v", code, me)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/settings", ""); code != http.StatusOK {
		t.Errorf("the built-in admin from an admin network = %d, want 200", code)
	}

	// From another network the same session no longer works.
	ts, _ = newDemoServer(t, "198.51.100.0/24")
	if code, _, _ := login(t, ts, "andy", "role-password"); code != http.StatusForbidden {
		t.Errorf("password sign-in from outside 198.51.100.0/24 = %d, want 403", code)
	}
}

// The features that send to or fetch from other systems are off for
// everyone, admins too.
func TestDemoTurnsFeaturesOffForAdmins(t *testing.T) {
	ts, s := newDemoServer(t, "127.0.0.1/32")
	wildcard := regexp.MustCompile(`\{[^}]+\}`)
	matched := map[string]bool{}
	for _, rt := range s.routes {
		method, path, _ := strings.Cut(rt.Pattern, " ")
		off := demoOff(rt, method)
		for _, o := range demoOffRoutes {
			rest := strings.TrimPrefix(path, "/api/")
			if rest == o.path || strings.HasPrefix(rest, o.path+"/") {
				matched[o.path] = true
			}
		}
		code, body, raw := call(t, ts, method, wildcard.ReplaceAllString(path, "x"), "{}", "admin", "s3cret-pass", nil)
		refused := code == http.StatusForbidden && body["code"] == "demo_off"
		if refused != off {
			t.Errorf("admin %s: status %d, refused=%v, want refused=%v (%s)", rt.Pattern, code, refused, off, raw)
		}
	}
	for _, o := range demoOffRoutes {
		if !matched[o.path] {
			t.Errorf("demoOffRoutes has %q, which is no route", o.path)
		}
	}
	for _, p := range []string{
		"POST /api/findings/x/investigate", "POST /api/findings/x/investigate/preview", "PUT /api/notify", "POST /api/notify/test",
		"POST /api/respond/run", "PUT /api/respond/config", "PUT /api/playbooks", "POST /api/playbooks/runs/x/approve",
		"PUT /api/ticketing", "POST /api/cases/x/tickets", "POST /api/vulns/networks/x/scan", "PUT /api/vulns/settings",
		"POST /api/intel/feeds", "POST /api/intel/feeds/test", "POST /api/intel/feeds/x/refresh", "POST /api/intel/catalog",
		"POST /api/intel/taxii/collections", "POST /api/settings/test/assistant", "POST /api/auth/oidc/test",
		"POST /api/auth/saml/test", "POST /api/auth/scim/token", "POST /api/auth/directory/test", "POST /api/tenants",
		"POST /api/chat/link",
	} {
		method, path, _ := strings.Cut(p, " ")
		if code, body := doAs(t, ts, "admin", "s3cret-pass", method, path, "{}"); code != http.StatusForbidden || body["code"] != "demo_off" {
			t.Errorf("admin %s = %d %v, want 403 demo_off", p, code, body)
		}
	}
	// Reading what is set up still works for admins.
	if code, body := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/intel/feeds", ""); code == http.StatusForbidden {
		t.Errorf("admin GET /api/intel/feeds = %d %v", code, body)
	}
	// No AI model is used, whatever is set up.
	s.Assistant = &assistant.Client{}
	if s.model() != nil {
		t.Error("the demo uses an AI model")
	}
}

// Of the routes that work without signing in, only signing in and out and
// the CA certificate stay: no event intake, joins, installs, single
// sign-on, SCIM, passkeys or chat buttons. The agent port answers nothing.
func TestDemoPublicRoutesAreOff(t *testing.T) {
	ts, s := newDemoServer(t, "127.0.0.1/32")
	wildcard := regexp.MustCompile(`\{[^}.]+(\.\.\.)?\}`)
	for _, p := range publicRoutes {
		if slices.Contains(demoPublicRoutes, p) {
			continue
		}
		method, path, ok := strings.Cut(p, " ")
		if !ok {
			method, path = "POST", p
		}
		path = wildcard.ReplaceAllString(path, "x")
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), `"code":"demo_off"`) {
			t.Errorf("%s in demo mode = %d %s, want 403 demo_off", p, resp.StatusCode, raw)
		}
	}
	agents := httptest.NewServer(s.AgentHandler())
	defer agents.Close()
	for _, p := range []string{"/api/ingest", "/api/otlp/v1/logs", "/services/collector/event", "/api/osquery/enroll", "/api/sensor/install.sh"} {
		resp, err := http.Post(agents.URL+p, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "demo_off") {
			t.Errorf("agent port %s in demo mode = %d %s", p, resp.StatusCode, raw)
		}
	}
}

// The sign-in page offers the demo, and every page of the app shows the
// banner; neither shows when demo mode is off, and nobody can sign in to a
// demo that is not there.
func TestDemoPages(t *testing.T) {
	get := func(ts *httptest.Server, path string, c *http.Cookie) (int, string) {
		t.Helper()
		code, _, raw := call(t, ts, "GET", path, "", "", "", c)
		return code, raw
	}
	ts, _ := newDemoServer(t)
	if _, page := get(ts, "/login", nil); !strings.Contains(page, `<div id="demo">`) {
		t.Errorf("the demo's sign-in page: %s", page)
	}
	c := demoVisit(t, ts)
	if code, page := get(ts, "/", c); code != http.StatusOK || !strings.Contains(page, `<div id="demo-banner">`) {
		t.Errorf("the demo's app page = %d %s", code, page)
	}
	// A signed-in visitor goes on to the app.
	if code, _ := get(ts, "/login", c); code != http.StatusSeeOther {
		t.Errorf("the sign-in page for a visitor = %d, want 303", code)
	}

	ts, s := newDemoServer(t)
	s.Config.Demo.Enabled = false
	if _, page := get(ts, "/login", nil); !strings.Contains(page, `id="demo" hidden`) {
		t.Errorf("the sign-in page without demo mode: %s", page)
	}
	resp := send(t, "POST", ts.URL+"/api/demo", "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("demo sign-in without demo mode = %d, want 404", resp.StatusCode)
	}
	if code, out, c := login(t, ts, "vera", "role-password"); code != http.StatusOK || c == nil {
		t.Errorf("password sign-in without demo mode = %d %v", code, out)
	}
}

// Visitors' sign-ins are limited per address.
func TestDemoSignInsAreLimited(t *testing.T) {
	ts, _ := newDemoServer(t)
	for range 10 {
		demoVisit(t, ts)
	}
	resp := send(t, "POST", ts.URL+"/api/demo", "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("the 11th demo sign-in in a minute = %d, want 429 with Retry-After", resp.StatusCode)
	}
}

// Each demo visitor's searches count against a share of the search slots
// of their own; everyone else's against their user's.
func TestSearchUserPerDemoSession(t *testing.T) {
	a, b := demoPrincipal(), demoPrincipal()
	a.token, b.token = "token-a", "token-b"
	if searchUser(a) == searchUser(b) {
		t.Errorf("two visitors share %q", searchUser(a))
	}
	if !strings.HasPrefix(searchUser(a), demoUser+":") {
		t.Errorf("visitor's search user = %q", searchUser(a))
	}
	a2 := demoPrincipal()
	a2.token = "token-a"
	if searchUser(a) != searchUser(a2) {
		t.Error("one session's search user changes")
	}
	u := &principal{Username: "alice", Source: "local", token: "token-a"}
	if got := searchUser(u); got != "alice" {
		t.Errorf("user's search user = %q, want alice", got)
	}
}

// A visitor may run a notebook shared for editing, but the run is not
// kept in it, and the page offers no editing or copying.
func TestDemoVisitorRunsAreNotSaved(t *testing.T) {
	ts, _ := newDemoServer(t, "127.0.0.0/8", "::1/128")
	code, body, _, _ := nb(t, ts, "admin", "POST", "/api/notebooks", `{"from":"starter-powershell"}`, "")
	if code != 201 {
		t.Fatalf("copy starter = %d %v", code, body)
	}
	n := notebookOf(t, body)
	path := "/api/notebooks/" + n.ID
	if code, body, _, _ = nb(t, ts, "admin", "PUT", path, putBody(n, func(m map[string]any) { m["sharing"] = "edit" }), ""); code != 200 {
		t.Fatalf("share = %d %v", code, body)
	}
	c := demoVisit(t, ts)
	code, body, _ = call(t, ts, "GET", path, "", "", "", c)
	if can, _ := body["can"].(map[string]any); code != 200 || can["edit"] != false || can["copy"] != false || can["manage"] != false {
		t.Errorf("visitor sees %d %v", code, body)
	}
	if code, body, _ = call(t, ts, "POST", path+"/run", "", "", "", c); code != 200 || body["saved"] != false {
		t.Errorf("visitor run = %d %v", code, body)
	}
	_, body, _, _ = nb(t, ts, "admin", "GET", path, "", "")
	for _, cell := range notebookOf(t, body).Cells {
		if cell.Result != nil {
			t.Errorf("the visitor's run was kept in cell %s: %+v", cell.ID, cell.Result)
		}
	}
}
