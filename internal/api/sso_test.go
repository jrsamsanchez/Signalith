// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/oidc"
	"github.com/jrsamsanchez/signalith/internal/oidc/oidctest"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// ssoLoginPage is the part of login.html the server changes.
const ssoLoginPage = `<div class="auth__sso" id="sso" hidden><a href="api/auth/oidc/start"><span id="sso-label">Sign in with single sign-on</span></a></div>`

// newSSOServer starts a server whose single sign-on uses the mock
// provider p.
func newSSOServer(t *testing.T, p *oidctest.Provider, change func(o *config.OIDC)) (*httptest.Server, *Server) {
	t.Helper()
	yes := true
	ts, s := newUsersServer(t, func(s *Server) {
		s.UI = fstest.MapFS{"index.html": {Data: []byte("<h1>app</h1>")}, "login.html": {Data: []byte(ssoLoginPage)}}
		c := oidc.NewClient()
		c.HTTP = p.Client()
		c.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		s.OIDC = c
		s.Config.Auth.OIDC = config.OIDC{Enabled: true, Provider: "keycloak", Issuer: p.Issuer, ClientID: p.ClientID,
			ClientSecret: p.ClientSecret, AdminGroups: []string{"/soc-admins"}, AnalystGroups: []string{"/soc"},
			CreateUsers: &yes}
		if change != nil {
			change(&s.Config.Auth.OIDC)
		}
	})
	s.Config.Server.PublicURL = ts.URL
	return ts, s
}

// browser is a client that keeps cookies and follows redirects, trusting
// the mock provider.
func browser(t *testing.T, p *oidctest.Provider) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Transport: p.Client().Transport}
}

// ssoSignIn signs in with the button and returns where the browser ended
// up and that page.
func ssoSignIn(t *testing.T, b *http.Client, ts *httptest.Server, next string) (*url.URL, string) {
	t.Helper()
	u := ts.URL + "/api/auth/oidc/start"
	if next != "" {
		u += "?next=" + url.QueryEscape(next)
	}
	resp, err := b.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.Request.URL, string(raw)
}

func me(t *testing.T, b *http.Client, ts *httptest.Server) (int, map[string]any) {
	t.Helper()
	resp, err := b.Get(ts.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestSSOSignIn(t *testing.T) {
	p := oidctest.New(t)
	p.Set(func(p *oidctest.Provider) {
		p.Claims = map[string]any{"preferred_username": "Alice", "name": "Alice Example", "email": "alice@corp.example.com",
			"email_verified": true, "groups": []any{"/soc", "/everyone"}}
	})
	ts, s := newSSOServer(t, p, nil)

	// The sign-in page shows the button, with its label.
	resp := send(t, "GET", ts.URL+"/login", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("login page: %d", resp.StatusCode)
	}
	page := pageText(t, ts.URL+"/login")
	if strings.Contains(page, `id="sso" hidden`) || !strings.Contains(page, ">Sign in with Keycloak<") {
		t.Errorf("login page = %s", page)
	}

	b := browser(t, p)
	at, body := ssoSignIn(t, b, ts, "/#cases?id=7")
	if at.Path != "/api/auth/oidc/callback" || !strings.Contains(body, `content="0;url=/#cases?id=7"`) {
		t.Fatalf("ended at %s with %s", at, body)
	}
	code, who := me(t, b, ts)
	if code != 200 || who["username"] != "alice" || who["role"] != "analyst" {
		t.Fatalf("me = %d %v", code, who)
	}
	u, ok := s.userStore().Get("alice")
	if !ok || u.Source != users.SourceSSO || u.Email != "alice@corp.example.com" || u.Name != "Alice Example" ||
		u.Subject != users.SSOSubject(p.Issuer, "00u1abcd") {
		t.Fatalf("user = %+v", u)
	}
	// PKCE and the client secret went to the token endpoint.
	if p.LastTokenForm.Get("code_verifier") == "" || p.LastBasic[1] != p.ClientSecret {
		t.Errorf("token request: form %v basic %v", p.LastTokenForm, p.LastBasic)
	}

	// The role follows the groups at each sign-in.
	p.Set(func(p *oidctest.Provider) { p.Claims["groups"] = []any{"/soc-admins"} })
	b2 := browser(t, p)
	ssoSignIn(t, b2, ts, "")
	if _, who := me(t, b2, ts); who["role"] != "admin" {
		t.Errorf("role after group change = %v", who["role"])
	}

	// They have no password to change, and an admin can't edit their name.
	if code, body, _ := call(t, ts, "PUT", "/api/users/alice", `{"name":"Mallory"}`, "admin", adminPass, nil); code != 409 {
		t.Errorf("edit SSO user = %d %v", code, body)
	}

	// Moving to another provider ends the old provider's users' sessions.
	moved := *s.Config
	moved.Auth.OIDC.Issuer = "https://other.example.com"
	s.live.Store(&moved)
	if code, _ := me(t, b2, ts); code != 401 {
		t.Errorf("me after the issuer changed = %d", code)
	}
	// The session is gone, not just held: moving back doesn't revive it.
	s.live.Store(nil)
	if code, _ := me(t, b2, ts); code != 401 {
		t.Errorf("me after the issuer changed back = %d", code)
	}
	ssoSignIn(t, b2, ts, "")

	// Turning single sign-on off ends their sessions.
	off := *s.Config
	off.Auth.OIDC.Enabled = false
	s.live.Store(&off)
	if code, _ := me(t, b2, ts); code != 401 {
		t.Errorf("me with single sign-on off = %d", code)
	}
	if at, _ := ssoSignIn(t, browser(t, p), ts, ""); at.Path != "/login" || at.Query().Get("sso_error") != "off" {
		t.Errorf("start with single sign-on off ended at %s", at)
	}
	if page := pageText(t, ts.URL+"/login"); !strings.Contains(page, `id="sso" hidden`) {
		t.Errorf("login page shows the button while off")
	}
}

// pageText returns a page's body.
func pageText(t *testing.T, u string) string {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw)
}

func TestSSORefusals(t *testing.T) {
	p := oidctest.New(t)
	base := map[string]any{"preferred_username": "bob", "email": "bob@corp.example.com", "email_verified": true, "groups": []any{"/soc"}}
	for _, tc := range []struct {
		name   string
		claims map[string]any
		sub    string
		brk    string
		change func(o *config.OIDC)
		want   string
	}{
		{name: "no group", claims: map[string]any{"groups": []any{"/sales"}}, want: "role"},
		{name: "not added", change: func(o *config.OIDC) { no := false; o.CreateUsers = &no }, want: "new"},
		{name: "domain", change: func(o *config.OIDC) { o.AllowedDomains = []string{"example.org"} }, want: "domain"},
		{name: "unverified email for the domain", claims: map[string]any{"email_verified": false},
			change: func(o *config.OIDC) { o.AllowedDomains = []string{"corp.example.com"} }, want: "domain"},
		{name: "local user's name", claims: map[string]any{"preferred_username": "carol"}, want: "taken"},
		{name: "built-in admin", claims: map[string]any{"preferred_username": "admin"}, want: "taken"},
		{name: "no username", claims: map[string]any{"preferred_username": ""}, want: "username"},
		{name: "forged token", brk: "wrong-key", want: "failed"},
		{name: "unsigned token", brk: "alg-none", want: "failed"},
		{name: "another audience", brk: "wrong-audience", want: "failed"},
		{name: "another issuer", brk: "wrong-issuer", want: "failed"},
		{name: "replayed nonce", brk: "wrong-nonce", want: "failed"},
		{name: "expired token", brk: "expired", want: "failed"},
		{name: "token error", brk: "token-error", want: "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, s := newSSOServer(t, p, tc.change)
			if _, err := s.userStore().Create(t.Context(), users.NewUser{Username: "carol", Role: users.Analyst, Password: "a-long-password-1"}); err != nil {
				t.Fatal(err)
			}
			p.Set(func(p *oidctest.Provider) {
				p.Claims = map[string]any{}
				for k, v := range base {
					p.Claims[k] = v
				}
				for k, v := range tc.claims {
					p.Claims[k] = v
				}
				p.Break = map[string]bool{}
				if tc.brk != "" {
					p.Break[tc.brk] = true
				}
			})
			b := browser(t, p)
			at, _ := ssoSignIn(t, b, ts, "")
			if at.Path != "/login" || at.Query().Get("sso_error") != tc.want {
				t.Fatalf("ended at %s, want sso_error=%s", at, tc.want)
			}
			if code, _ := me(t, b, ts); code != 401 {
				t.Errorf("signed in anyway: %d", code)
			}
		})
	}
	p.Set(func(p *oidctest.Provider) { p.Break = map[string]bool{} })

	// Another identity at the provider with a name already taken by an
	// SSO user is refused, not let in as them.
	p.Set(func(p *oidctest.Provider) { p.Claims = base; p.Subject = "first" })
	ts, _ := newSSOServer(t, p, nil)
	b := browser(t, p)
	ssoSignIn(t, b, ts, "")
	if code, _ := me(t, b, ts); code != 200 {
		t.Fatalf("first sign-in: %d", code)
	}
	p.Set(func(p *oidctest.Provider) { p.Subject = "second" })
	if at, _ := ssoSignIn(t, browser(t, p), ts, ""); at.Query().Get("sso_error") != "taken" {
		t.Errorf("another identity ended at %s", at)
	}

	// A disabled SSO user stays out.
	if code, body, _ := call(t, ts, "PUT", "/api/users/bob", `{"disabled":true}`, "admin", adminPass, nil); code != 200 {
		t.Fatalf("disable: %d %v", code, body)
	}
	p.Set(func(p *oidctest.Provider) { p.Subject = "first" })
	if at, _ := ssoSignIn(t, browser(t, p), ts, ""); at.Query().Get("sso_error") != "disabled" {
		t.Errorf("disabled user ended at %s", at)
	}

	// Disabling them ended the session they had.
	if code, _ := me(t, b, ts); code != 401 {
		t.Errorf("disabled user's session still works: %d", code)
	}
}

func TestSSOState(t *testing.T) {
	p := oidctest.New(t)
	p.Set(func(p *oidctest.Provider) {
		p.Claims = map[string]any{"preferred_username": "dana", "groups": []any{"/soc"}}
	})
	ts, s := newSSOServer(t, p, nil)

	// A callback with no sign-in under way in this browser (a link from
	// someone else, say) is refused.
	resp := send(t, "GET", ts.URL+"/api/auth/oidc/callback?code=code-1&state=abc", "", nil)
	if loc := resp.Header.Get("Location"); loc != "/login?sso_error=expired" {
		t.Errorf("callback without the cookie went to %q", loc)
	}

	// Start, then come back with another state.
	b := browser(t, p)
	b.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := b.Get(ts.URL + "/api/auth/oidc/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	auth, _ := url.Parse(resp.Header.Get("Location"))
	q := auth.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" ||
		q.Get("redirect_uri") != ts.URL+"/api/auth/oidc/callback" {
		t.Fatalf("authorization request = %s", auth)
	}
	resp, err = b.Get(ts.URL + "/api/auth/oidc/callback?code=code-1&state=" + url.QueryEscape(q.Get("state")+"x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/login?sso_error=expired" {
		t.Errorf("wrong state went to %q", loc)
	}
	// The cookie is gone after one try, so the right state now fails too.
	resp, err = b.Get(ts.URL + "/api/auth/oidc/callback?code=code-1&state=" + url.QueryEscape(q.Get("state")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/login?sso_error=expired" {
		t.Errorf("second try went to %q", loc)
	}

	// The provider's error comes back as denied.
	resp = send(t, "GET", ts.URL+"/api/auth/oidc/callback?error=access_denied&state=x", "", nil)
	if loc := resp.Header.Get("Location"); loc != "/login?sso_error=denied" {
		t.Errorf("provider error went to %q", loc)
	}

	// A browser that came in by another address is sent to the public
	// one first, so the cookie lands where the provider sends it back.
	s.Config.Server.PublicURL = "https://siem.example.com:8443"
	resp = send(t, "GET", ts.URL+"/api/auth/oidc/start?next=/%23search", "", nil)
	if loc := resp.Header.Get("Location"); loc != "https://siem.example.com:8443/api/auth/oidc/start?hop=1&next=%2F%23search" {
		t.Errorf("start by another address went to %q", loc)
	}
}

func TestSSONextStaysHere(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "/",
		"/":                     "/",
		"/#cases?id=7":          "/#cases?id=7",
		"/?q=a+b#search":        "/?q=a+b#search",
		"//evil.example.com/":   "/",
		"/\\evil.example.com":   "/",
		"https://evil.example/": "/",
		"javascript:alert(1)":   "/",
		"/api/users":            "/",
		"/login":                "/",
		"evil.example.com":      "/",
		"/%2F%2Fevil.example":   "/",
		"/\r\nSet-Cookie: x=1":  "/",
		"/a\"><script>":         "/a%22%3E%3Cscript%3E",
	} {
		if got := localPath(in); got != want {
			t.Errorf("localPath(%q) = %q, want %q", in, got, want)
		}
	}
	// And the landing page escapes whatever it is given.
	p := oidctest.New(t)
	p.Set(func(p *oidctest.Provider) {
		p.Claims = map[string]any{"preferred_username": "erin", "groups": []any{"/soc"}}
	})
	ts, _ := newSSOServer(t, p, nil)
	_, body := ssoSignIn(t, browser(t, p), ts, "//evil.example.com/")
	if !strings.Contains(body, `content="0;url=/"`) {
		t.Errorf("landing = %s", body)
	}
}

func TestSSOTab(t *testing.T) {
	p := oidctest.New(t)
	ts, s := newSSOServer(t, p, nil)
	admin := func(method, path, body string) (int, map[string]any, string) {
		return call(t, ts, method, path, body, "admin", adminPass, nil)
	}
	code, body, raw := admin("GET", "/api/auth/oidc", "")
	if code != 200 || body["on"] != true || body["redirect_uri"] != ts.URL+"/api/auth/oidc/callback" || strings.Contains(raw, p.ClientSecret) {
		t.Fatalf("GET = %d %s", code, raw)
	}
	if len(body["presets"].([]any)) != len(oidc.Presets) {
		t.Errorf("presets = %v", body["presets"])
	}

	// The test reads discovery and the keys, with the saved secret.
	code, body, raw = admin("POST", "/api/auth/oidc/test", `{"values":{}}`)
	if code != 200 || body["ok"] != true {
		t.Fatalf("test = %d %s", code, raw)
	}
	// With an issuer that is not the provider's, it fails and says why.
	p2 := oidctest.New(t)
	p2.Set(func(p *oidctest.Provider) { p.Break["discovery-issuer"] = true })
	// The saved secret is only sent to the issuer it was entered for.
	_, body, raw = admin("POST", "/api/auth/oidc/test", `{"values":{"auth.oidc.issuer":"`+p2.Issuer+`"}}`)
	if f, _ := body["fields"].(map[string]any); f == nil || f["auth.oidc.client_secret"] == nil || p2.Count("/token") != 0 {
		t.Errorf("test with another issuer and the saved secret = %s", raw)
	}
	_, body, raw = admin("POST", "/api/auth/oidc/test", `{"values":{"auth.oidc.issuer":"`+p2.Issuer+`","auth.oidc.client_secret":"other"}}`)
	if body["ok"] != false {
		t.Errorf("test with a mismatched issuer = %s", raw)
	}
	if code, body, _ := admin("POST", "/api/auth/oidc/test", `{"values":{"auth.oidc.issuer":"http://idp.example.com"}}`); code != 400 || body["fields"] == nil {
		t.Errorf("test with http issuer = %d %v", code, body)
	}

	// Analysts can't see or test it.
	if _, err := s.userStore().Create(t.Context(), users.NewUser{Username: "ana", Role: users.Analyst, Password: "a-long-password-1"}); err != nil {
		t.Fatal(err)
	}
	for _, r := range [][2]string{{"GET", "/api/auth/oidc"}, {"POST", "/api/auth/oidc/test"}} {
		if code, _ := doAs(t, ts, "ana", "a-long-password-1", r[0], r[1], "{}"); code != 403 {
			t.Errorf("analyst %s %s = %d", r[0], r[1], code)
		}
	}
}

// An admin can disable an SSO user whatever name and email the provider
// sends, and those are kept as the Users page would take them.
func TestSSOUserWithOddNameCanBeDisabled(t *testing.T) {
	p := oidctest.New(t)
	long := strings.Repeat("Ö", 150)
	p.Set(func(p *oidctest.Provider) {
		p.Claims = map[string]any{"preferred_username": "odd", "name": long, "email": "Odd Person <odd@corp.example.com>",
			"email_verified": true, "groups": []any{"/soc"}}
	})
	ts, s := newSSOServer(t, p, nil)
	b := browser(t, p)
	ssoSignIn(t, b, ts, "")
	if code, _ := me(t, b, ts); code != 200 {
		t.Fatalf("sign-in: %d", code)
	}
	u, _ := s.userStore().Get("odd")
	if len([]rune(u.Name)) != 100 || u.Email != "" {
		t.Errorf("kept name %d characters, email %q", len([]rune(u.Name)), u.Email)
	}
	if code, body, _ := call(t, ts, "PUT", "/api/users/odd", `{"disabled":true}`, "admin", adminPass, nil); code != 200 {
		t.Fatalf("disable: %d %v", code, body)
	}
	if code, _ := me(t, b, ts); code != 401 {
		t.Errorf("disabled user's session still works: %d", code)
	}
}

// With the email as the username, it must be verified: otherwise anyone
// at a provider that lets people register could take any address.
func TestSSOEmailUsernameMustBeVerified(t *testing.T) {
	p := oidctest.New(t)
	ts, _ := newSSOServer(t, p, func(o *config.OIDC) {
		o.UsernameClaim = "email"
		o.AnalystGroups = append(o.AnalystGroups, "ceo@corp.example.com")
	})
	for _, tc := range []struct {
		verified any
		want     string
	}{{false, "username"}, {nil, "username"}, {true, ""}} {
		p.Set(func(p *oidctest.Provider) {
			p.Claims = map[string]any{"email": "ceo@corp.example.com"}
			if tc.verified != nil {
				p.Claims["email_verified"] = tc.verified
			}
		})
		at, _ := ssoSignIn(t, browser(t, p), ts, "")
		if got := at.Query().Get("sso_error"); got != tc.want {
			t.Errorf("email_verified %v: sso_error %q, want %q", tc.verified, got, tc.want)
		}
	}
}

// Entra ID's email counts as verified only with xms_edov.
func TestSSOEntraEmailNeedsEDOV(t *testing.T) {
	p := oidctest.New(t)
	ts, _ := newSSOServer(t, p, func(o *config.OIDC) {
		o.Provider = "entra"
		o.AdminGroups = []string{"boss@corp.example.com"}
		o.AnalystGroups = nil
	})
	for _, tc := range []struct {
		edov any
		want string
	}{{nil, "role"}, {false, "role"}, {true, ""}} {
		p.Set(func(p *oidctest.Provider) {
			p.Claims = map[string]any{"preferred_username": "boss", "email": "boss@corp.example.com"}
			if tc.edov != nil {
				p.Claims["xms_edov"] = tc.edov
			}
		})
		b := browser(t, p)
		at, _ := ssoSignIn(t, b, ts, "")
		if got := at.Query().Get("sso_error"); got != tc.want {
			t.Errorf("xms_edov %v: sso_error %q, want %q", tc.edov, got, tc.want)
		}
		if tc.want == "" {
			if _, who := me(t, b, ts); who["role"] != "admin" {
				t.Errorf("xms_edov true: role %v", who["role"])
			}
		}
	}
}

// The path in the sign-in cookie is checked again at the callback, so a
// cookie set by someone else can't send the browser to another site.
func TestSSONextCheckedAtCallback(t *testing.T) {
	p := oidctest.New(t)
	p.Set(func(p *oidctest.Provider) {
		p.Claims = map[string]any{"preferred_username": "fay", "groups": []any{"/soc"}}
	})
	ts, _ := newSSOServer(t, p, nil)
	b := browser(t, p)
	b.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := b.Get(ts.URL + "/api/auth/oidc/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	auth := resp.Header.Get("Location")
	base, _ := url.Parse(ts.URL)
	var ck *http.Cookie
	for _, c := range b.Jar.Cookies(base) {
		if c.Name == ssoCookie {
			ck = c
		}
	}
	if ck == nil {
		t.Fatal("no sign-in cookie")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(ck.Value)
	var st ssoState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	st.Next = "//evil.example.com/"
	raw, _ = json.Marshal(st)
	b.Jar.SetCookies(base, []*http.Cookie{{Name: ssoCookie, Value: base64.RawURLEncoding.EncodeToString(raw), Path: "/"}})
	b.CheckRedirect = nil
	resp, err = b.Get(auth)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `content="0;url=/"`) || strings.Contains(string(body), "evil") {
		t.Errorf("landing = %s", body)
	}
}
