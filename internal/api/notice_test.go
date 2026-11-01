// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jrsamsanchez/signalith/internal/oidc/oidctest"
)

// loginPage is the sign-in page as the server sends it.
func loginPage(t *testing.T, url string) string {
	t.Helper()
	resp, err := noRedirect.Get(url + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestSignInNotice(t *testing.T) {
	page, err := os.ReadFile("../../web/static/login.html")
	if err != nil {
		t.Fatal(err)
	}
	ts, _, logs := newSettingsServer(t, "", func(s *Server) {
		s.UI = fstest.MapFS{"index.html": {Data: []byte("<h1>app</h1>")}, "login.html": {Data: page}}
	})

	// Off by default: the page has the notice's box, hidden, and signing in
	// needs no tick.
	if p := loginPage(t, ts.URL); !strings.Contains(p, `id="notice" hidden`) || !strings.Contains(p, `id="notice-agree" hidden`) {
		t.Error("the notice shows while it is off")
	}
	login := func(body string) (int, map[string]any) {
		req, _ := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(body))
		req.Header.Set("Origin", ts.URL)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, out := login(`{"username":"admin","password":"s3cret-pass"}`); code != 200 {
		t.Fatalf("sign-in with no notice = %d %v", code, out)
	}

	// Saving it is checked: the length, invisible characters, and agree
	// with nothing to agree to.
	for name, values := range map[string]string{
		"too long":      `{"auth.notice.text":"` + strings.Repeat("a", 4001) + `"}`,
		"bidi":          `{"auth.notice.text":"Authorized use only ‮ylno"}`,
		"zero width":    `{"auth.notice.text":"adm​in"}`,
		"control":       `{"auth.notice.text":"bell \u0007"}`,
		"title break":   `{"auth.notice.title":"a\nb","auth.notice.text":"x"}`,
		"title long":    `{"auth.notice.title":"` + strings.Repeat("t", 81) + `","auth.notice.text":"x"}`,
		"agree no text": `{"auth.notice.agree":true}`,
	} {
		if code, out := do(t, ts, "PUT", "/api/settings", `{"values":`+values+`}`, true); code != 400 {
			t.Errorf("%s: saved = %d %v", name, code, out)
		}
	}

	text := "Authorized use only.\r\n<script>alert(1)</script> & <b>bold</b>\n\tMonitored."
	body, _ := json.Marshal(map[string]any{"values": map[string]any{
		"auth.notice.title": `Warning <img src=x onerror=alert(1)>`, "auth.notice.text": text, "auth.notice.agree": true}})
	if code, out := do(t, ts, "PUT", "/api/settings", string(body), true); code != 200 {
		t.Fatalf("save = %d %v", code, out)
	}
	// The change is in the audit log.
	if l := logs.String(); !strings.Contains(l, "settings saved") || !strings.Contains(l, "auth.notice.text=") || !strings.Contains(l, "auth.notice.agree=true") {
		t.Errorf("audit log has no notice change:\n%s", l)
	}

	// The page shows it at once, as plain text: nothing in it is HTML.
	p := loginPage(t, ts.URL)
	if strings.Contains(p, `id="notice" hidden`) || strings.Contains(p, `id="notice-agree" hidden`) {
		t.Error("the notice or its I agree is still hidden")
	}
	if strings.Contains(p, "<script>alert") || strings.Contains(p, "<img src=x") || strings.Contains(p, "<b>bold") {
		t.Error("the notice was put on the page as HTML")
	}
	if !strings.Contains(p, `id="notice-text" tabindex="0">Authorized use only.`+"\n"+`&lt;script&gt;alert(1)&lt;/script&gt; &amp; &lt;b&gt;bold&lt;/b&gt;`+"\n\tMonitored.</div>") {
		t.Errorf("notice text not shown as typed:\n%s", p)
	}
	if !strings.Contains(p, `id="notice-title">Warning &lt;img src=x onerror=alert(1)&gt;</h2>`) {
		t.Error("notice title not shown as typed")
	}

	// The Sign-in notice tab reads it back, for admins only.
	code, view := do(t, ts, "GET", "/api/auth/notice", "", true)
	if code != 200 || view["text"] != strings.ReplaceAll(text, "\r\n", "\n") || view["agree"] != true || view["on"] != true || view["editable"] != true {
		t.Errorf("notice view = %d %v", code, view)
	}
	if code, _ := doAs(t, ts, "andy", "role-password", "GET", "/api/auth/notice", ""); code != 403 {
		t.Errorf("analyst notice view = %d", code)
	}

	// Signing in now needs the tick, before the password is even checked.
	for _, b := range []string{`{"username":"admin","password":"s3cret-pass"}`, `{"username":"admin","password":"s3cret-pass","agreed":false}`, `{"username":"admin","password":"wrong","agreed":false}`} {
		if code, out := login(b); code != 400 || out["code"] != "notice_not_agreed" {
			t.Errorf("sign-in %s without agreeing = %d %v", b, code, out)
		}
	}
	if strings.Contains(logs.String(), "sign-in failed") {
		t.Error("a sign-in refused for the notice counted as a failed sign-in")
	}
	if code, out := login(`{"username":"admin","password":"s3cret-pass","agreed":true}`); code != 200 {
		t.Fatalf("sign-in after agreeing = %d %v", code, out)
	}
	if l := logs.String(); !strings.Contains(l, `msg="signed in"`) || !strings.Contains(l, "notice=agreed") {
		t.Errorf("sign-in not logged with the notice:\n%s", l)
	}
	// A passkey sign-in is refused without it too.
	req, _ := http.NewRequest("POST", ts.URL+"/api/login/passkey", strings.NewReader(`{"token":"x","credential":{}}`))
	req.Header.Set("Origin", ts.URL)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != 400 || out["code"] != "notice_not_agreed" {
		t.Errorf("passkey sign-in without agreeing = %d %v", resp.StatusCode, out)
	}
	// Scripts with a password over the API are not asked.
	if code, _ := do(t, ts, "GET", "/api/health", "", true); code != 200 {
		t.Errorf("Basic auth with the notice on = %d", code)
	}

	// Emptied, it is off again.
	if code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"auth.notice.text":"","auth.notice.agree":false}}`, true); code != 200 {
		t.Fatalf("turn off = %d %v", code, out)
	}
	if p := loginPage(t, ts.URL); !strings.Contains(p, `id="notice" hidden`) {
		t.Error("the notice still shows once emptied")
	}
	if code, out := login(`{"username":"admin","password":"s3cret-pass"}`); code != 200 {
		t.Errorf("sign-in with the notice off = %d %v", code, out)
	}
}

func TestSignInNoticeSSO(t *testing.T) {
	p := oidctest.New(t)
	ts, s := newSSOServer(t, p, nil)
	s.Config.Auth.Notice.Text = "Authorized use only."
	s.Config.Auth.Notice.Agree = true

	// Without the tick the sign-in does not start.
	resp := send(t, "GET", ts.URL+"/api/auth/oidc/start", "", nil)
	if loc := resp.Header.Get("Location"); loc != "/login?sso_error=notice" {
		t.Errorf("start without agreeing went to %q", loc)
	}
	// With it, it goes to the provider, and through the hop to the public
	// address too.
	resp = send(t, "GET", ts.URL+"/api/auth/oidc/start?agreed=1", "", nil)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, p.Issuer) {
		t.Errorf("start after agreeing went to %q", loc)
	}
	s.Config.Server.PublicURL = "https://siem.example.com:8443"
	resp = send(t, "GET", ts.URL+"/api/auth/oidc/start?agreed=1&next=/", "", nil)
	if loc := resp.Header.Get("Location"); loc != "https://siem.example.com:8443/api/auth/oidc/start?agreed=1&hop=1&next=%2F" {
		t.Errorf("hop went to %q", loc)
	}
	// SAML checks it when the sign-in starts too (here before it finds
	// SAML is off, which comes first).
	resp = send(t, "GET", ts.URL+"/api/auth/saml/start", "", nil)
	if loc := resp.Header.Get("Location"); loc != "/login?sso_error=off" {
		t.Errorf("SAML start = %q", loc)
	}
}
