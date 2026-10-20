// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// selfSigned writes a certificate and key for 127.0.0.1 and returns their
// paths.
func selfSigned(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "signalith test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certFile, keyFile
}

// asAdmin sends a request straight to the handler, as an admin on the
// computer at remote.
func asAdmin(srv *Server, method, path, body, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://siem.example.com:8080"+path, strings.NewReader(body))
	req.RemoteAddr = remote
	req.SetBasicAuth("admin", "s3cret-pass")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// A key typed on the page goes into use only with the address it was
// saved for, even when the address in use is another one: signalith.yaml
// changed since the start, or the server started without the page's
// settings.
func TestApplyLiveSendsASecretOnlyWhereItWasSaved(t *testing.T) {
	ts, srv, _ := newSettingsServer(t, "assistant:\n  provider: openai\n  url: http://127.0.0.1:18723/v1\n  model: llama3.1\n", nil)
	// signalith.yaml now names another address; the running server still
	// uses the first one.
	data, _ := os.ReadFile(srv.Config.Path())
	os.WriteFile(srv.Config.Path(), []byte(strings.Replace(string(data), "18723", "18724", 1)), 0o600)
	code, out, _ := call(t, ts, "PUT", "/api/settings", `{"values":{"assistant.api_key":"typed-for-18724"}}`, "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("save %d %v", code, out)
	}
	if m := srv.model(); m != nil && m.APIKey == "typed-for-18724" && !strings.Contains(m.URL, "18724") {
		t.Errorf("the key went into use for %s", m.URL)
	}

	// Started without the page's settings: nothing applies at once.
	dir := t.TempDir()
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, []byte("auth:\n  admin_password_hash: "+h+"\nassistant:\n  provider: openai\n  url: http://127.0.0.1:18723/v1\n  model: llama3.1\n"), 0o600)
	os.MkdirAll(filepath.Join(dir, "lookups"), 0o750)
	os.WriteFile(filepath.Join(dir, "lookups", "settings.yaml"), []byte("settings:\n  assistant.url:\n    value: http://127.0.0.1:18724/v1\n"), 0o600)
	cfg, err := config.LoadWithoutPage(path, "the web address was taken", []string{"server.listen"})
	if err != nil {
		t.Fatal(err)
	}
	ts2, _ := newTestServerWith(t, func(s *Server) { s.Config = cfg; srv = s })
	code, out = do(t, ts2, "PUT", "/api/settings", `{"values":{"assistant.api_key":"typed-for-18724"}}`, true)
	if code != 200 || len(out["applied"].([]any)) != 0 || len(out["after_restart"].([]any)) == 0 {
		t.Errorf("fallback save %d applied %v after restart %v", code, out["applied"], out["after_restart"])
	}
	if m := srv.model(); m != nil && m.APIKey == "typed-for-18724" {
		t.Errorf("the key went into use for %s while the page's settings are not in use", m.URL)
	}
	_, view := do(t, ts2, "GET", "/api/settings", "", true)
	if keys := view["startup_keys"].([]any); len(keys) != 1 || keys[0] != "server.listen" {
		t.Errorf("startup keys %v", keys)
	}
	if f := field(t, view, "server.listen"); f["startup_problem"] != true {
		t.Errorf("listen %v", f)
	}
}

// Save asks the server first what to confirm, and nothing is written
// until the real save.
func TestCheckOnly(t *testing.T) {
	cert, key := selfSigned(t)
	ts, srv, _ := newSettingsServer(t, "server:\n  listen: 0.0.0.0:18746\n  public_url: http://siem.example.com:18746\n  tls:\n    mode: off\n", nil)
	check := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "PUT", "/api/settings", body, "admin", "s3cret-pass", nil)
		return code, out
	}
	// A value the server refuses comes back before anything is asked.
	if code, out := check(`{"check_only":true,"values":{"server.listen":"not-an-address"}}`); code != 400 || out["fields"].(map[string]any)["server.listen"] == nil {
		t.Errorf("bad value %d %v", code, out)
	}
	code, out := check(`{"check_only":true,"values":{"server.listen":"0.0.0.0:18747"}}`)
	if code != 200 || out["ok"] != true {
		t.Fatalf("check %d %v", code, out)
	}
	confirm := out["confirm"].([]any)
	if len(confirm) != 2 {
		t.Fatalf("confirm %v", confirm)
	}
	if c := confirm[0].(map[string]any); c["key"] != "server.listen" || c["old"] != "0.0.0.0:18746" || c["new"] != "0.0.0.0:18747" {
		t.Errorf("listen %v", c)
	}
	// The public address agents use is on the old port: the page offers
	// to move it too.
	if c := confirm[1].(map[string]any); c["key"] != "server.public_url" || c["also"].(map[string]any)["value"] != "http://siem.example.com:18747" {
		t.Errorf("public address %v", c)
	}
	if _, err := os.Stat(srv.Config.SettingsFile()); !os.IsNotExist(err) {
		t.Errorf("check_only wrote the file: %v", err)
	}
	// HTTPS on: agents told http:// stop working.
	// json.Marshal, since Windows paths hold backslashes.
	paths, _ := json.Marshal(map[string]string{"server.tls.mode": "files", "server.tls_cert": cert, "server.tls_key": key})
	_, out = check(`{"check_only":true,"values":` + string(paths) + `}`)
	confirm = out["confirm"].([]any)
	texts := ""
	for _, c := range confirm {
		texts += c.(map[string]any)["text"].(string) + "\n"
	}
	if !strings.Contains(texts, "answer with https:// only") || !strings.Contains(texts, "http://siem.example.com:18746, the old address") {
		t.Errorf("https on: %s", texts)
	}
	// Safe changes ask nothing.
	if _, out = check(`{"check_only":true,"values":{"search.max_events":50}}`); len(out["confirm"].([]any)) != 0 {
		t.Errorf("safe change %v", out["confirm"])
	}
	// From another computer, a web address on loopback only says so.
	rec := asAdmin(srv, "PUT", "/api/settings", `{"check_only":true,"values":{"server.listen":"127.0.0.1:18747"}}`, "192.0.2.2:5555")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "You could not open this page again from here") {
		t.Errorf("loopback from afar %d %s", rec.Code, rec.Body)
	}
}

// Moving the web page to loopback from another computer needs a second
// yes, and is then not undone for want of a confirmation.
func TestRestartToLoopbackFromAnotherComputer(t *testing.T) {
	_, srv, _ := newSettingsServer(t, "server:\n  listen: 0.0.0.0:18726\n", nil)
	r := &fakeRestarter{}
	srv.Restarter = r
	if rec := asAdmin(srv, "PUT", "/api/settings", `{"values":{"server.listen":"127.0.0.1:18728"}}`, "192.0.2.2:5555"); rec.Code != 200 {
		t.Fatalf("save %d %s", rec.Code, rec.Body)
	}
	rec := asAdmin(srv, "POST", "/api/settings/restart", `{}`, "192.0.2.2:5555")
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"code":"local_only"`) || len(r.calls) != 0 {
		t.Fatalf("restart without a yes %d %s", rec.Code, rec.Body)
	}
	rec = asAdmin(srv, "POST", "/api/settings/restart", `{"local_only":true}`, "192.0.2.2:5555")
	if rec.Code != 202 || !strings.Contains(rec.Body.String(), `"reachable":false`) || len(r.localOnly) != 1 || !r.localOnly[0] {
		t.Errorf("restart with a yes %d %s %v", rec.Code, rec.Body, r.localOnly)
	}
	// On the server itself, nothing to ask.
	r.calls, r.localOnly = nil, nil
	if rec := asAdmin(srv, "POST", "/api/settings/restart", ``, "127.0.0.1:5555"); rec.Code != 202 || r.localOnly[0] {
		t.Errorf("restart from the server %d %s", rec.Code, rec.Body)
	}
	// While a move waits for someone at the new address, another restart
	// waits too.
	r.awaiting = true
	if rec := asAdmin(srv, "POST", "/api/settings/restart", ``, "127.0.0.1:5555"); rec.Code != 409 || !strings.Contains(rec.Body.String(), `"code":"awaiting"`) {
		t.Errorf("restart while awaiting %d %s", rec.Code, rec.Body)
	}
	if r.confirms == 0 {
		t.Error("the restart route did not try to confirm a move")
	}
}

// Addresses with a password in them are refused on the page, and when
// they come from signalith.yaml they are shown, logged and exported
// without it.
func TestAddressesWithPasswordsAreHidden(t *testing.T) {
	ts, _, logs := newSettingsServer(t, "opensearch:\n  proxy: http://proxyuser:Pr0xy-S3cret@proxy.example:3128\n", nil)
	code, out, raw := call(t, ts, "PUT", "/api/settings", `{"values":{"opensearch.url":"http://osadmin:Url-S3cret@127.0.0.1:18721"}}`, "admin", "s3cret-pass", nil)
	if code != 400 || !strings.Contains(out["fields"].(map[string]any)["opensearch.url"].(string), "own fields") {
		t.Errorf("url with a password %d %v", code, out)
	}
	if code, out, _ = call(t, ts, "PUT", "/api/settings", `{"values":{"assistant.url":"http://127.0.0.1:11434/v1?api_key=sk-1"}}`, "admin", "s3cret-pass", nil); code != 400 {
		t.Errorf("url with a key %d %v", code, out)
	}
	_, view, raw := call(t, ts, "GET", "/api/settings", "", "admin", "s3cret-pass", nil)
	if strings.Contains(raw, "Pr0xy-S3cret") || field(t, view, "opensearch.proxy")["value"] != "http://***@proxy.example:3128" {
		t.Errorf("proxy shown as %v", field(t, view, "opensearch.proxy")["value"])
	}
	_, out, raw = call(t, ts, "GET", "/api/settings/export", "", "admin", "s3cret-pass", nil)
	if strings.Contains(raw, "Pr0xy-S3cret") || !strings.Contains(out["yaml"].(string), "# proxy: left out, as it holds a password") {
		t.Errorf("export:\n%s", out["yaml"])
	}
	// The test sends the saved proxy, shown without its password, as saved.
	call(t, ts, "POST", "/api/settings/test/opensearch", `{"values":{"opensearch.url":"http://127.0.0.1:1","opensearch.proxy":"http://***@proxy.example:3128"}}`, "admin", "s3cret-pass", nil)
	if strings.Contains(logs.String(), "S3cret") {
		t.Errorf("log:\n%s", logs.String())
	}
}

// One connection test runs at a time.
func TestOneConnectionTestAtATime(t *testing.T) {
	ts, srv, _ := newSettingsServer(t, "opensearch:\n  url: http://127.0.0.1:1\n", nil)
	srv.testMu.Lock()
	defer srv.testMu.Unlock()
	code, out, _ := call(t, ts, "POST", "/api/settings/test/opensearch", `{}`, "admin", "s3cret-pass", nil)
	if code != 429 || out["code"] != "busy" {
		t.Errorf("second test %d %v", code, out)
	}
}

// A change a restart set aside shows on its field with why; Retry uses it
// again, and saving the field replaces it.
func TestSetAsideChanges(t *testing.T) {
	ts, srv, _ := newSettingsServer(t, "server:\n  listen: 127.0.0.1:18730\n", nil)
	file := srv.Config.SettingsFile()
	os.MkdirAll(filepath.Dir(file), 0o750)
	if _, err := config.MarkRefused(file, []string{"server.listen"}, "x"); err != nil {
		t.Fatal(err)
	}
	p := &config.PageSettings{}
	p.Set("server.listen", "127.0.0.1:18745", "admin", time.Now())
	if err := config.WritePageSettings(file, p); err != nil {
		t.Fatal(err)
	}
	if _, err := config.MarkRefused(file, []string{"server.listen"}, "Signalith cannot listen on 127.0.0.1:18745 (address already in use)."); err != nil {
		t.Fatal(err)
	}
	_, view := do(t, ts, "GET", "/api/settings", "", true)
	f := field(t, view, "server.listen")
	ref, _ := f["refused"].(map[string]any)
	if f["value"] != "127.0.0.1:18730" || f["pending"] != false || ref == nil || ref["value"] != "127.0.0.1:18745" || !strings.Contains(ref["reason"].(string), "already in use") {
		t.Errorf("set aside %v", f)
	}
	if list := view["refused"].([]any); len(list) != 1 {
		t.Errorf("refused %v", list)
	}
	code, out := do(t, ts, "PUT", "/api/settings", `{"retry":["server.listen"]}`, true)
	if f := field(t, out, "server.listen"); code != 200 || f["refused"] != nil || f["value"] != "127.0.0.1:18745" || f["pending"] != true {
		t.Errorf("retry %d %v", code, f)
	}
	config.MarkRefused(file, []string{"server.listen"}, "again")
	code, out = do(t, ts, "PUT", "/api/settings", `{"values":{"server.listen":"127.0.0.1:18746"}}`, true)
	if f := field(t, out, "server.listen"); code != 200 || f["refused"] != nil || f["value"] != "127.0.0.1:18746" {
		t.Errorf("changed again %d %v", code, f)
	}
}

// An empty public address, saved on the page, stays empty there: it is
// worked out from the listen address, like the default.
func TestEmptyPublicAddressStaysEmpty(t *testing.T) {
	ts, _, _ := newSettingsServer(t, "server:\n  listen: 127.0.0.1:18740\n  public_url: http://127.0.0.1:18746\n  tls:\n    mode: off\n", nil)
	code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"server.public_url":""}}`, true)
	f := field(t, out, "server.public_url")
	if code != 200 || f["value"] != "" || f["empty_means"] != "http://127.0.0.1:18740, worked out from the listen address" || f["source"].(map[string]any)["kind"] != "page" {
		t.Errorf("emptied %d %v", code, f)
	}
	if len(out["pending"].([]any)) != 0 {
		t.Errorf("pending %v", out["pending"])
	}
	_, exp := do(t, ts, "GET", "/api/settings/export", "", true)
	if !strings.Contains(exp["yaml"].(string), "  public_url: \"\"") {
		t.Errorf("export:\n%s", exp["yaml"])
	}
}

// The session cookie is Secure when the browser came over HTTPS, not
// because the public address says https://: a browser on plain HTTP would
// never send it back.
func TestSessionCookieFollowsTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		// proxyBelieved: X-Forwarded-Proto from this machine is believed.
		proxyBelieved bool
	}{
		// A file from before HTTPS was the default, which believes a proxy
		// on this machine.
		{"legacy", "", true},
		// HTTPS off: the request reaches the handlers over plain HTTP, as
		// it does in production.
		{"https off", "server:\n  tls:\n    mode: off\n", false},
		{"https off, trusted proxy", "server:\n  trusted_proxies: [127.0.0.1, '::1']\n  tls:\n    mode: off\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, srv, _ := newSettingsServer(t, tc.config, nil)
			code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"server.public_url":"https://siem.example.com:18720"}}`, true)
			if code != 200 || srv.conf().Server.PublicURL != "https://siem.example.com:18720" {
				t.Fatalf("save %d %v", code, out)
			}
			login := func(hdr map[string]string) string {
				t.Helper()
				resp := send(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"s3cret-pass"}`, hdr)
				return resp.Header.Get("Set-Cookie")
			}
			if c := login(map[string]string{"Origin": ts.URL}); c == "" || strings.Contains(c, "Secure") || strings.Contains(c, "__Host-") {
				t.Errorf("plain HTTP: %q", c)
			}
			if c := login(map[string]string{"Origin": ts.URL, "X-Forwarded-Proto": "https"}); strings.Contains(c, "Secure") != tc.proxyBelieved {
				t.Errorf("behind an HTTPS proxy: %q", c)
			}
		})
	}
}

// /api/me tells the Search page the default time range, and an admin
// asking it confirms a move of the web page.
func TestMeHasTheSearchDefault(t *testing.T) {
	ts, srv, _ := newSettingsServer(t, "search:\n  default_earliest: -4h\n", nil)
	r := &fakeRestarter{}
	srv.Restarter = r
	if code, me := do(t, ts, "GET", "/api/me", "", true); code != 200 || me["search_default_earliest"] != "-4h" {
		t.Errorf("me %d %v", code, me)
	}
	if r.confirms != 1 {
		t.Errorf("confirms %d", r.confirms)
	}
	if code, out := do(t, ts, "POST", "/api/settings/restart/confirm", "", true); code != 200 || out["confirmed"] != false {
		t.Errorf("confirm %d %v", code, out)
	}
}

// Saving a list of trusted proxies that leaves out the one this very
// request came through is refused: with HTTPS on, the next request
// through it would be sent to https:// or refused, and nobody could open
// the page through the proxy again to undo it.
func TestTrustedProxiesCannotLockOutTheProxyInUse(t *testing.T) {
	// A file from before HTTPS was the default, which believes a proxy on
	// this computer.
	ts, srv, _ := newSettingsServer(t, "", nil)
	if !srv.conf().Server.HTTPS() {
		t.Fatal("HTTPS is off")
	}
	plain := httptest.NewServer(srv.PlainHandler(srv.Handler()))
	defer plain.Close()
	viaProxy := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, plain.URL+path, strings.NewReader(body))
		req.SetBasicAuth("admin", "s3cret-pass")
		req.Host = "siem.lan"
		req.Header.Set("X-Forwarded-Proto", "https")
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	_, view := viaProxy("GET", "/api/settings", "")
	if f := field(t, view, "server.trusted_proxies"); !strings.Contains(f["empty_means"].(string), "private networks") {
		t.Errorf("empty means %v", f["empty_means"])
	}
	for _, body := range []string{
		`{"values":{"server.trusted_proxies":["10.0.0.9"]},"check_only":true}`,
		`{"values":{"server.trusted_proxies":["10.0.0.9"]}}`,
	} {
		code, out := viaProxy("PUT", "/api/settings", body)
		fields, _ := out["fields"].(map[string]any)
		if msg, _ := fields["server.trusted_proxies"].(string); code != 400 || !strings.Contains(msg, "through the reverse proxy at 127.0.0.1") {
			t.Errorf("%s: %d %v", body, code, out)
		}
	}
	if code, _ := viaProxy("GET", "/api/settings", ""); code != 200 {
		t.Fatalf("the proxy stopped working: %d", code)
	}
	// Listing it keeps it working.
	if code, out := viaProxy("PUT", "/api/settings", `{"values":{"server.trusted_proxies":["127.0.0.1","10.0.0.9"]}}`); code != 200 {
		t.Fatalf("listing the proxy: %d %v", code, out)
	}
	if code, _ := viaProxy("GET", "/api/settings", ""); code != 200 {
		t.Fatalf("the listed proxy stopped working: %d", code)
	}
	_, view = viaProxy("GET", "/api/settings", "")
	if f := field(t, view, "server.trusted_proxies"); f["empty_means"] != "none" {
		t.Errorf("empty means with a list %v", f["empty_means"])
	}
	// From a browser that does not use the proxy, the admin decides.
	if code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"server.trusted_proxies":["10.0.0.9"]}}`, true); code != 200 {
		t.Errorf("without the proxy: %d %v", code, out)
	}
}

// HTTPS turned on from behind a trusted proxy keeps the page at the
// proxy's address: the restart names no new address to go to.
func TestHTTPSOnBehindAProxyStaysAtTheProxy(t *testing.T) {
	ts, srv, _ := newSettingsServer(t, "server:\n  listen: 127.0.0.1:18766\n  public_url: https://siem.example.com\n  trusted_proxies: [127.0.0.1, '::1']\n  tls:\n    mode: off\n", nil)
	srv.Restarter = &fakeRestarter{}
	viaProxy := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.SetBasicAuth("admin", "s3cret-pass")
		req.Host = "siem.example.com"
		req.Header.Set("X-Forwarded-Proto", "https")
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, out := viaProxy("PUT", "/api/settings", `{"values":{"server.tls.mode":"auto"}}`); code != 200 {
		t.Fatalf("save %d %v", code, out)
	}
	code, out := viaProxy("POST", "/api/settings/restart", "")
	if code != 202 || out["go_to"] != nil || out["listen_changed"] != false {
		t.Errorf("restart through the proxy: %d %v", code, out)
	}
	// Directly, the page moves to https:// at the listen address.
	code, out = do(t, ts, "POST", "/api/settings/restart", "", true)
	if code != 202 || out["go_to"] != "https://127.0.0.1:18766/" {
		t.Errorf("restart without the proxy: %d %v", code, out)
	}
}
