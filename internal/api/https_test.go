package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// newPlainSide serves the plain-HTTP side of the HTTPS port.
func newPlainSide(t *testing.T, change func(*Server)) (*httptest.Server, *Server) {
	t.Helper()
	var srv *Server
	full, _ := newTestServerWith(t, func(s *Server) {
		withUI(s)
		if change != nil {
			change(s)
		}
		srv = s
	})
	full.Close()
	ts := httptest.NewServer(srv.PlainHandler(srv.Handler()))
	t.Cleanup(ts.Close)
	return ts, srv
}

func plainSend(t *testing.T, method, url, body string, hdr map[string]string, cookies ...*http.Cookie) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
		}
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestPlainHTTPGoesToHTTPS(t *testing.T) {
	ts, _ := newPlainSide(t, nil)
	host := map[string]string{"Host": "siem.example.com:8080"}

	// Pages and API reads: the same address over HTTPS.
	for path, want := range map[string]string{
		"/":                       "https://siem.example.com:8080/",
		"/login?next=%2Fcases":    "https://siem.example.com:8080/login?next=%2Fcases",
		"/api/tls/ca.pem":         "https://siem.example.com:8080/api/tls/ca.pem",
		"/assets/app.css?v=2#top": "https://siem.example.com:8080/assets/app.css?v=2",
	} {
		resp, _ := plainSend(t, "GET", ts.URL+path, "", host)
		if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != want {
			t.Errorf("GET %s: %d %q, want %s", path, resp.StatusCode, resp.Header.Get("Location"), want)
		}
		if resp.Header.Get("Strict-Transport-Security") != "" {
			t.Errorf("GET %s: HSTS over plain HTTP", path)
		}
	}
	// A Host header that is not a host is not echoed into the redirect.
	resp, _ := plainSend(t, "GET", ts.URL+"/", "", map[string]string{"Host": "evil.example/x"})
	if loc := resp.Header.Get("Location"); loc != "https://127.0.0.1:8080/" {
		t.Errorf("bad Host: Location %q", loc)
	}
	// No port in Host: the browser used port 80, which serves HTTPS now;
	// https:// alone would send it to 443.
	resp, _ = plainSend(t, "GET", ts.URL+"/search?q=1", "", map[string]string{"Host": "siem.corp"})
	if loc := resp.Header.Get("Location"); loc != "https://siem.corp:80/search?q=1" {
		t.Errorf("Host without a port: Location %q", loc)
	}

	// Passwords and sessions are never taken over plain HTTP.
	resp, body := plainSend(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"s3cret-pass"}`, host)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "https://siem.example.com:8080/api/login") || len(resp.Cookies()) != 0 {
		t.Errorf("sign-in over plain HTTP: %d %s %v", resp.StatusCode, body, resp.Cookies())
	}
	basic := map[string]string{"Host": "siem.example.com:8080", "Authorization": "Basic YWRtaW46czNjcmV0LXBhc3M="}
	for _, m := range []string{"GET", "POST"} {
		resp, body = plainSend(t, m, ts.URL+"/api/health", "", basic)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "only accepts passwords over HTTPS") {
			t.Errorf("%s with Basic: %d %s", m, resp.StatusCode, body)
		}
	}
	old := &http.Cookie{Name: sessionCookie, Value: "from-before"}
	resp, body = plainSend(t, "GET", ts.URL+"/api/cases", "", host, old)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "sessions") {
		t.Errorf("API with a session over plain HTTP: %d %s", resp.StatusCode, body)
	}
	// A browser with a cookie from before HTTPS: sent on, and told to
	// forget the cookie.
	resp, _ = plainSend(t, "GET", ts.URL+"/", "", host, old)
	if resp.StatusCode != http.StatusPermanentRedirect || len(resp.Cookies()) != 1 || resp.Cookies()[0].MaxAge >= 0 {
		t.Errorf("page with an old cookie: %d %v", resp.StatusCode, resp.Cookies())
	}
	// Other writes are refused, not redirected.
	resp, body = plainSend(t, "POST", ts.URL+"/api/search", `{"query":"*"}`, host)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "https://") {
		t.Errorf("POST over plain HTTP: %d %s", resp.StatusCode, body)
	}
}

// TestPlainIngestReachesOnlyIngest checks that a plain-HTTP request let
// through as agent ingest can only ever be ingest: an escaped path that
// the API's router would not take for ingest is refused like any other,
// so a password sent with it is never checked in clear text.
func TestPlainIngestReachesOnlyIngest(t *testing.T) {
	ts, s := newPlainSide(t, nil)
	if !s.Config.Server.PlaintextIngest() {
		t.Fatal("plain-text ingest is off for an old config")
	}
	for _, pw := range []string{"wrong-password", "s3cret-pass"} {
		req, _ := http.NewRequest("POST", ts.URL+"/api%2Fingest", strings.NewReader("[]"))
		req.URL.RawPath, req.URL.Path = "/api%2Fingest", "/api/ingest"
		req.SetBasicAuth("admin", pw)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "only accepts passwords over HTTPS") {
			t.Errorf("/api%%2Fingest with %s: %d %s", pw, resp.StatusCode, b)
		}
	}
	// Ingest itself never looks at a password: the agent's token decides.
	basic := map[string]string{"Authorization": "Basic YWRtaW46czNjcmV0LXBhc3M="}
	if resp, _ := plainSend(t, "POST", ts.URL+"/api/ingest", "[]", basic); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("ingest with Basic: %d", resp.StatusCode)
	}
}

func TestPlainIngest(t *testing.T) {
	batch := `[{"date":1760000000,"log":"Accepted password for bob from 192.0.2.4 port 22 ssh2"}]`
	bearer := map[string]string{"Authorization": "Bearer tok-0123456789abcdef"}

	// A config from before HTTPS was the default: old agents still send.
	ts, s := newPlainSide(t, nil)
	if !s.Config.Server.PlaintextIngest() {
		t.Fatal("plain-text ingest is off for an old config")
	}
	resp, body := plainSend(t, "POST", ts.URL+"/api/ingest", batch, bearer)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("plain ingest allowed: %d %s", resp.StatusCode, body)
	}
	senders := s.Pipeline.PlaintextSenders(time.Time{})
	if len(senders) != 1 || senders[0].Address != "127.0.0.1" || senders[0].Requests != 1 {
		t.Errorf("senders = %+v", senders)
	}
	// A wrong token is refused and not listed as sending, but as refused.
	resp, _ = plainSend(t, "POST", ts.URL+"/api/ingest", batch, map[string]string{"Authorization": "Bearer wrong-token-0123456"})
	if resp.StatusCode != http.StatusUnauthorized || s.Pipeline.PlaintextSenders(time.Time{})[0].Requests != 1 {
		t.Errorf("wrong token: %d", resp.StatusCode)
	}
	if r := s.Pipeline.RefusedSenders(time.Time{}); len(r) != 1 || r[0].Reason != ingest.RefusedToken {
		t.Errorf("refused = %+v", r)
	}
	// The Health page names the agent and says how to move it.
	code, h := do(t, mustServe(t, s), "GET", "/api/health", "", true)
	warn, _ := json.Marshal(h["warnings"])
	if code != 200 || !strings.Contains(string(warn), "over plain HTTP, which anyone on the network can read: 127.0.0.1.") || !strings.Contains(string(warn), "plaintext_ingest: deny") || h["plaintext_senders"] == nil ||
		!strings.Contains(string(warn), "wrong or missing ingest token: 127.0.0.1") {
		t.Errorf("health: %d %v", code, h)
	}

	// Denied: nothing is stored, and the agent is told to try again
	// later (503), so Fluent Bit keeps the batch instead of dropping it
	// as it does for a 4xx; the Health page names it.
	ts, s = newPlainSide(t, func(s *Server) {
		s.Config.Server.TLS = &config.ServerTLS{Mode: "auto", PlaintextIngest: "deny"}
	})
	resp, body = plainSend(t, "POST", ts.URL+"/api/ingest", batch, bearer)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" || !strings.Contains(body, "Add data") || !strings.Contains(body, "sends it again") {
		t.Errorf("plain ingest denied: %d %s", resp.StatusCode, body)
	}
	if len(s.Pipeline.PlaintextSenders(time.Time{})) != 0 || s.Pipeline.Stats().Received != 0 {
		t.Error("a denied batch was counted")
	}
	_, h = do(t, mustServe(t, s), "GET", "/api/health", "", true)
	if warn, _ := json.Marshal(h["warnings"]); !strings.Contains(string(warn), "turned away for sending over plain HTTP (server.tls.plaintext_ingest is deny): 127.0.0.1") {
		t.Errorf("health after a refusal: %s", warn)
	}
	// Without a token of this server's, it is refused as over HTTPS (401,
	// not told to try again) and not counted as an agent on plain HTTP.
	ts, s = newPlainSide(t, func(s *Server) {
		s.Config.Server.TLS = &config.ServerTLS{Mode: "auto", PlaintextIngest: "deny"}
	})
	for _, hdr := range []map[string]string{{"Authorization": "Bearer wrong-token-0123456"}, nil} {
		resp, body = plainSend(t, "POST", ts.URL+"/api/ingest", batch, hdr)
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Retry-After") != "" || !strings.Contains(body, "missing or invalid ingest token") {
			t.Errorf("plain ingest denied, token %v: %d %s", hdr, resp.StatusCode, body)
		}
	}
	if r := s.Pipeline.RefusedSenders(time.Time{}); len(r) != 1 || r[0].Reason != ingest.RefusedToken {
		t.Errorf("refused = %+v", r)
	}
}

// TestOldDockerToken checks agents set up by the older Docker quick
// start, which all sent the example token change-this-ingest-token over
// plain HTTP. On a quick start upgraded from it they keep sending over
// plain HTTP while that is allowed (by default there), and are listed to
// update. Over HTTPS, and before Signalith knows whether the quick start
// was upgraded, the token is refused with 503, which Fluent Bit keeps and
// sends again. On a quick start installed new, and anywhere else, it is
// just a wrong token, since anyone can look it up: 401, even over plain
// HTTP.
func TestOldDockerToken(t *testing.T) {
	batch := `[{"Computer":"WIN-01","EventID":4624,"Channel":"Security"}]`
	old := map[string]string{"Authorization": "Bearer change-this-ingest-token"}
	// The Docker quick start's own config: HTTPS, plaintext_ingest not set.
	quickStart := func(u *config.DockerUpgrade, change ...func(*Server)) func(*Server) {
		return func(s *Server) {
			s.Runtime = &Runtime{OS: "linux", Container: true, Addresses: []string{}}
			s.Config.Server.TLS = &config.ServerTLS{Mode: "auto"}
			s.Config = s.Config.WithDockerUpgrade(u)
			for _, f := range change {
				f(s)
			}
		}
	}
	overHTTPS := func(s *Server, token string) int {
		t.Helper()
		ts := httptest.NewTLSServer(s.Handler())
		defer ts.Close()
		req, _ := http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(batch))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	upgraded := &config.DockerUpgrade{Upgraded: true, Decided: time.Now()}

	ts, s := newPlainSide(t, quickStart(upgraded))
	if !s.Config.Server.PlaintextIngest() {
		t.Error("an upgraded quick start refuses agents on plain HTTP")
	}
	if resp, body := plainSend(t, "POST", ts.URL+"/api/ingest", batch, old); resp.StatusCode != http.StatusOK {
		t.Fatalf("old agent over plain HTTP: %d %s", resp.StatusCode, body)
	}
	if p := s.Pipeline.PlaintextSenders(time.Time{}); len(p) != 1 || !slices.Equal(p[0].Hosts, []string{"WIN-01"}) {
		t.Errorf("plain senders %+v", p)
	}
	_, h := do(t, mustServe(t, s), "GET", "/api/health", "", true)
	if warn, _ := json.Marshal(h["warnings"]); !strings.Contains(string(warn), "127.0.0.1 (WIN-01)") || !strings.Contains(string(warn), "Docker's port forwarding") ||
		!strings.Contains(string(warn), "That also ends for good the example token change-this-ingest-token") {
		t.Errorf("health: %s", warn)
	}
	// Over HTTPS: refused, but kept by the agent.
	if code := overHTTPS(s, "change-this-ingest-token"); code != http.StatusServiceUnavailable {
		t.Errorf("old token over HTTPS: %d", code)
	}
	if r := s.Pipeline.RefusedSenders(time.Time{}); len(r) != 1 || r[0].Reason != ingest.RefusedOldToken {
		t.Errorf("refused %+v", r)
	}
	// Plain-text ingest denied: refused like every plain-HTTP agent, and
	// so once the token has ended.
	for name, u := range map[string]*config.DockerUpgrade{"denied": upgraded, "ended": {Upgraded: true, Decided: time.Now(), Ended: time.Now()}} {
		ts, s = newPlainSide(t, quickStart(u, func(s *Server) { s.Config.Server.TLS.PlaintextIngest = "deny" }))
		if resp, _ := plainSend(t, "POST", ts.URL+"/api/ingest", batch, old); resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("%s: old token over plain HTTP: %d", name, resp.StatusCode)
		}
		if r := s.Pipeline.RefusedSenders(time.Time{}); len(r) != 1 || r[0].Reason != ingest.RefusedPlaintext {
			t.Errorf("%s: refused %+v", name, r)
		}
	}
	// Ended, with agents on plain HTTP accepted again: still refused, as a
	// batch the agent keeps.
	ts, s = newPlainSide(t, quickStart(&config.DockerUpgrade{Upgraded: true, Decided: time.Now(), Ended: time.Now()},
		func(s *Server) { s.Config.Server.TLS.PlaintextIngest = "allow" }))
	if resp, _ := plainSend(t, "POST", ts.URL+"/api/ingest", batch, old); resp.StatusCode != http.StatusServiceUnavailable || s.Pipeline.Stats().Received != 0 {
		t.Errorf("ended, plain allowed again: %d", resp.StatusCode)
	}
	// Not decided yet: refused, as a batch the agent keeps.
	ts, s = newPlainSide(t, quickStart(nil, func(s *Server) { s.Config.Server.TLS.PlaintextIngest = "allow" }))
	if resp, _ := plainSend(t, "POST", ts.URL+"/api/ingest", batch, old); resp.StatusCode != http.StatusServiceUnavailable || s.Pipeline.Stats().Received != 0 {
		t.Errorf("not decided: %d", resp.StatusCode)
	}

	// A quick start installed new: a wrong token, over plain HTTP too,
	// and nothing is stored.
	fresh := &config.DockerUpgrade{Decided: time.Now()}
	ts, s = newPlainSide(t, quickStart(fresh))
	if s.Config.Server.PlaintextIngest() {
		t.Error("a new quick start accepts agents on plain HTTP")
	}
	if resp, body := plainSend(t, "POST", ts.URL+"/api/ingest", batch, old); resp.StatusCode != http.StatusUnauthorized || s.Pipeline.Stats().Received != 0 ||
		resp.Header.Get("Retry-After") != "" || !strings.Contains(body, "missing or invalid ingest token") {
		t.Errorf("new quick start, plain HTTP: %d %s", resp.StatusCode, body)
	}
	if code := overHTTPS(s, "change-this-ingest-token"); code != http.StatusUnauthorized {
		t.Errorf("new quick start, HTTPS: %d", code)
	}
	if r := s.Pipeline.RefusedSenders(time.Time{}); len(r) != 1 || r[0].Reason != ingest.RefusedToken {
		t.Errorf("refused %+v", r)
	}
	// Its own agents' token is refused over plain HTTP as a batch they
	// keep, and works over HTTPS.
	if resp, _ := plainSend(t, "POST", ts.URL+"/api/ingest", batch, map[string]string{"Authorization": "Bearer tok-0123456789abcdef"}); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("new quick start, own token over plain HTTP: %d", resp.StatusCode)
	}
	if code := overHTTPS(s, "tok-0123456789abcdef"); code != http.StatusOK {
		t.Errorf("new quick start, own token over HTTPS: %d", code)
	}
	// Agents on plain HTTP accepted there by choice: still a wrong token.
	ts, s = newPlainSide(t, quickStart(fresh, func(s *Server) { s.Config.Server.TLS.PlaintextIngest = "allow" }))
	if resp, _ := plainSend(t, "POST", ts.URL+"/api/ingest", batch, old); resp.StatusCode != http.StatusUnauthorized || s.Pipeline.Stats().Received != 0 {
		t.Errorf("new quick start, plain HTTP accepted: %d", resp.StatusCode)
	}
	// Not in a container: that token was never this server's.
	ts, s = newPlainSide(t, func(s *Server) {
		s.Runtime = &Runtime{OS: "linux", Addresses: []string{}}
		s.Config = s.Config.WithDockerUpgrade(upgraded)
	})
	if resp, _ := plainSend(t, "POST", ts.URL+"/api/ingest", batch, old); resp.StatusCode != http.StatusUnauthorized || s.Pipeline.Stats().Received != 0 {
		t.Errorf("old token outside a container: %d", resp.StatusCode)
	}
}

// TestOldDockerTokenEnds checks that refusing agents on plain HTTP on an
// upgraded Docker quick start ends the example token for good: it is
// noted in the state folder, and accepting them again does not bring the
// token back.
func TestOldDockerTokenEnds(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	if err := config.WriteDockerUpgrade(state, &config.DockerUpgrade{Upgraded: true, Decided: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ts, srv, _ := newSettingsServer(t, "server:\n  listen: 0.0.0.0:18749\n  tls:\n    mode: auto\n", func(s *Server) {
		s.Runtime = &Runtime{OS: "linux", Container: true, Addresses: []string{}}
	})
	if srv.Config.OldToken() != config.OldTokenAccepted || !srv.Config.Server.PlaintextIngest() {
		t.Fatalf("loaded: %v %v", srv.Config.OldToken(), srv.Config.Server.PlaintextIngest())
	}
	plain := httptest.NewServer(srv.PlainHandler(srv.Handler()))
	defer plain.Close()
	send := func(token string) int {
		t.Helper()
		resp, _ := plainSend(t, "POST", plain.URL+"/api/ingest", `[{"log":"hello"}]`, map[string]string{"Authorization": "Bearer " + token})
		return resp.StatusCode
	}
	if code := send("change-this-ingest-token"); code != http.StatusOK {
		t.Fatalf("old token before: %d", code)
	}
	// Starting with agents on plain HTTP accepted changes nothing.
	srv.EndOldTokenIfRefused()
	if u, _ := config.ReadDockerUpgrade(state); u == nil || !u.Ended.IsZero() {
		t.Fatalf("ended while accepted: %+v", u)
	}
	if code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"server.tls.plaintext_ingest":"deny"}}`, true); code != 200 {
		t.Fatalf("deny %d %v", code, out)
	}
	u, err := config.ReadDockerUpgrade(state)
	if err != nil || u == nil || !u.Upgraded || u.Ended.IsZero() {
		t.Fatalf("after deny: %+v %v", u, err)
	}
	if srv.Running().OldToken() != config.OldTokenEnded {
		t.Errorf("running: %v", srv.Running().OldToken())
	}
	do(t, ts, "PUT", "/api/settings", `{"values":{"server.tls.plaintext_ingest":"allow"}}`, true)
	if code := send("change-this-ingest-token"); code != http.StatusServiceUnavailable {
		t.Errorf("old token after it ended, plain HTTP accepted again: %d", code)
	}
	if code := send("tok-0123456789abcdef"); code != http.StatusOK {
		t.Errorf("own token, plain HTTP accepted again: %d", code)
	}
	// A restart reads it from the state folder.
	c, err := config.Load(srv.Config.Path())
	if err != nil {
		t.Fatal(err)
	}
	if c.OldToken() != config.OldTokenEnded {
		t.Errorf("after a restart: %v", c.OldToken())
	}
}

// TestAgentsGetTheServersOwnToken checks that new agent configs never
// carry the public example token while the server has a token of its own,
// whichever order they are listed in.
func TestAgentsGetTheServersOwnToken(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Config.Ingest.Tokens = []string{"change-this-ingest-token", "own-token-0123456789abcdef"}
	})
	_, body := do(t, ts, "GET", "/api/agents/config?os=linux", "", true)
	cfg, _ := body["config"].(string)
	if !strings.Contains(cfg, "Bearer own-token-0123456789abcdef") || strings.Contains(cfg, "change-this") {
		t.Errorf("config:\n%s", cfg)
	}
}

// TestLegacyConfigBehindProxy checks a config from before HTTPS was the
// default, behind a reverse proxy set up the way older versions said: it
// sends X-Forwarded-Proto: https and public_url was left http://. The
// proxy keeps working (no redirect loop, sign-in works), and the Health
// page asks for server.trusted_proxies.
func TestLegacyConfigBehindProxy(t *testing.T) {
	ts, s := newPlainSide(t, nil)
	proxy := map[string]string{"Host": "siem.example.com", "X-Forwarded-Proto": "https"}
	if resp, _ := plainSend(t, "GET", ts.URL+"/", "", proxy); resp.StatusCode == http.StatusPermanentRedirect {
		t.Errorf("page behind the proxy redirected to %s", resp.Header.Get("Location"))
	}
	resp, body := plainSend(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"s3cret-pass"}`, proxy)
	if resp.StatusCode != http.StatusOK || len(resp.Cookies()) == 0 || resp.Cookies()[0].Name != secureSessionCookie {
		t.Errorf("sign-in behind the proxy: %d %s %v", resp.StatusCode, body, resp.Cookies())
	}
	_, h := do(t, mustServe(t, s), "GET", "/api/health", "", true)
	if warn, _ := json.Marshal(h["warnings"]); !strings.Contains(string(warn), "server.trusted_proxies: [127.0.0.1]") {
		t.Errorf("health: %s", warn)
	}
	// Without the header it is a browser on plain HTTP: redirected.
	if resp, _ := plainSend(t, "GET", ts.URL+"/", "", map[string]string{"Host": "siem.example.com:8080"}); resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("plain page: %d", resp.StatusCode)
	}
	// A config written for HTTPS believes only server.trusted_proxies.
	ts, _ = newPlainSide(t, func(s *Server) { s.Config.Server.TLS = &config.ServerTLS{Mode: "auto"} })
	if resp, _ := plainSend(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"s3cret-pass"}`, proxy); resp.StatusCode != http.StatusForbidden {
		t.Errorf("new config, unlisted proxy: %d", resp.StatusCode)
	}
}

// TestLoginPageOffersTheCA checks that the sign-in page links the CA
// certificate only when there is one to download, so it never asks for
// one that is not there.
func TestLoginPageOffersTheCA(t *testing.T) {
	page := func(s *httptest.Server) string {
		resp, err := http.Get(s.URL + "/login")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	const both = `<p id="ca-help" hidden><a href="api/tls/ca.pem">Download</a></p><p id="ca-next" hidden><a href="api/tls/ca.pem?which=next">New</a></p>`
	certs := newCertManager(t)
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.UI = fstest.MapFS{"login.html": {Data: []byte(both)}}
		s.TLS = certs
	})
	if p := page(ts); !strings.Contains(p, `id="ca-help">`) || !strings.Contains(p, `id="ca-next" hidden`) {
		t.Errorf("with a CA: %s", p)
	}
	// While a new certificate authority waits, the page offers it too.
	if err := certs.Prepare("standard"); err != nil {
		t.Fatal(err)
	}
	if p := page(ts); !strings.Contains(p, `id="ca-next">`) {
		t.Errorf("with a new CA ready: %s", p)
	}
	ts, _ = newTestServerWith(t, func(s *Server) {
		s.UI = fstest.MapFS{"login.html": {Data: []byte(`<p id="ca-help" hidden><a href="api/tls/ca.pem">Download</a></p>`)}}
	})
	if p := page(ts); !strings.Contains(p, `id="ca-help" hidden`) {
		t.Errorf("without a CA: %s", p)
	}
}

// mustServe serves s's normal handler.
func mustServe(t *testing.T, s *Server) *httptest.Server {
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestTrustedProxyIsServed(t *testing.T) {
	ts, _ := newPlainSide(t, func(s *Server) { s.Config.Server.TrustedProxies = []string{"127.0.0.1"} })
	hdr := map[string]string{"X-Forwarded-Proto": "https", "Authorization": "Basic YWRtaW46czNjcmV0LXBhc3M=", "Host": "siem.example.com"}
	resp, body := plainSend(t, "GET", ts.URL+"/api/health", "", hdr)
	if resp.StatusCode != 200 || resp.Header.Get("Strict-Transport-Security") == "" {
		t.Errorf("trusted proxy: %d %s", resp.StatusCode, body)
	}
	// Not trusted: the header is ignored.
	ts, _ = newPlainSide(t, func(s *Server) { s.Config.Server.TrustedProxies = []string{"192.0.2.1"} })
	if resp, _ := plainSend(t, "GET", ts.URL+"/api/health", "", hdr); resp.StatusCode != http.StatusForbidden {
		t.Errorf("untrusted proxy: %d", resp.StatusCode)
	}
}

func TestSessionCookieOverHTTPS(t *testing.T) {
	var srv *Server
	plain, _ := newTestServerWith(t, func(s *Server) { srv = s })
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = noRedirect.CheckRedirect
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(`{"username":"admin","password":"s3cret-pass"}`))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var c *http.Cookie
	for _, x := range resp.Cookies() {
		if x.Value != "" {
			c = x
		}
	}
	if c == nil || c.Name != "__Host-signalith_session" || !c.Secure || c.Path != "/" || c.Domain != "" || !c.HttpOnly {
		t.Fatalf("cookie over HTTPS: %+v", c)
	}
	me := func(url string, cl *http.Client, cookie *http.Cookie) int {
		req, _ := http.NewRequest("GET", url+"/api/me", nil)
		req.AddCookie(cookie)
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := me(ts.URL, client, c); code != 200 {
		t.Errorf("signed in with the __Host- cookie: %d", code)
	}
	// The same token under the plain name is not a session over HTTPS.
	if code := me(ts.URL, client, &http.Cookie{Name: sessionCookie, Value: c.Value}); code != http.StatusUnauthorized {
		t.Errorf("plain cookie name over HTTPS: %d", code)
	}
	// Over plain HTTP (HTTPS off, or a test): the plain name, not Secure.
	_, _, pc := login(t, plain, "admin", "s3cret-pass")
	if pc == nil || pc.Secure {
		t.Errorf("cookie over plain HTTP: %+v", pc)
	}
	// HTTPS off behind a trusted proxy that adds it: Secure.
	off, _ := newTestServerWith(t, func(s *Server) {
		s.Config.Server.TLS = &config.ServerTLS{Mode: "off"}
		s.Config.Server.PublicURL = "https://siem.example.com"
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
	})
	resp = send(t, "POST", off.URL+"/api/login", `{"username":"admin","password":"s3cret-pass"}`, map[string]string{"X-Forwarded-Proto": "https"})
	if cs := resp.Cookies(); len(cs) != 1 || cs[0].Name != "__Host-signalith_session" || !cs[0].Secure {
		t.Errorf("mode off, through a trusted proxy: %+v", cs)
	}
	// The same server reached over plain HTTP: an https:// public_url does
	// not make the cookie Secure, which the browser would never send back.
	resp = send(t, "POST", off.URL+"/api/login", `{"username":"admin","password":"s3cret-pass"}`, nil)
	if cs := resp.Cookies(); len(cs) != 1 || cs[0].Name != sessionCookie || cs[0].Secure {
		t.Errorf("mode off, https public_url, plain HTTP: %+v", cs)
	}
}

func newCertManager(t *testing.T) *tlsauto.Manager {
	t.Helper()
	m, err := tlsauto.New(tlsauto.Options{Dir: t.TempDir(), Names: []string{"siem.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCACertificateIsPublic(t *testing.T) {
	m := newCertManager(t)
	ts, _ := newTestServerWith(t, func(s *Server) { s.TLS = m })
	resp, err := http.Get(ts.URL + "/api/tls/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != string(m.CAPEM()) || resp.Header.Get("Content-Type") != "application/x-x509-ca-cert" ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "signalith-ca.crt") {
		t.Errorf("ca.pem: %d %s %v", resp.StatusCode, b, resp.Header)
	}
	// Without a certificate of its own, there is nothing to download.
	ts, _ = newTestServer(t)
	code, body := do(t, ts, "GET", "/api/tls/ca.pem", "", false)
	if code != http.StatusNotFound || !strings.Contains(body["error"].(string), "server.tls.mode is off") {
		t.Errorf("no certificate: %d %v", code, body)
	}
}

func TestAgentConfigTrustsTheCA(t *testing.T) {
	dir := t.TempDir()
	m, err := tlsauto.New(tlsauto.Options{Dir: dir, Names: []string{"siem.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) { s.TLS = m })
	// Building the setup, as the page does while an address is typed,
	// changes nothing; it says which name is still to be added.
	for _, typed := range []string{"https://192.168.1.7", "https://192.168.1.77:8080"} {
		q := url.Values{"os": {"linux"}, "server": {typed}}
		code, body := do(t, ts, "GET", "/api/agents/config?"+q.Encode(), "", true)
		cfg, _ := body["config"].(string)
		if code != 200 || !strings.Contains(cfg, "tls.ca_file          /etc/fluent-bit/signalith-ca.pem") || body["ca"] != string(m.CAPEM()) ||
			body["ca_fingerprint"] != m.Fingerprint() || body["ca_step"] != float64(2) || body["config_step"] != float64(3) ||
			body["add_name"] != strings.TrimPrefix(strings.Split(typed, ":8080")[0], "https://") {
			t.Fatalf("agent config: %d %v", code, body)
		}
	}
	if m.Covers("192.168.1.7") || m.Covers("192.168.1.77") {
		t.Error("building a setup changed the certificate")
	}
	if _, err := os.Stat(filepath.Join(dir, "names.txt")); err == nil {
		t.Error("building a setup saved a name")
	}
	// Once entered, the page adds it.
	code, body := do(t, ts, "POST", "/api/tls/names", `{"name":"192.168.1.77"}`, true)
	if code != 200 || !m.Covers("192.168.1.77") || m.Covers("192.168.1.7") {
		t.Errorf("add name: %d %v", code, body)
	}
	q := url.Values{"os": {"linux"}, "server": {"https://192.168.1.77:8080"}}
	if _, body := do(t, ts, "GET", "/api/agents/config?"+q.Encode(), "", true); body["add_name"] != nil {
		t.Errorf("covered name still to add: %v", body["add_name"])
	}
	// Another website's name is refused, saying why and what to use.
	q = url.Values{"os": {"linux"}, "server": {"https://www.bank.example"}}
	code, body = do(t, ts, "GET", "/api/agents/config?"+q.Encode(), "", true)
	if msg, _ := body["error"].(string); code != 400 || body["field"] != "server" || !strings.Contains(msg, "can't include www.bank.example") {
		t.Errorf("outside name: %d %v", code, body)
	}
	code, body = do(t, ts, "POST", "/api/tls/names", `{"name":"www.bank.example"}`, true)
	if code != 400 || body["field"] != "name" {
		t.Errorf("add outside name: %d %v", code, body)
	}
}

// Admins see how HTTPS is served, the names the certificate covers and
// the CA's fingerprint, which the Add data page's syslog setups use.
func TestHealthShowsTLS(t *testing.T) {
	m := newCertManager(t)
	ts, _ := newTestServerWith(t, func(s *Server) { s.TLS = m })
	_, body := do(t, ts, "GET", "/api/health", "", true)
	info, _ := body["tls"].(map[string]any)
	names, _ := info["names"].([]any)
	if info == nil || info["mode"] != config.TLSAuto || info["ca_sha256"] != m.Fingerprint() || info["own_ca"] != true ||
		len(names) == 0 || names[0] != "siem.example.com" {
		t.Errorf("tls = %v", body["tls"])
	}
	// Without a certificate there is no CA to give out.
	ts, _ = newTestServer(t)
	_, body = do(t, ts, "GET", "/api/health", "", true)
	if info, _ := body["tls"].(map[string]any); info == nil || info["ca_sha256"] != nil || info["names"] != nil {
		t.Errorf("no certificate: %v", body["tls"])
	}
}

func TestPlaintextWarning(t *testing.T) {
	one := plaintextWarning([]ingest.Sender{{Address: "192.0.2.4"}}, false, false)
	if !strings.HasPrefix(one, "An agent still sends") || !strings.Contains(one, ": 192.0.2.4.") || !strings.Contains(one, "plaintext_ingest: deny in signalith.yaml.") {
		t.Errorf("one: %s", one)
	}
	var many []ingest.Sender
	for _, a := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"} {
		many = append(many, ingest.Sender{Address: a})
	}
	if got := plaintextWarning(many, false, false); !strings.HasPrefix(got, "7 agents still send") ||
		!strings.Contains(got, "192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, 192.0.2.5 and 2 more.") || strings.Contains(got, "Docker") {
		t.Errorf("many: %s", got)
	}
	// Behind Docker Desktop every agent has the gateway's address: the
	// host names in their events count and name them.
	got := plaintextWarning([]ingest.Sender{{Address: "192.168.65.1", Hosts: []string{"WIN-01", "web-02", "web-03"}}}, true, false)
	if !strings.HasPrefix(got, "3 agents still send") || !strings.Contains(got, "192.168.65.1 (WIN-01, web-02, web-03)") ||
		!strings.Contains(got, "deploy/docker/signalith.yaml") || !strings.Contains(got, "names in brackets come from their events") ||
		strings.Contains(got, "change-this-ingest-token") {
		t.Errorf("docker: %s", got)
	}
	// On a quick start upgraded from one whose agents send the example
	// token, refusing them ends it.
	got = plaintextWarning([]ingest.Sender{{Address: "192.168.65.1", Hosts: []string{"WIN-01"}}}, true, true)
	if !strings.Contains(got, "That also ends for good the example token change-this-ingest-token") {
		t.Errorf("old token: %s", got)
	}
}
