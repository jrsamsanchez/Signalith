// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/security"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// newSecurityServer is a settings server with Signalith's own
// certificate and a fake OpenSearch, and its state folder in a temporary
// one.
func newSecurityServer(t *testing.T, change func(*Server)) (*httptest.Server, *Server, *logBuffer) {
	t.Helper()
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	fake := ostest.New(t)
	return newSettingsServer(t, "opensearch:\n  url: "+fake.URL+"\n", func(s *Server) {
		s.TLS = newCertManager(t)
		if change != nil {
			change(s)
		}
	})
}

// get fetches path as the admin and returns the response and its body.
func get(t *testing.T, ts *httptest.Server, path string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestSecurityRoutesAreAdminOnly(t *testing.T) {
	ts, _, _ := newSecurityServer(t, nil)
	for _, rt := range []struct{ method, path string }{{"GET", "/api/security"}, {"POST", "/api/security/ca"}} {
		if code, out := doAs(t, ts, "andy", "role-password", rt.method, rt.path, `{"action":"prepare"}`); code != 403 || out["code"] != "forbidden" {
			t.Errorf("analyst %s %s: %d %v", rt.method, rt.path, code, out)
		}
		if code, _ := do(t, ts, rt.method, rt.path, `{"action":"prepare"}`, false); code != 401 {
			t.Errorf("signed out %s %s: %d", rt.method, rt.path, code)
		}
	}
	// Non-admins learn nothing of it from api/health either.
	if _, out := doAs(t, ts, "andy", "role-password", "GET", "/api/health", ""); out["security"] != nil {
		t.Errorf("analyst health: %v", out["security"])
	}
}

func TestSecurityReport(t *testing.T) {
	ts, srv, logs := newSecurityServer(t, nil)
	resp, body := get(t, ts, "/api/security")
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, body)
	}
	var rep security.Report
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Checks) < 15 || rep.Server.Version != "test" || rep.CA == nil || rep.CA.Current == nil || rep.CA.ScopeSetting != "standard" {
		t.Errorf("report %+v", rep)
	}
	if rep.CA.SeenNames == nil || rep.CA.Refusals == nil {
		t.Error("the server's report leaves out what it saw")
	}
	// Never a secret: the ingest token, the admin's hash.
	for _, secret := range []string{"tok-0123456789abcdef", srv.conf().Auth.AdminPasswordHash} {
		if strings.Contains(body, secret) {
			t.Errorf("the report holds %q", secret)
		}
	}
	// One run, logged once.
	if n := strings.Count(logs.String(), `msg="security check:`); n != 1 {
		t.Errorf("%d log lines:\n%s", n, logs.String())
	}
	// The text, and as a file.
	resp, text := get(t, ts, "/api/security?format=text&download=1")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") ||
		!strings.HasPrefix(text, "Signalith security report for ") {
		t.Errorf("text: %d %v\n%s", resp.StatusCode, resp.Header, text)
	}
	want := `attachment; filename="signalith-security-`
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, want) || !strings.HasSuffix(cd, rep.CheckedAt.UTC().Format("2006-01-02")+`.txt"`) {
		t.Errorf("download: %q", cd)
	}
	// The menu's count, for admins.
	_, health := do(t, ts, "GET", "/api/health", "", true)
	sec, _ := health["security"].(map[string]any)
	if sec == nil || sec["risk"] != float64(rep.Summary.Risk) || sec["checked_at"] == nil {
		t.Errorf("health %v", health["security"])
	}
	if tlsInfo := health["tls"].(map[string]any); tlsInfo["ca_scope"] != "standard" || tlsInfo["next_ca_sha256"] != nil || tlsInfo["ca_made"] == nil {
		t.Errorf("tls %v", tlsInfo)
	}
}

func TestReportFileName(t *testing.T) {
	r := &security.Report{CheckedAt: time.Date(2026, 10, 13, 23, 0, 0, 0, time.UTC), Server: security.ServerInfo{Name: `siem 1/"x"`}}
	if got := reportFileName(r); got != "signalith-security-siem-1--x-2026-10-13.txt" {
		t.Error(got)
	}
	r.Server.Name = ""
	if got := reportFileName(r); got != "signalith-security-server-2026-10-13.txt" {
		t.Error(got)
	}
}

func TestSecurityChecksShareRuns(t *testing.T) {
	c := NewSecurityChecker(nil)
	var calls atomic.Int32
	release := make(chan struct{})
	gather := func(context.Context) *security.Report {
		calls.Add(1)
		<-release
		return &security.Report{CheckedAt: time.Now()}
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			if c.run(ctx, gather, false) == nil {
				t.Error("no report")
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("%d runs for callers at once", n)
	}
	// A recheck soon after is the same report.
	c.run(ctx, gather, false)
	if n := calls.Load(); n != 1 {
		t.Errorf("rechecked within %s: %d runs", recheckEvery, n)
	}
	// A fresh run always runs.
	c.run(ctx, gather, true)
	if n := calls.Load(); n != 2 {
		t.Errorf("fresh: %d runs", n)
	}
	// A recheck is allowed again once recheckEvery has passed.
	c.mu.Lock()
	c.lastRun = time.Now().Add(-recheckEvery)
	c.mu.Unlock()
	c.run(ctx, gather, false)
	if n := calls.Load(); n != 3 {
		t.Errorf("later recheck: %d runs", n)
	}
}

func TestSecurityCheckWaitsOnlySoLong(t *testing.T) {
	c := NewSecurityChecker(nil)
	stop := make(chan struct{})
	defer close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := c.run(ctx, func(context.Context) *security.Report { <-stop; return nil }, false)
	if r != nil || time.Since(start) > 2*time.Second {
		t.Errorf("%v after %v", r, time.Since(start))
	}
}

func TestSecurityCheckSurvivesAPanic(t *testing.T) {
	var buf logBuffer
	c := NewSecurityChecker(slog.New(slog.NewTextHandler(&buf, nil)))
	if r := c.run(context.Background(), func(context.Context) *security.Report { panic("boom") }, true); r != nil {
		t.Errorf("%v", r)
	}
	if !strings.Contains(buf.String(), "security check failed") {
		t.Error(buf.String())
	}
}

func TestSecurityLogsChanges(t *testing.T) {
	var buf logBuffer
	c := NewSecurityChecker(slog.New(slog.NewTextHandler(&buf, nil)))
	var next []security.Check
	gather := func(context.Context) *security.Report { return &security.Report{CheckedAt: time.Now(), Checks: next} }
	risk := func(ids ...string) []security.Check {
		var out []security.Check
		for _, id := range ids {
			out = append(out, security.Check{ID: id, State: security.Risk})
		}
		return out
	}
	for _, step := range []struct {
		checks []security.Check
		want   string
	}{
		{risk("transit.https"), `level=WARN msg="security check: at risk" checks=transit.https`},
		{risk("transit.https"), ""},
		{risk("transit.https", "rest.master_key"), `checks=transit.https,rest.master_key`},
		{nil, `level=INFO msg="security check: nothing at risk"`},
		{nil, ""},
	} {
		buf.mu.Lock()
		buf.buf.Reset()
		buf.mu.Unlock()
		next = step.checks
		c.run(context.Background(), gather, true)
		got := buf.String()
		if step.want == "" && got != "" || step.want != "" && !strings.Contains(got, step.want) {
			t.Errorf("logged %q, want %q", got, step.want)
		}
	}
}

func TestSecurityCA(t *testing.T) {
	var reports atomic.Int32
	ts, srv, logs := newSecurityServer(t, func(s *Server) {
		s.Security = NewSecurityChecker(s.Log)
		s.Security.OnReport = func(*security.Report) { reports.Add(1) }
	})
	ca := func(body string) (int, map[string]any) { return do(t, ts, "POST", "/api/security/ca", body, true) }
	if code, out := ca(`{"action":"switch"}`); code != 409 || out["error"] != "There's no new certificate authority to switch to." {
		t.Errorf("switch first: %d %v", code, out)
	}
	if code, _ := ca(`{"action":"explode"}`); code != 400 {
		t.Errorf("unknown action: %d", code)
	}
	if code, _ := ca(`{"action":"prepare","scope":"loose"}`); code != 400 {
		t.Errorf("unknown scope: %d", code)
	}
	before := srv.TLS.CAInfo().Fingerprint
	code, out := ca(`{"action":"prepare","scope":"strict"}`)
	next := out["ca"].(map[string]any)["next"].(map[string]any)
	if code != 200 || next["scope"] != "strict" || out["ca"].(map[string]any)["scope_setting"] != "strict" {
		t.Fatalf("prepare: %d %v", code, out["ca"])
	}
	// The setting was saved the way the Settings page saves, and both
	// steps are in the audit log.
	if srv.conf().Server.CAScope() != "strict" || !strings.Contains(logs.String(), "settings saved") ||
		!strings.Contains(logs.String(), `msg="certificate authority prepared"`) || !strings.Contains(logs.String(), "scope=strict") {
		t.Errorf("scope %s\n%s", srv.conf().Server.CAScope(), logs.String())
	}
	if code, out := ca(`{"action":"prepare"}`); code != 409 || !strings.Contains(out["error"].(string), "already made") {
		t.Errorf("prepare twice: %d %v", code, out)
	}
	// Both CAs for agents, and the new one alone for browsers.
	resp, both := get(t, ts, "/api/tls/ca.pem?which=both")
	if resp.StatusCode != 200 || strings.Count(both, "BEGIN CERTIFICATE") != 2 || !strings.Contains(resp.Header.Get("Content-Disposition"), "signalith-ca.pem") {
		t.Errorf("both: %d %v", resp.StatusCode, resp.Header)
	}
	resp, nextPEM := get(t, ts, "/api/tls/ca.pem?which=next")
	if resp.StatusCode != 200 || nextPEM != string(srv.TLS.NextPEM()) || !strings.Contains(resp.Header.Get("Content-Disposition"), "signalith-ca-new.crt") {
		t.Errorf("next: %d %v", resp.StatusCode, resp.Header)
	}
	_, health := do(t, ts, "GET", "/api/health", "", true)
	if health["tls"].(map[string]any)["next_ca_sha256"] != next["fingerprint"] {
		t.Errorf("health tls %v", health["tls"])
	}
	if code, out := ca(`{"action":"switch"}`); code != 200 || out["ca"].(map[string]any)["previous"] == nil {
		t.Fatalf("switch: %d %v", code, out["ca"])
	}
	if after := srv.TLS.CAInfo(); after.Fingerprint == before || after.Scope != "strict" {
		t.Errorf("in use after the switch: %+v", after)
	}
	if !strings.Contains(logs.String(), `msg="certificate authority switched" audit=true`) {
		t.Error(logs.String())
	}
	if code, out := ca(`{"action":"prepare"}`); code != 409 || out["error"] != tlsauto.ErrPreviousKept.Error() {
		t.Errorf("prepare with the previous kept: %d %v", code, out)
	}
	if code, _ := ca(`{"action":"rollback"}`); code != 200 || srv.TLS.CAInfo().Fingerprint != before {
		t.Errorf("rollback: %d", code)
	}
	if code, _ := ca(`{"action":"discard"}`); code != 200 || srv.TLS.Next() != nil {
		t.Errorf("discard: %d", code)
	}
	if resp, _ := get(t, ts, "/api/tls/ca.pem?which=next"); resp.StatusCode != 404 {
		t.Errorf("next with none: %d", resp.StatusCode)
	}
	for _, msg := range []string{"certificate authority switched back", "new certificate authority discarded"} {
		if !strings.Contains(logs.String(), msg) {
			t.Errorf("no %q in the log", msg)
		}
	}
	// Each action checks again, and the heartbeat hears of it.
	if n := reports.Load(); n != 4 {
		t.Errorf("%d reports", n)
	}
}

func TestSecurityCAWithOwnFiles(t *testing.T) {
	ts, _, _ := newSecurityServer(t, func(s *Server) { s.TLS = nil })
	if code, out := do(t, ts, "POST", "/api/security/ca", `{"action":"prepare"}`, true); code != 404 || !strings.Contains(out["error"].(string), "no certificate authority of its own") {
		t.Errorf("%d %v", code, out)
	}
}

func TestPlainSignInsAreNoted(t *testing.T) {
	_, srv, _ := newSecurityServer(t, nil)
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "10.0.0.7:5555"
	srv.notePlainSignIn(r)
	r.RemoteAddr = "127.0.0.1:5555"
	srv.notePlainSignIn(r)
	r = httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr, r.TLS = "10.0.0.8:5555", &tls.ConnectionState{}
	srv.notePlainSignIn(r)
	if got := srv.security().plain.since(time.Now().Add(-time.Hour)); len(got) != 1 || got[0] != "10.0.0.7" {
		t.Errorf("%v", got)
	}

	// A reverse proxy on this computer that says the browser used plain
	// HTTP: noted under the client it names, or itself when it names
	// none. One that says HTTPS, or says nothing, is not noted.
	_, srv, _ = newSecurityServer(t, func(s *Server) {
		s.Config.Server.TrustedProxies = []string{"127.0.0.1", "::1"}
		s.Config.Server.ClientHeader = config.ClientHeaderXFF
	})
	proxied := func(proto, xff string, agent bool) {
		r := httptest.NewRequest("POST", "/api/login", nil)
		r.RemoteAddr = "127.0.0.1:5555"
		if proto != "" {
			r.Header.Set("X-Forwarded-Proto", proto)
		}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if agent {
			srv.notePlainAgent(r)
		} else {
			srv.notePlainSignIn(r)
		}
	}
	proxied("http", "10.0.0.77", false)
	proxied("http", "", false)
	proxied("https", "10.0.0.78", false)
	proxied("", "10.0.0.79", false)
	proxied("http", "10.0.0.80", true)
	since := time.Now().Add(-time.Hour)
	if got := srv.security().proxiedPlain.since(since); len(got) != 2 || !slices.Contains(got, "10.0.0.77") || !slices.Contains(got, "127.0.0.1") {
		t.Errorf("proxied sign-ins %v", got)
	}
	if got := srv.security().proxiedPlainAgents.since(since); len(got) != 1 || got[0] != "10.0.0.80" {
		t.Errorf("proxied agents %v", got)
	}
	if got := srv.security().plain.since(since); len(got) != 0 {
		t.Errorf("direct sign-ins %v", got)
	}
	rt := srv.runtimeFacts(time.Now(), false)
	if len(rt.ProxiedPlain) != 2 || len(rt.ProxiedPlainAgents) != 1 {
		t.Errorf("runtime facts %+v", rt)
	}
	// It remembers the latest few.
	c := NewSecurityChecker(nil)
	for i := range maxPlainSignIns + 10 {
		c.notePlain(netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}))
	}
	if n := len(c.plain.since(time.Time{})); n != maxPlainSignIns {
		t.Errorf("%d remembered", n)
	}
}

// Names are noted only from people signed in and agents with a token:
// anyone who can reach the port could send any name.
func TestHTTPSNamesAreNoted(t *testing.T) {
	_, srv, _ := newSecurityServer(t, nil)
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = &tls.Config{GetCertificate: srv.TLS.GetCertificate}
	ts.StartTLS()
	defer ts.Close()
	send := func(method, path, host string, auth func(*http.Request)) {
		t.Helper()
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader("[]"))
		req.Host = host
		if auth != nil {
			auth(req)
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	admin := func(r *http.Request) { r.SetBasicAuth("admin", "s3cret-pass") }
	wrongPassword := func(r *http.Request) { r.SetBasicAuth("admin", "wrong") }
	token := func(tok string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
	}
	send("GET", "/api/health", "stranger-1.example.com", nil)
	send("GET", "/", "stranger-2.example.com", nil)
	send("GET", "/api/health", "stranger-3.example.com", wrongPassword)
	send("POST", "/api/ingest", "stranger-4.example.com", token("not-the-token"))
	// A bare handshake asking for any name.
	conn, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "stranger-5.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if seen := srv.TLS.SeenNames(); len(seen) != 0 {
		t.Fatalf("names from strangers: %+v", seen)
	}
	send("GET", "/api/health", "192.168.1.20:8080", admin)
	send("POST", "/api/ingest", "siem.corp.local", token("tok-0123456789abcdef"))
	var names []string
	for _, n := range srv.TLS.SeenNames() {
		names = append(names, n.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"192.168.1.20", "siem.corp.local"}) {
		t.Errorf("%v", names)
	}
}

// Agents that reach a server without HTTPS directly, not through its
// reverse proxy, are noted; those on this computer, through the proxy or
// over HTTPS are not.
func TestPlainAgentsAreNoted(t *testing.T) {
	_, srv, _ := newSecurityServer(t, nil)
	srv.Config.Server.TrustedProxies = []string{"10.0.0.5"}
	for _, tc := range []struct {
		from  string
		proto string
		tls   bool
	}{
		{from: "10.0.0.4:5555"},
		{from: "127.0.0.1:5555"},
		{from: "10.0.0.5:5555", proto: "https"},
		{from: "10.0.0.6:5555", tls: true},
	} {
		r := httptest.NewRequest("POST", "/api/ingest", nil)
		r.RemoteAddr = tc.from
		if tc.proto != "" {
			r.Header.Set("X-Forwarded-Proto", tc.proto)
		}
		if tc.tls {
			r.TLS = &tls.ConnectionState{}
		}
		srv.notePlainAgent(r)
	}
	if got := srv.security().plainAgents.since(time.Now().Add(-time.Hour)); !slices.Equal(got, []string{"10.0.0.4"}) {
		t.Errorf("%v", got)
	}
	if rt := srv.runtimeFacts(time.Now(), false); !slices.Equal(rt.DirectPlainAgents, []string{"10.0.0.4"}) {
		t.Errorf("%+v", rt)
	}
}

// Agents on this computer that send over plain HTTP are counted apart:
// their events don't cross the network.
func TestLocalPlainSenders(t *testing.T) {
	_, srv, _ := newSecurityServer(t, nil)
	srv.Pipeline.NotePlaintext(netip.MustParseAddr("127.0.0.1"), []string{"siem-1"})
	srv.Pipeline.NotePlaintext(netip.MustParseAddr("::1"), nil)
	srv.Pipeline.NotePlaintext(netip.MustParseAddr("10.0.0.4"), []string{"web-1"})
	rt := srv.runtimeFacts(time.Now(), false)
	if rt.LocalPlainSenders != 2 || rt.PlainSenderCount != 1 || !slices.Equal(rt.PlainSenders, []string{"web-1 (10.0.0.4)"}) {
		t.Errorf("%+v", rt)
	}
}

func TestSecurityDelay(t *testing.T) {
	if d := SecurityDelay(time.Now()); d < 29*time.Second || d > securityFirstRun {
		t.Errorf("at start: %v", d)
	}
	if d := SecurityDelay(time.Now().Add(-time.Hour)); d != securityAfterReload {
		t.Errorf("after a restart in place: %v", d)
	}
}

// Each step has words for a message that it failed.
func TestCADoingCoversActions(t *testing.T) {
	for action := range caActions {
		if caDoing[action] == "" {
			t.Errorf("no words for %s", action)
		}
	}
}
