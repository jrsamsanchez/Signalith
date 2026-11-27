// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	// Progress lines come from several goroutines at once (faults and
	// phases), as they do to os.Stderr.
	var out, errOut lockedBuilder
	code := run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// lockedBuilder is a strings.Builder safe for writes from several
// goroutines.
type lockedBuilder struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuilder) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuilder) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func readJSONReport(t *testing.T, path string) *Report {
	t.Helper()
	rep, err := readReport(path)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestHelpCommand(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		code, out, _ := runCmd(t, arg)
		if code != exitPass || !strings.Contains(out, "Usage: signalith-loadgen") {
			t.Errorf("%s: exit %d, %q", arg, code, out)
		}
	}
}

func TestCheckCommand(t *testing.T) {
	dir := files(t, map[string]string{
		"good.yaml": "name: g\nphases:\n  - {name: p, for: 1s}\n",
		"bad.yaml":  "name: b\nphases: []\n",
	})
	if code, _, errOut := runCmd(t, "check"); code != exitError || !strings.Contains(errOut, "needs scenario files") {
		t.Errorf("check without files: %d %q", code, errOut)
	}
	code, out, errOut := runCmd(t, "check", filepath.Join(dir, "good.yaml"), filepath.Join(dir, "bad.yaml"), filepath.Join(dir, "missing.yaml"))
	if code != exitError || !strings.Contains(out, "good.yaml: ok") || !strings.Contains(errOut, "at least one phase") || !strings.Contains(errOut, "missing.yaml") {
		t.Errorf("check: %d\n%s\n%s", code, out, errOut)
	}
}

func TestRunCommandErrors(t *testing.T) {
	dir := files(t, map[string]string{
		"bad.yaml":    "name: b\nphases: []\n",
		"admin.txt":   "admin:pw\n",
		"report.json": "{not json",
	})
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"bad flag", []string{"agents", "-nope"}, "flag provided but not defined"},
		{"bad scenario", []string{"run", "-f", filepath.Join(dir, "bad.yaml")}, "at least one phase"},
		{"invalid load", []string{"users", "-n", "0"}, "users: n is required"},
		{"bad baseline", []string{"agents", "-baseline", filepath.Join(dir, "report.json")}, "baseline:"},
		{"missing baseline", []string{"agents", "-baseline", filepath.Join(dir, "none.json")}, "baseline:"},
		{"bad pids", []string{"agents", "-pids", "x"}, "-pids:"},
		{"no targets", []string{"agents", "-q"}, "no targets"},
		{"bad target", []string{"agents", "-target", "ftp://x"}, "is not an http(s) address"},
		{"bad ca", []string{"agents", "-target", "http://127.0.0.1:1", "-ca", filepath.Join(dir, "admin.txt")}, "holds no certificate"},
		{"missing ca", []string{"agents", "-target", "http://127.0.0.1:1", "-ca", filepath.Join(dir, "none.pem")}, "CA file"},
		{"missing admin", []string{"agents", "-target", "http://127.0.0.1:1", "-admin-file", filepath.Join(dir, "none.txt")}, "admin file"},
		{"unreachable", []string{"agents", "-target", "http://127.0.0.1:1", "-admin-file", filepath.Join(dir, "admin.txt")}, "signing in as admin"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := runCmd(t, tc.args...)
			if code != exitError || !strings.Contains(errOut, tc.want) {
				t.Errorf("exit %d, stderr %q, want %q", code, errOut, tc.want)
			}
		})
	}
}

func TestPrepareErrors(t *testing.T) {
	f := newFakeSignalith(t, "one")
	dir := files(t, map[string]string{"admin.txt": "admin:pw\n", "users.csv": "username,password\nbad line\n"})
	admin := filepath.Join(dir, "admin.txt")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"churn without admin", []string{"churn", "-target", f.urls()[0]}, "churn needs credentials.admin_file"},
		{"create without admin", []string{"users", "-create", "-target", f.urls()[0]}, "needs credentials.admin_file"},
		{"users without file", []string{"users", "-target", f.urls()[0]}, "users need credentials.users_file"},
		{"bad users file", []string{"users", "-target", f.urls()[0], "-users-file", filepath.Join(dir, "users.csv")}, "users file"},
		{"agents without token", []string{"agents", "-target", f.urls()[0], "-admin-file", admin, "-token-file", filepath.Join(dir, "none.txt")}, "agent token"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := runCmd(t, append(tc.args, "-q", "-for", "50ms")...)
			if code != exitError || !strings.Contains(errOut, tc.want) {
				t.Errorf("exit %d, stderr %q, want %q", code, errOut, tc.want)
			}
		})
	}
	// Accounts that cannot be made end the run before it starts.
	f.failUsers = true
	code, _, errOut := runCmd(t, "brute", "-q", "-for", "50ms", "-target", f.urls()[0], "-admin-file", admin)
	if code != exitError || !strings.Contains(errOut, "making account lg-") {
		t.Errorf("brute with accounts refused: %d %q", code, errOut)
	}
}

func TestUsersCommand(t *testing.T) {
	f := newFakeSignalith(t, "one", "two")
	dir := files(t, map[string]string{"admin.txt": "admin:pw\n"})
	report := filepath.Join(dir, "r.json")
	code, out, errOut := runCmd(t, "users", "-target", strings.Join(f.urls(), ","), "-admin-file", filepath.Join(dir, "admin.txt"),
		"-n", "3", "-think", "40ms", "-triage", "-create", "-search", "* | head 1", "-for", "400ms", "-run", "u1", "-json", report)
	if code != exitPass {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(errOut, "phase users for 400ms") || !strings.Contains(errOut, "2 server(s) ready") {
		t.Errorf("progress lines: %s", errOut)
	}
	rep := readJSONReport(t, report)
	if !rep.Cluster || len(rep.Servers) != 2 {
		t.Errorf("cluster not seen: %+v", rep)
	}
	var p *PhaseReport
	for i := range rep.Phases {
		if rep.Phases[i].Name == "users" {
			p = &rep.Phases[i]
		}
	}
	if p == nil {
		t.Fatalf("no users phase: %+v", rep.Phases)
	}
	if p.Counts["user_requests"] == 0 || p.Counts["write_conflicts"] == 0 || p.Latencies["signin"].Count == 0 {
		t.Errorf("users phase %+v", p)
	}
	if p.Counts["page_reloads"] == 0 {
		t.Errorf("no page reloads although the second server answers as two versions: %+v", p.Counts)
	}
	// The accounts and the case made for the run are gone.
	f.mu.Lock()
	for u := range f.passwords {
		if strings.HasPrefix(u, "lg-u1-") {
			t.Errorf("account %s left", u)
		}
	}
	if len(f.cases) != 0 {
		t.Errorf("cases left open: %v", f.cases)
	}
	f.mu.Unlock()
	if f.count("POST /api/cases/{id}/entries") == 0 || f.count("POST /api/logout") == 0 {
		t.Errorf("no case notes or sign-outs: %v", f.requests)
	}
}

func TestUsersFromFile(t *testing.T) {
	f := newFakeSignalith(t, "one")
	dir := files(t, map[string]string{"users.csv": "# people\nusername,password\nana,apw\n\nnobody,x\n"})
	code, out, errOut := runCmd(t, "users", "-q", "-target", f.urls()[0], "-users-file", filepath.Join(dir, "users.csv"),
		"-n", "2", "-think", "30ms", "-for", "200ms")
	if code != exitPass {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "signin_errors") && !strings.Contains(out, "signin_status_401") {
		t.Errorf("a user with a wrong password not counted:\n%s", out)
	}
	if !strings.Contains(out, "no admin credentials") {
		t.Errorf("no note on the missing admin credentials:\n%s", out)
	}
}

func TestBruteCommand(t *testing.T) {
	f := newFakeSignalith(t, "one")
	dir := files(t, map[string]string{"admin.txt": "admin:pw\n"})
	report := filepath.Join(dir, "r.json")
	code, out, errOut := runCmd(t, "brute", "-q", "-target", f.urls()[0], "-admin-file", filepath.Join(dir, "admin.txt"),
		"-accounts", "2", "-sources", "1", "-rate", "60", "-for", "300ms", "-keep", "-run", "b1", "-json", report)
	if code != exitPass {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	rep := readJSONReport(t, report)
	c := rep.Phases[len(rep.Phases)-1].Counts
	if c["brute_attempts"] == 0 || c["brute_wrong_password"] == 0 || c["brute_lockouts"] == 0 {
		t.Errorf("brute counts %v", c)
	}
	// Each account had two passwords checked before the limit.
	if v := rep.Phases[len(rep.Phases)-1].Values["brute_checked_per_account"]; v != 2 {
		t.Errorf("brute_checked_per_account %v, want 2", v)
	}
	// -keep leaves the accounts.
	f.mu.Lock()
	_, kept := f.passwords["lg-b1-b01"]
	f.mu.Unlock()
	if !kept {
		t.Error("-keep removed the accounts")
	}
}

func TestChurnCommand(t *testing.T) {
	f := newFakeSignalith(t, "one", "two")
	dir := files(t, map[string]string{"admin.txt": "pw\n"})
	// A password alone is signalithadmin's.
	f.passwords["signalithadmin"] = "pw"
	report := filepath.Join(dir, "r.json")
	code, out, errOut := runCmd(t, "churn", "-q", "-target", strings.Join(f.urls(), ","), "-admin-file", filepath.Join(dir, "admin.txt"),
		"-every", "40ms", "-key", "search.max_events", "-values", "6000,6001,text", "-for", "300ms", "-json", report)
	if code != exitPass {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	rep := readJSONReport(t, report)
	var saved int64
	var converge float64
	for _, p := range rep.Phases {
		saved += p.Counts["churn_saved"]
		converge = max(converge, p.Values["settings_converge_seconds"])
	}
	if saved == 0 {
		t.Errorf("no setting saved: %+v", rep.Phases)
	}
	if converge <= 0 {
		t.Errorf("no convergence time: %+v", rep.Phases)
	}

	// A key the servers do not have is counted, not changed.
	code, out, errOut = runCmd(t, "churn", "-q", "-target", f.urls()[0], "-admin-file", filepath.Join(dir, "admin.txt"),
		"-every", "40ms", "-key", "no.such.key", "-for", "100ms", "-json", report)
	if code != exitPass {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	rep = readJSONReport(t, report)
	if n := rep.Phases[len(rep.Phases)-1].Counts["churn_unknown_key"]; n == 0 {
		t.Errorf("unknown key not counted: %+v", rep.Phases)
	}
}

func TestChurnConflictsAndErrors(t *testing.T) {
	m := newMetrics()
	m.SetPhase("p")
	var puts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/login":
			w.Write([]byte(`{}`))
		case r.Method == http.MethodGet:
			w.Write([]byte(`{"sections":[{"fields":[{"key":"k","value":1}]}]}`))
		case puts.Add(1) == 1:
			http.Error(w, "changed", http.StatusConflict)
		default:
			http.Error(w, "broken", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	s := newSession(srv.URL, http.DefaultTransport, "a", "b")
	c := &Churn{load: ChurnLoad{Key: "k"}, sessions: []*Session{s}, m: m}
	c.change(context.Background(), s, 2)
	c.change(context.Background(), s, 3)
	if m.Count("p", "churn_conflicts") != 1 || m.Count("p", "churn_errors") != 1 || m.Count("p", "churn_status_500") != 1 {
		t.Errorf("counts conflicts %d errors %d", m.Count("p", "churn_conflicts"), m.Count("p", "churn_errors"))
	}
	// A server that does not answer the read.
	srv.Close()
	c.change(context.Background(), s, 4)
	if m.Count("p", "churn_errors") != 2 {
		t.Errorf("unreachable server not counted: %d", m.Count("p", "churn_errors"))
	}
	// No admin session: counted, and nothing runs.
	(&Churn{m: m}).Run(context.Background())
	if m.Count("p", "churn_without_admin") != 1 {
		t.Error("churn without admin not counted")
	}
}

func TestJSONValue(t *testing.T) {
	if v := jsonValue(5000.0); v != int64(5000) {
		t.Errorf("jsonValue(5000.0) = %#v", v)
	}
	if v := jsonValue(1.5); v != 1.5 {
		t.Errorf("jsonValue(1.5) = %#v", v)
	}
	if v := jsonValue(json.Number("12")); v != "12" {
		t.Errorf("jsonValue(Number) = %#v", v)
	}
	if v := jsonValue("x"); v != "x" {
		t.Errorf("jsonValue(x) = %#v", v)
	}
}

func TestCleanupCommand(t *testing.T) {
	f := newFakeSignalith(t, "one")
	dir := files(t, map[string]string{"admin.txt": "admin:pw\n", "bad.yaml": "name: x\n"})
	admin := filepath.Join(dir, "admin.txt")
	f.passwords["lg-c1-u01"] = "x"
	f.passwords["lg-c1-b01-stuck"] = "x"
	f.passwords["lg-other-u01"] = "x"
	f.cases["case-a"] = caseTitle("c1")
	f.cases["case-b"] = "something else"

	if code, _, errOut := runCmd(t, "cleanup", "-run", "c1"); code != exitError || !strings.Contains(errOut, "cleanup needs") {
		t.Errorf("cleanup without target: %d %q", code, errOut)
	}
	if code, _, _ := runCmd(t, "cleanup", "-nope"); code != exitError {
		t.Errorf("bad flag: %d", code)
	}
	if code, _, errOut := runCmd(t, "cleanup", "-f", filepath.Join(dir, "bad.yaml")); code != exitError || !strings.Contains(errOut, "bad.yaml") {
		t.Errorf("bad scenario: %d %q", code, errOut)
	}
	if code, _, errOut := runCmd(t, "cleanup", "-run", "c1", "-target", f.urls()[0], "-admin-file", admin, "-ca", admin); code != exitError || !strings.Contains(errOut, "no certificate") {
		t.Errorf("bad CA: %d %q", code, errOut)
	}
	if code, _, errOut := runCmd(t, "cleanup", "-run", "c1", "-target", f.urls()[0], "-admin-file", filepath.Join(dir, "none")); code != exitError || errOut == "" {
		t.Errorf("missing admin file: %d %q", code, errOut)
	}
	if code, _, errOut := runCmd(t, "cleanup", "-run", "c1", "-target", "http://127.0.0.1:1", "-admin-file", admin); code != exitError || errOut == "" {
		t.Errorf("unreachable server: %d %q", code, errOut)
	}

	code, out, errOut := runCmd(t, "cleanup", "-run", "c1", "-target", f.urls()[0], "-admin-file", admin)
	// The stuck account could not be removed: an error, after the rest.
	if code != exitError || !strings.Contains(errOut, "lg-c1-b01-stuck") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "removed account lg-c1-u01") || !strings.Contains(out, "closed case case-a") || !strings.Contains(out, "retention policy") {
		t.Errorf("output:\n%s", out)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.passwords["lg-other-u01"]; !ok {
		t.Error("another run's account removed")
	}
	if _, ok := f.cases["case-b"]; !ok {
		t.Error("another case closed")
	}
	if _, ok := f.cases["case-a"]; ok {
		t.Error("the run's case left open")
	}
}

func TestVerifyCommand(t *testing.T) {
	osrv := fakeOpenSearch(t, "green")
	dir := files(t, map[string]string{"bad.yaml": "name: x\n", "s.yaml": "name: s\nopensearch: {url: " + osrv.URL + "}\nphases:\n  - {name: p, for: 1s}\n"})
	if code, _, errOut := runCmd(t, "verify", "-opensearch", osrv.URL); code != exitError || !strings.Contains(errOut, "needs -run") {
		t.Errorf("without -run: %d %q", code, errOut)
	}
	if code, _, _ := runCmd(t, "verify", "-nope"); code != exitError {
		t.Errorf("bad flag: %d", code)
	}
	if code, _, errOut := runCmd(t, "verify", "-run", "r", "-f", filepath.Join(dir, "bad.yaml")); code != exitError || !strings.Contains(errOut, "bad.yaml") {
		t.Errorf("bad scenario: %d %q", code, errOut)
	}
	if code, _, errOut := runCmd(t, "verify", "-run", "r"); code != exitError || !strings.Contains(errOut, "no OpenSearch address") {
		t.Errorf("no OpenSearch: %d %q", code, errOut)
	}
	if code, _, errOut := runCmd(t, "verify", "-run", "r", "-opensearch", "http://127.0.0.1:1"); code != exitError || errOut == "" {
		t.Errorf("unreachable OpenSearch: %d %q", code, errOut)
	}
	code, out, errOut := runCmd(t, "verify", "-run", "r", "-f", filepath.Join(dir, "s.yaml"))
	if code != exitFail {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{"Run r: 2 agents, 5 events stored, 1 missing", "1 duplicated", "agent 0 event 3 lost", "agent 0 event 2 stored 2 times"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestOSReaderClientFiles(t *testing.T) {
	dir := files(t, map[string]string{"user.txt": "osuser:ospw\n", "empty.txt": "\n"})
	r, err := newOSReader(OpenSearch{URL: "http://a/", URLs: []string{"http://a", "http://b/", ""}, UserFile: filepath.Join(dir, "user.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.urls, ",") != "http://a,http://b" || r.user != "osuser" || r.pass != "ospw" || r.prefix != "signalith" {
		t.Errorf("reader %+v", r)
	}
	for name, o := range map[string]OpenSearch{
		"empty user file": {URL: "http://a", UserFile: filepath.Join(dir, "empty.txt")},
		"missing CA":      {URL: "http://a", CA: filepath.Join(dir, "none.pem")},
		"bad client cert": {URL: "http://a", Cert: filepath.Join(dir, "user.txt"), Key: filepath.Join(dir, "user.txt")},
	} {
		if _, err := newOSReader(o); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// Basic authentication is sent.
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		got.Store(u + ":" + p)
		w.Write([]byte(`{"status":"green"}`))
	}))
	defer srv.Close()
	r.urls = []string{srv.URL}
	if st, err := r.indexHealth(context.Background()); err != nil || st != "green" {
		t.Errorf("indexHealth %q %v", st, err)
	}
	if got.Load() != "osuser:ospw" {
		t.Errorf("basic auth %v", got.Load())
	}
}

func TestOSReaderOps(t *testing.T) {
	osrv := fakeOpenSearch(t, "green")
	r, err := newOSReader(OpenSearch{URL: osrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a, err := r.opsTotal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := r.opsTotal(ctx)
	if b-a != 100 {
		t.Errorf("opsTotal grew by %d, want 100", b-a)
	}
	ix, err := r.opsByIndex(ctx)
	if err != nil || ix["signalith_settings"] != 5 || ix["signalith-events-1"] == 0 {
		t.Errorf("opsByIndex %v %v", ix, err)
	}
	// No node statistics is an error.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"nodes":{}}`)) }))
	defer empty.Close()
	r.urls = []string{empty.URL}
	if _, err := r.opsTotal(ctx); err == nil {
		t.Error("no nodes gives no error")
	}
	r.urls = []string{"http://127.0.0.1:1"}
	if _, err := r.opsByIndex(ctx); err == nil {
		t.Error("unreachable OpenSearch gives no error")
	}
}

func TestNumberKinds(t *testing.T) {
	tests := []struct {
		in   any
		want int64
		ok   bool
	}{
		{json.Number("7"), 7, true},
		{json.Number("x"), 0, false},
		{3.0, 3, true},
		{"12", 12, true},
		{"x", 0, false},
		{true, 0, false},
	}
	for _, tc := range tests {
		if n, ok := number(tc.in); n != tc.want || ok != tc.ok {
			t.Errorf("number(%#v) = %d, %v", tc.in, n, ok)
		}
	}
}

// TestRunScenarioCluster runs a scenario with every kind of load but
// agents and syslog against a two-server stand-in cluster, with faults,
// checks, seed data, OpenSearch's counters and many criteria.
func TestRunScenarioCluster(t *testing.T) {
	f := newFakeSignalith(t, "one", "two")
	osrv := fakeOpenSearch(t, "red")
	var toxic atomic.Int64
	tp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Enabled bool }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if r.URL.Path != "/proxies/os" {
			http.NotFound(w, r)
			return
		}
		toxic.Add(1)
		if !in.Enabled {
			f.takeOver()
		}
		w.Write([]byte(`{}`))
	}))
	defer tp.Close()
	dir := files(t, map[string]string{"admin.txt": "admin:pw\n"})
	scenario := filepath.Join(dir, "s.yaml")
	if err := os.WriteFile(scenario, []byte(`name: fake-cluster
needs: [cluster, windows_server, proxy_protocol]
targets: [`+strings.Join(f.urls(), ", ")+`]
credentials: {admin_file: `+filepath.Join(dir, "admin.txt")+`}
opensearch: {url: `+osrv.URL+`}
toxiproxy: {url: `+tp.URL+`, proxy: os}
seed:
  - {name: rules, method: POST, path: "/api/seed/{i}", body: '{"n": {i}, "run": "{run}"}', count: 1}
  - {name: flaky, method: POST, path: "/api/seed/{i}", count: 2}
phases:
  - {name: quiet, for: 400ms}
  - name: busy
    for: 500ms
    users: {n: 2, think: 50ms, triage: true, create: true}
    brute: {accounts: 1, sources: 1, rate: 30}
    churn: {every: 60ms, key: search.max_events, values: [5000, 5001]}
    cookie_flood: {rate: 30}
faults:
  - {at: 50ms, kind: cut_opensearch, target: leader, for: 100ms}
  - {at: 0s, kind: cmd, target: windows, cmd: "echo linux {server}", windows_cmd: "echo windows {server}", for: 50ms, undo: "echo undo", windows_undo: "echo winundo"}
  - {at: 0s, kind: cmd, target: standby, cmd: "exit 3"}
  - {at: 0s, kind: cmd, target: nowhere, cmd: "echo named"}
checks:
  - {name: fine, cmd: "echo fine"}
  - {name: broken, cmd: "exit 4"}
criteria:
  - {name: page_p95_ms, max: 60000}
  - {name: search_p95_ms, max: 60000}
  - {name: write_p95_ms, max: 60000}
  - {name: unexpected_signouts, max: 1000}
  - {name: write_conflicts}
  - {name: brute_lockouts}
  - {name: brute_checked_per_account, max: 5}
  - {name: settings_converge_seconds, max: 60}
  - {name: leaders_at_once, max: 1}
  - {name: jobs_moves}
  - {name: windows_led_seconds}
  - {name: takeover_seconds, max: 60}
  - {name: os_ops_per_server_per_second, max: 1000000000}
  - {name: os_ops_per_random_cookie, phase: busy, baseline: quiet}
  - {name: opensearch_red_samples, max: 0}
  - {name: opensearch_unreachable_samples, max: 0}
  - {name: servers_ready, min: 2}
  - {name: windows_servers_ready, min: 1}
  - {name: check_failures, max: 0}
  - {name: generator_lag_ms}
  - {name: page_reloads_per_user}
  - {name: events_lost, max: 0}
  - {name: ingest_p99_ms, max: 1000}
  - {name: server_cpu_cores}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(dir, "r.json")
	args := []string{"run", "-f", scenario, "-run", "c1", "-json", report}
	if runtime.GOOS == "linux" {
		args = append(args, "-pids", "self="+strconv.Itoa(os.Getpid()))
	}
	code, out, errOut := runCmd(t, args...)
	// The red samples and the broken check fail the run.
	if code != exitFail {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	rep := readJSONReport(t, report)
	byName := map[string]CriterionResult{}
	for _, c := range rep.Criteria {
		byName[c.Name] = c
	}
	for _, name := range []string{"opensearch_red_samples", "check_failures"} {
		if c := byName[name]; c.Status != statusFail {
			t.Errorf("%s: %+v, want a failure", name, c)
		}
	}
	for _, name := range []string{"page_p95_ms", "search_p95_ms", "write_p95_ms", "servers_ready", "windows_servers_ready", "leaders_at_once", "os_ops_per_server_per_second", "brute_checked_per_account"} {
		if c := byName[name]; c.Status != statusPass {
			t.Errorf("%s: %+v, want a pass", name, c)
		}
	}
	for _, name := range []string{"events_lost", "ingest_p99_ms"} {
		if c := byName[name]; c.Status != statusSkip {
			t.Errorf("%s: %+v, want it skipped", name, c)
		}
	}
	if len(rep.Faults) != 4 {
		t.Fatalf("faults %+v", rep.Faults)
	}
	cut, win, standby, named := rep.Faults[0], rep.Faults[1], rep.Faults[2], rep.Faults[3]
	if cut.Server != "one" || cut.Undone == nil || cut.TakeoverSeconds == nil || cut.NewLeader != "two" || toxic.Load() != 2 {
		t.Errorf("cut_opensearch fault %+v, toxiproxy calls %d", cut, toxic.Load())
	}
	if win.Server != "two" || !strings.Contains(win.Output, "windows two") || !strings.Contains(win.Output, "winundo") {
		t.Errorf("windows fault %+v", win)
	}
	if standby.Error == "" || standby.Server == "" {
		t.Errorf("failing fault %+v", standby)
	}
	if named.Server != "nowhere" || !strings.Contains(named.Output, "named") {
		t.Errorf("named fault %+v", named)
	}
	if len(rep.Checks) != 2 || !rep.Checks[0].Pass || rep.Checks[1].Pass {
		t.Errorf("checks %+v", rep.Checks)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "seed flaky") {
		t.Errorf("notes lack the failed seed step: %s", notes)
	}
	var seeded bool
	for _, p := range rep.Phases {
		if _, ok := p.Values["seed_rules_seconds"]; ok {
			seeded = true
		}
	}
	if !seeded || f.count("POST /api/seed/{n}") != 3 {
		t.Errorf("seed not run: %d requests", f.count("POST /api/seed/{n}"))
	}
	if !strings.Contains(out, "fake-cluster") {
		t.Errorf("text report:\n%s", out)
	}
}

func TestRunScenarioNeeds(t *testing.T) {
	f := newFakeSignalith(t, "one")
	dir := files(t, map[string]string{"admin.txt": "admin:pw\n"})
	admin := filepath.Join(dir, "admin.txt")
	tests := []struct {
		name    string
		needs   string
		admin   bool
		upgrade bool
		skipped string
	}{
		{"cluster", "cluster", true, false, "needs a cluster"},
		{"windows", "windows_server", true, false, "needs a Windows server"},
		{"unknown", "gpu", true, false, "cannot check for yet"},
		{"no admin", "proxy_protocol", false, false, "takes credentials.admin_file"},
		{"no setting", "opensearch_urls", true, false, "no opensearch.urls setting"},
		{"no upgrade", "rolling_upgrade", true, false, "does not have (no GET /api/cluster/upgrade)"},
		{"upgrade", "rolling_upgrade", true, true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f.mu.Lock()
			f.upgrade = tc.upgrade
			f.mu.Unlock()
			cred := ""
			if tc.admin {
				cred = "credentials: {admin_file: " + admin + "}\n"
			}
			path := filepath.Join(t.TempDir(), "s.yaml")
			if err := os.WriteFile(path, []byte("name: needs\nneeds: ["+tc.needs+"]\ntargets: ["+f.urls()[0]+"]\n"+cred+
				"phases:\n  - {name: p, for: 50ms}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			report := filepath.Join(t.TempDir(), "r.json")
			code, out, errOut := runCmd(t, "run", "-q", "-f", path, "-json", report)
			if code != exitPass {
				t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
			}
			rep := readJSONReport(t, report)
			if tc.skipped == "" && rep.Skipped != "" || !strings.Contains(rep.Skipped, tc.skipped) {
				t.Errorf("skipped %q, want %q", rep.Skipped, tc.skipped)
			}
		})
	}
	// Settings that cannot be read say so.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			w.Write([]byte(`{}`))
		default:
			http.Error(w, "down", http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	for _, need := range []string{"proxy_protocol", "rolling_upgrade"} {
		path := filepath.Join(t.TempDir(), "s.yaml")
		_ = os.WriteFile(path, []byte("name: needs\nneeds: ["+need+"]\ntargets: ["+srv.URL+"]\ncredentials: {admin_file: "+admin+"}\nphases:\n  - {name: p, for: 50ms}\n"), 0o600)
		code, out, _ := runCmd(t, "run", "-q", "-f", path)
		if code != exitPass || !strings.Contains(out, "did not answer") && !strings.Contains(out, "could not read the settings") {
			t.Errorf("%s with settings down: %d\n%s", need, code, out)
		}
	}
}

func TestBruteDialer(t *testing.T) {
	ln := newLocalListener(t)
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()
	b := &Brute{load: BruteLoad{ViaProxy: "203.0.113.9"}}
	c, err := b.dialer(1)(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h := <-got
	if len(h) < 12 || string(h[:12]) != "\r\n\r\n\x00\r\nQUIT\n" {
		t.Errorf("no PROXY v2 header sent: %q", h)
	}
	// A proxy address that is not one is an error.
	b.load.ViaProxy = "not-an-address"
	if _, err := b.dialer(1)(context.Background(), "tcp", ln.Addr().String()); err == nil {
		t.Error("bad proxy address gives no error")
	}
	// A host name is looked up.
	b.load.ViaProxy = ""
	_, port, _ := strings.Cut(ln.Addr().String(), ":")
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	c2, err := b.dialer(0)(context.Background(), "tcp", "localhost:"+port)
	if err != nil {
		t.Skipf("localhost does not resolve to the listener: %v", err)
	}
	c2.Close()
	if hostOf("h:1") != "h" || portOf("h:1") != "1" || hostOf("bad") != "" {
		t.Error("hostOf/portOf")
	}
}

func TestCookieFlooder(t *testing.T) {
	var cookies atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("signalith_session"); err == nil && len(c.Value) == 36 {
			cookies.Add(1)
		}
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()
	m := newMetrics()
	m.SetPhase("p")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	(&CookieFlooder{rate: 50, targets: []string{srv.URL}, tr: http.DefaultTransport, m: m}).Run(ctx)
	if m.Count("p", "cookie_status_401") == 0 || cookies.Load() == 0 {
		t.Errorf("cookie requests %d, 401s %d", cookies.Load(), m.Count("p", "cookie_status_401"))
	}
	// An unreachable target counts errors.
	m2 := newMetrics()
	m2.SetPhase("p")
	ctx2, cancel2 := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel2()
	(&CookieFlooder{rate: 30, targets: []string{"http://127.0.0.1:1"}, tr: http.DefaultTransport, m: m2}).Run(ctx2)
	if m2.Count("p", "cookie_errors") == 0 {
		t.Error("errors not counted")
	}
}

func TestBrowsersWithoutAccounts(t *testing.T) {
	m := newMetrics()
	m.SetPhase("p")
	(&Browsers{load: UserLoad{N: 4}, m: m}).Run(context.Background())
	if m.Count("p", "users_without_account") != 4 {
		t.Error("users without accounts not counted")
	}
	if d := (&Browsers{}).think(); d.Seconds() != 5 {
		t.Errorf("default think time %v", d)
	}
}

func TestBrowserCallStatuses(t *testing.T) {
	status := atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" {
			w.Write([]byte(`{}`))
			return
		}
		http.Error(w, "x", int(status.Load()))
	}))
	defer srv.Close()
	m := newMetrics()
	m.SetPhase("p")
	b := &Browsers{m: m}
	s := newSession(srv.URL, http.DefaultTransport, "u", "p")
	for _, tc := range []struct {
		status int
		cont   bool
		count  string
	}{
		{http.StatusUnauthorized, false, "unexpected_signouts"},
		{http.StatusConflict, true, "write_conflicts"},
		{http.StatusInternalServerError, true, "user_status_500"},
	} {
		status.Store(int64(tc.status))
		if got := b.call(context.Background(), s, &openPage{}, "page", http.MethodGet, "/api/x", nil, nil); got != tc.cont {
			t.Errorf("%d: call = %v", tc.status, got)
		}
		if m.Count("p", tc.count) != 1 {
			t.Errorf("%d: %s not counted", tc.status, tc.count)
		}
	}
	// A server that is gone stops the round.
	srv.Close()
	if b.call(context.Background(), s, &openPage{}, "page", http.MethodGet, "/api/x", nil, nil) {
		t.Error("call to a closed server continues")
	}
}

func TestSessionErrors(t *testing.T) {
	s := newSession("http://127.0.0.1:1/", http.DefaultTransport, "u", "p")
	if s.Base != "http://127.0.0.1:1" {
		t.Errorf("base %q", s.Base)
	}
	if err := s.Do(context.Background(), http.MethodGet, "/x", nil, nil); err == nil {
		t.Error("unreachable server gives no error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not json")) }))
	defer srv.Close()
	s = newSession(srv.URL, http.DefaultTransport, "u", "p")
	var out map[string]any
	if err := s.Do(context.Background(), http.MethodGet, "/x", nil, &out); err == nil || !strings.Contains(err.Error(), "GET /x") {
		t.Errorf("bad JSON answer: %v", err)
	}
	if err := s.Do(context.Background(), http.MethodPost, "/x", func() {}, nil); err == nil {
		t.Error("a body that is not JSON gives no error")
	}
	if err := s.raw(context.Background(), "BAD METHOD", "/x", nil, nil); err == nil {
		t.Error("bad method gives no error")
	}
	e := &apiError{Status: 418, Body: " teapot \n"}
	if e.Error() != "HTTP 418: teapot" || statusOf(e) != 418 || statusOf(nil) != 0 {
		t.Errorf("apiError %q", e.Error())
	}
	if truncate("abcdef", 3) != "abc..." || truncate("ab", 3) != "ab" {
		t.Error("truncate")
	}
}

func TestReadFiles(t *testing.T) {
	dir := files(t, map[string]string{
		"login.txt":  "bob:secret\nignored\n",
		"spaced.txt": "my password:x\n",
		"pw.txt":     "justapassword\n",
		"users.csv":  "username,password\n# comment\nana , apw \n",
	})
	if _, err := readSecret(""); err == nil {
		t.Error("readSecret with no file gives no error")
	}
	if u, p, err := readLogin(filepath.Join(dir, "login.txt")); err != nil || u != "bob" || p != "secret" {
		t.Errorf("readLogin = %q %q %v", u, p, err)
	}
	if u, p, _ := readLogin(filepath.Join(dir, "spaced.txt")); u != "signalithadmin" || p != "my password:x" {
		t.Errorf("readLogin of a password with a colon = %q %q", u, p)
	}
	if u, p, _ := readLogin(filepath.Join(dir, "pw.txt")); u != "signalithadmin" || p != "justapassword" {
		t.Errorf("readLogin of a password = %q %q", u, p)
	}
	users, err := readUsers(filepath.Join(dir, "users.csv"))
	if err != nil || len(users) != 1 || users[0] != [2]string{"ana", "apw"} {
		t.Errorf("readUsers = %v %v", users, err)
	}
	if _, err := readUsers(filepath.Join(dir, "none.csv")); err == nil {
		t.Error("missing users file gives no error")
	}
}

func TestClusterViewNames(t *testing.T) {
	var v clusterView
	if err := json.Unmarshal([]byte(`{"servers":[{"name":"a","state":"ready","os":"linux"},{"name":"b","self":true,"state":"starting","os":"windows"}]}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.selfName() != "b" || !v.isWindows("b") || v.isWindows("a") || v.isWindows("c") || len(v.live()) != 1 || len(v.windows()) != 0 {
		t.Errorf("view %+v", v)
	}
	if (clusterView{}).selfName() != "" {
		t.Error("selfName of an empty view")
	}
}

func newLocalListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}
