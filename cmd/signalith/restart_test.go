package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
)

// newFakeOpenSearch starts an in-memory OpenSearch that stops when the
// test ends.
func newFakeOpenSearch(t *testing.T) *ostest.Server { return ostest.New(t) }

// syncBuffer collects log lines written from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freeAddr returns a local address nothing listens on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// running is a server started with serve's runner, as signalith serve
// runs it.
type running struct {
	t      *testing.T
	r      *runner
	addr   string
	os     *ostest.Server
	logs   *syncBuffer
	cookie string
	// dir holds signalith.yaml. scheme is how the web page answers, and
	// client what calls it: one that trusts the server's certificate
	// with HTTPS.
	dir    string
	scheme string
	client *http.Client
	// stop stops the server as an interrupt does, and waits for it.
	stop func()

	mu      sync.Mutex
	started []string // index prefix of each set of components started
}

// starts lists the index prefix of each set of components started.
func (rs *running) starts() string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return strings.Join(rs.started, ",")
}

// startRunner runs the server on a free local port with a signalith.yaml
// in a temporary folder, and page's settings saved on the Settings page.
// fail, when set, makes starting with a config fail.
func startRunner(t *testing.T, fail func(*config.Config) error, page map[string]any) *running {
	t.Helper()
	// Plain HTTP: these tests are about restarting; restarting with
	// HTTPS on is tested on its own.
	return startRunnerWith(t, runOptions{fail: fail, page: page, server: plainHTTP})
}

// plainHTTP is the server section that turns HTTPS off.
const plainHTTP = "  tls:\n    mode: off\n"

// runOptions change how startRunnerWith starts the server.
type runOptions struct {
	fail func(*config.Config) error
	page map[string]any
	// server is added to signalith.yaml's server section; "" leaves HTTPS
	// on, as it is by default.
	server string
	// scheduler turns detections.scheduler on, so the server runs the
	// background jobs.
	scheduler bool
	// os is a fake OpenSearch to share with another server; nil makes
	// one. name is the server's name ("" is siem-test), and extra is
	// added to signalith.yaml.
	os    *ostest.Server
	name  string
	extra string
	// dir starts the server of an earlier test start again, with its
	// files as they are; "" makes a new one.
	dir string
}

// noFollow is a client that does not follow redirects.
var noFollow = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// startRunnerWith starts the server as serve does, with its cluster node.
// With HTTPS on, the client trusts Signalith's own certificate authority.
func startRunnerWith(t *testing.T, o runOptions) *running {
	t.Helper()
	fail, page := o.fail, o.page
	for _, name := range []string{"SIGNALITH_LISTEN", "SIGNALITH_PUBLIC_URL", "SIGNALITH_OPENSEARCH_URL", "SIGNALITH_OPENSEARCH_USERNAME",
		"SIGNALITH_OPENSEARCH_PASSWORD", "SIGNALITH_SETTINGS_FILE", "SIGNALITH_ADMIN_PASSWORD", "SIGNALITH_ASSISTANT_API_KEY",
		"SIGNALITH_SYSLOG_UDP", "SIGNALITH_SYSLOG_TCP", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_USERS_FILE",
		"SIGNALITH_STATE_DIR", "SIGNALITH_NODE_URL"} {
		t.Setenv(name, "")
	}
	name := o.name
	if name == "" {
		name = "siem-test"
	}
	t.Setenv("SIGNALITH_NODE_NAME", name)
	restartDelay, drainWait, oldAddressGrace = 10*time.Millisecond, time.Second, 300*time.Millisecond
	t.Cleanup(func() { restartDelay, drainWait, oldAddressGrace = 200*time.Millisecond, 5*time.Second, 30*time.Second })

	fos := o.os
	if fos == nil {
		fos = ostest.New(t)
	}
	dir := o.dir
	if dir == "" {
		dir = t.TempDir()
	}
	h, err := config.HashPassword("s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	path := filepath.Join(dir, "signalith.yaml")
	if prev, err := config.LoadFile(path); err == nil && o.dir != "" {
		// The same server again, with its files as they are.
		addr = prev.Server.Listen
	} else {
		body := "server:\n  listen: " + addr + "\n" + o.server + "opensearch:\n  url: " + fos.URL + "\nauth:\n  admin_password_hash: " + h +
			"\ningest:\n  tokens: [tok-0123456789abcdef]\ndetections:\n  scheduler: " + strconv.FormatBool(o.scheduler) + "\n" + o.extra
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(page) > 0 {
		p := &config.PageSettings{}
		for k, v := range page {
			p.Set(k, v, "admin", time.Now())
		}
		if err := config.WritePageSettings(filepath.Join(dir, "lookups", "settings.yaml"), p); err != nil {
			t.Fatal(err)
		}
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	node, log, err := openNode(c, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r := newRunner(path, log)
	r.node = node
	r.shared, r.sharedContent = openShared(c, node, log)
	node.Start(context.Background())
	sharedCtx, sharedStop := context.WithCancel(context.Background())
	r.shared.Start(sharedCtx)
	rs := &running{t: t, r: r, addr: addr, os: fos, logs: logs, dir: dir, scheme: "http", client: &http.Client{Timeout: 10 * time.Second}}
	r.failStart = func(c *config.Config) error {
		rs.mu.Lock()
		rs.started = append(rs.started, c.OpenSearch.IndexPrefix)
		rs.mu.Unlock()
		if fail != nil {
			return fail(c)
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.run(ctx, c) }()
	var once sync.Once
	rs.stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Error("the server did not stop")
			}
			node.Stop()
			node.Close()
			sharedStop()
			r.shared.Wait()
		})
	}
	t.Cleanup(rs.stop)
	deadline := time.Now().Add(10 * time.Second)
	for {
		// With HTTPS on, plain HTTP on the same port answers with a
		// redirect.
		if resp, err := noFollow.Get("http://" + addr + "/api/me"); err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server did not start:\n%s", logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c.Server.HTTPS() {
		rs.useHTTPS(rs.ownCA())
	}
	rs.signIn()
	return rs
}

// ownCA returns Signalith's own certificate authority, in PEM.
func (rs *running) ownCA() []byte {
	rs.t.Helper()
	pem, err := os.ReadFile(filepath.Join(rs.dir, "tls", "ca.pem"))
	if err != nil {
		rs.t.Fatal(err)
	}
	return pem
}

// useHTTPS calls the server over HTTPS, trusting the CA certificates in
// caPEM.
func (rs *running) useHTTPS(caPEM []byte) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		rs.t.Fatal("no CA certificate")
	}
	rs.scheme = "https"
	rs.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
}

// signIn signs in as the built-in admin and keeps the session cookie.
func (rs *running) signIn() {
	rs.t.Helper()
	resp, err := rs.client.Post(rs.scheme+"://"+rs.addr+"/api/login", "application/json", strings.NewReader(`{"username":"admin","password":"s3cret-pass"}`))
	if err != nil {
		rs.t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == "signalith_session" || c.Name == "__Host-signalith_session" {
			rs.cookie = c.Name + "=" + c.Value
		}
	}
	if resp.StatusCode != 200 || rs.cookie == "" {
		rs.t.Fatalf("sign in: %d %v", resp.StatusCode, resp.Cookies())
	}
}

// call sends a request with the session cookie to addr ("" is the
// server's first address).
func (rs *running) call(addr, method, path, body string) (int, map[string]any, error) {
	rs.t.Helper()
	if addr == "" {
		addr = rs.addr
	}
	req, _ := http.NewRequest(method, rs.scheme+"://"+addr+path, strings.NewReader(body))
	req.Header.Set("Cookie", rs.cookie)
	req.Header.Set("Content-Type", "application/json")
	resp, err := rs.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, nil
}

// save changes settings on the Settings page.
func (rs *running) save(values string) {
	rs.t.Helper()
	code, out, err := rs.call("", "PUT", "/api/settings", `{"values":`+values+`}`)
	// A server that just founded the cluster shares its users from then
	// on, and everyone signs in once more.
	for deadline := time.Now().Add(20 * time.Second); err == nil && code == 401 && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
		rs.signIn()
		code, out, err = rs.call("", "PUT", "/api/settings", `{"values":`+values+`}`)
	}
	if err != nil || code != 200 {
		rs.t.Fatalf("save %s: %d %v %v", values, code, out, err)
	}
}

// restart asks for a restart on the Settings page and waits for it.
func (rs *running) restart() (map[string]any, *api.RestartResult) {
	rs.t.Helper()
	code, out, err := rs.call("", "POST", "/api/settings/restart", "")
	// A server that just founded the cluster restarts its components in
	// place by itself: wait for that one to end. Its users are then shared,
	// and everyone signs in once more.
	for deadline := time.Now().Add(20 * time.Second); err == nil && (code == 401 || code == 409 && out["code"] == "restarting") && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
		if code == 401 {
			rs.signIn()
		}
		code, out, err = rs.call("", "POST", "/api/settings/restart", "")
	}
	if err != nil || code != 202 {
		rs.t.Fatalf("restart: %d %v %v", code, out, err)
	}
	return out, rs.wait()
}

// wait waits for the restart in progress to end.
func (rs *running) wait() *api.RestartResult {
	rs.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if st := rs.r.RestartStatus(); !st.InProgress && st.Last != nil {
			return st.Last
		}
		if time.Now().After(deadline) {
			rs.t.Fatalf("the restart did not end:\n%s", rs.logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// signedIn reports whether the session cookie still works at addr.
func (rs *running) signedIn(addr string) bool {
	rs.t.Helper()
	code, _, err := rs.call(addr, "GET", "/api/me", "")
	return err == nil && code == 200
}

func TestRestartRebuildsComponentsAndKeepsSessions(t *testing.T) {
	rs := startRunner(t, nil, nil)
	rs.save(`{"opensearch.index_prefix":"siem2","search.max_events":777}`)
	out, res := rs.restart()
	if out["restarting"] != true || out["listen_changed"] != false {
		t.Errorf("restart answer %v", out)
	}
	if !res.OK || res.RolledBack || res.Error != "" || res.By != "admin" || strings.Join(res.Keys, ",") != "opensearch.index_prefix" {
		t.Fatalf("restart %+v\n%s", res, rs.logs.String())
	}
	if got := rs.starts(); got != "signalith,siem2" {
		t.Errorf("components started: %s", got)
	}
	// The new components installed the new index template.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(strings.Join(rs.os.Templates(), ","), "siem2") {
		if time.Now().After(deadline) {
			t.Fatalf("templates %v", rs.os.Templates())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !rs.signedIn("") {
		t.Error("the admin was signed out by the restart")
	}
	code, view, _ := rs.call("", "GET", "/api/settings", "")
	if code != 200 || len(view["pending"].([]any)) != 0 {
		t.Errorf("after the restart: %d pending %v", code, view["pending"])
	}
	last := view["restart"].(map[string]any)["last"].(map[string]any)
	if last["ok"] != true || last["by"] != "admin" {
		t.Errorf("restart status on the page %v", last)
	}
	if l := rs.logs.String(); !strings.Contains(l, `msg="restarted with the saved settings" node=siem-test audit=true by=admin`) || !strings.Contains(l, "settings=opensearch.index_prefix") {
		t.Errorf("audit log:\n%s", l)
	}
	// A second restart with nothing changed works too.
	if _, res := rs.restart(); !res.OK || len(res.Keys) != 0 {
		t.Errorf("second restart %+v", res)
	}
}

func TestRestartKeepsRunningWhenTheNewAddressIsTaken(t *testing.T) {
	rs := startRunner(t, nil, nil)
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	rs.save(`{"server.listen":"` + taken.Addr().String() + `"}`)
	_, res := rs.restart()
	if res.OK || res.RolledBack || !strings.Contains(res.Error, "cannot listen on "+taken.Addr().String()) || !strings.Contains(res.Error, "kept running with the previous settings") {
		t.Fatalf("restart %+v", res)
	}
	if got := rs.starts(); got != "signalith" {
		t.Errorf("the components were replaced: %s", got)
	}
	if !rs.signedIn("") {
		t.Error("the old address stopped answering")
	}
	if l := rs.logs.String(); !strings.Contains(l, `msg="restart failed" node=siem-test audit=true by=admin`) {
		t.Errorf("audit log:\n%s", l)
	}
}

func TestRestartKeepsRunningWhenOpenSearchDoesNotAnswer(t *testing.T) {
	rs := startRunner(t, nil, nil)
	rs.save(`{"opensearch.url":"http://` + freeAddr(t) + `"}`)
	_, res := rs.restart()
	if res.OK || res.RolledBack || !strings.Contains(res.Error, "OpenSearch did not answer with the new settings") {
		t.Fatalf("restart %+v", res)
	}
	if got := rs.starts(); got != "signalith" {
		t.Errorf("the components were replaced: %s", got)
	}
	if !rs.signedIn("") {
		t.Error("the server stopped answering")
	}
}

func TestRestartGoesBackWhenTheNewSettingsDoNotStart(t *testing.T) {
	rs := startRunner(t, func(c *config.Config) error {
		if c.OpenSearch.IndexPrefix == "broken" {
			return errors.New("the disk is full")
		}
		return nil
	}, nil)
	rs.save(`{"opensearch.index_prefix":"broken"}`)
	_, res := rs.restart()
	if res.OK || !res.RolledBack || !strings.Contains(res.Error, "the disk is full") || !strings.Contains(res.Error, "went back to the previous settings") {
		t.Fatalf("restart %+v", res)
	}
	if got := rs.starts(); got != "signalith,broken,signalith" {
		t.Errorf("not started again with the previous settings: %s", got)
	}
	if !rs.signedIn("") {
		t.Error("the admin was signed out, or the server stopped answering")
	}
	// The change is set aside, so the next start does not use it either;
	// the page shows it on its field, to try again or change.
	if strings.Join(res.Refused, ",") != "opensearch.index_prefix" {
		t.Errorf("set aside %v", res.Refused)
	}
	code, view, _ := rs.call("", "GET", "/api/settings", "")
	if refused := view["refused"].([]any); code != 200 || len(refused) != 1 || refused[0].(map[string]any)["key"] != "opensearch.index_prefix" || len(view["pending"].([]any)) != 0 {
		t.Errorf("refused %d %v pending %v", code, view["refused"], view["pending"])
	}
	if c, err := config.Load(rs.r.path); err != nil || c.OpenSearch.IndexPrefix != "signalith" {
		t.Errorf("the next start would use %v %v", c.OpenSearch.IndexPrefix, err)
	}
	if l := rs.logs.String(); !strings.Contains(l, "rolled_back=true") {
		t.Errorf("audit log:\n%s", l)
	}
}

func TestRestartMovesTheWebAddress(t *testing.T) {
	rs := startRunner(t, nil, nil)
	old, next := rs.addr, freeAddr(t)
	rs.save(`{"server.listen":"` + next + `"}`)
	out, res := rs.restart()
	if out["listen_changed"] != true || out["new_listen"] != next || out["go_to"] != "http://"+next+"/" {
		t.Errorf("restart answer %v", out)
	}
	if !res.OK {
		t.Fatalf("restart %+v\n%s", res, rs.logs.String())
	}
	if !rs.signedIn(next) {
		t.Error("the new address does not answer, or the session was lost")
	}
	// The old address answers for a while, so the page there learns where
	// to go, then closes.
	if code, st, err := rs.call(old, "GET", "/api/settings", ""); err != nil || code != 200 || st["restart"].(map[string]any)["last"].(map[string]any)["ok"] != true {
		t.Errorf("old address during the grace period: %d %v", code, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, _, err := rs.call(old, "GET", "/api/me", ""); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the old address kept answering")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRestartMovesToAllInterfacesOnTheSamePort(t *testing.T) {
	rs := startRunner(t, nil, nil)
	_, port, _ := net.SplitHostPort(rs.addr)
	rs.save(`{"server.listen":"0.0.0.0:` + port + `"}`)
	_, res := rs.restart()
	if !res.OK {
		t.Fatalf("restart %+v\n%s", res, rs.logs.String())
	}
	if !rs.signedIn(rs.addr) {
		t.Error("the port does not answer after the move")
	}
}

func TestFrontHoldsRequestsDuringASwap(t *testing.T) {
	f := &front{}
	f.resume(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "old") }), nil)
	f.pause(time.Second)
	got := make(chan string, 1)
	go func() {
		rec := httptest.NewRecorder()
		f.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		got <- rec.Body.String()
	}()
	select {
	case b := <-got:
		t.Fatalf("answered during the pause: %q", b)
	case <-time.After(50 * time.Millisecond):
	}
	f.resume(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "new") }), nil)
	if b := <-got; b != "new" {
		t.Errorf("answered by %q", b)
	}
	// A request held back too long is told to try again.
	saved := pauseLimit
	pauseLimit = 20 * time.Millisecond
	defer func() { pauseLimit = saved }()
	f.pause(time.Second)
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 503 || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), `"code":"restarting"`) {
		t.Errorf("held too long: %d %s", rec.Code, rec.Body.String())
	}
}

// capture returns what fn prints.
func capture(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	out := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	ferr := fn()
	os.Stdout = stdout
	w.Close()
	return <-out, ferr
}

func TestSettingsCommand(t *testing.T) {
	t.Setenv("SIGNALITH_SETTINGS_FILE", "")
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD", "")
	fos := ostest.New(t)
	dir := t.TempDir()
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte("opensearch:\n  url: "+fos.URL+"\nauth:\n  admin_password_hash: "+h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "lookups", "settings.yaml")
	page := &config.PageSettings{}
	at := time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)
	page.Set("search.max_events", 1234, "alice", at)
	// The page's secrets are saved encrypted, with the config's master key.
	c0, err := config.LoadUnchecked(path)
	if err != nil {
		t.Fatal(err)
	}
	useTestKeyring(t, c0.Keyring())
	if err := page.SetSecret("opensearch.password", "never-printed", strings.TrimSuffix(fos.URL, "/"), "alice", at); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePageSettings(file, page); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(file); strings.Contains(string(data), "never-printed") || !strings.Contains(string(data), "secret: enc:v1:") {
		t.Fatalf("settings file:\n%s", data)
	}

	out, err := capture(t, func() error { return cmdSettings([]string{"list", "-c", path}) })
	if err != nil || !strings.Contains(out, "search.max_events") || !strings.Contains(out, "1234") || !strings.Contains(out, "by alice") ||
		!strings.Contains(out, "(hidden)") || strings.Contains(out, "never-printed") {
		t.Errorf("list: %v\n%s", err, out)
	}
	out, err = capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	if err != nil || !strings.Contains(out, "Changed on the Settings page ("+file+"): opensearch.password, search.max_events.") {
		t.Errorf("validate: %v\n%s", err, out)
	}
	if _, err := capture(t, func() error { return cmdSettings([]string{"reset", "-c", path, "retention.days"}) }); err == nil || !strings.Contains(err.Error(), "not a setting on the Settings page") {
		t.Errorf("reset of a setting not on the page: %v", err)
	}
	out, err = capture(t, func() error { return cmdSettings([]string{"reset", "-c", path, "search.max_events"}) })
	if err != nil || !strings.Contains(out, "Reset search.max_events") {
		t.Errorf("reset: %v\n%s", err, out)
	}
	if left, err := config.ReadPageSettings(file); err != nil || strings.Join(left.Keys(), ",") != "opensearch.password" {
		t.Errorf("left after reset: %v %v", left, err)
	}

	// A broken settings file does not stop Signalith; validate says so,
	// and reset with no setting named removes it.
	if err := os.WriteFile(file, []byte("settings: [not, a, map]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	if err != nil || !strings.Contains(out, "is valid.") || !strings.Contains(out, "Warning: The settings saved on the Settings page were not used") {
		t.Errorf("validate with a broken settings file: %v\n%s", err, out)
	}
	if _, err := capture(t, func() error { return cmdSettings([]string{"list", "-c", path}) }); err == nil || !strings.Contains(err.Error(), "signalith settings reset") {
		t.Errorf("list of a broken file: %v", err)
	}
	out, err = capture(t, func() error { return cmdSettings([]string{"reset", "-c", path}) })
	if err != nil || !strings.Contains(out, "Removed every change") || !strings.Contains(out, "kept as "+file+".broken") {
		t.Errorf("reset all: %v\n%s", err, out)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the settings file is still there: %v", err)
	}
	// With no file, nothing is claimed.
	out, err = capture(t, func() error { return cmdSettings([]string{"reset", "-c", path}) })
	if err == nil || strings.Contains(out, "Removed") || !strings.Contains(err.Error(), "there is no settings file at "+file) {
		t.Errorf("reset without a file: %v\n%s", err, out)
	}
}

// The Linux service points the lookups folder at /var/lib/signalith in its
// unit, which a shell does not see: the settings commands then name the
// service's file, never claim to have reset what they did not, and take
// it with -file.
func TestSettingsCommandWithTheServiceLayout(t *testing.T) {
	t.Setenv("SIGNALITH_SETTINGS_FILE", "")
	t.Setenv("SIGNALITH_LOOKUPS_DIR", "")
	fos := ostest.New(t)
	dir := t.TempDir()
	h, _ := config.HashPassword("s3cret-pass")
	os.MkdirAll(filepath.Join(dir, "etc"), 0o750)
	path := filepath.Join(dir, "etc", "signalith.yaml")
	os.WriteFile(path, []byte("opensearch:\n  url: "+fos.URL+"\nauth:\n  admin_password_hash: "+h+"\n"), 0o600)
	svc := filepath.Join(dir, "var", "lookups", "settings.yaml")
	saved := serviceSettingsFile
	serviceSettingsFile = svc
	t.Cleanup(func() { serviceSettingsFile = saved })
	page := &config.PageSettings{}
	page.Set("server.listen", "127.0.0.1:18745", "admin", time.Now())
	page.Set("assistant.model", "llama3\nauth:\n  admin_user: eve", "admin", time.Now())
	if err := config.WritePageSettings(svc, page); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "linux" {
		t.Skip("the service layout is Linux's")
	}
	shell := filepath.Join(dir, "etc", "lookups", "settings.yaml")
	out, err := capture(t, func() error { return cmdSettings([]string{"list", "-c", path}) })
	if err != nil || !strings.Contains(out, "There is no settings file at "+shell) ||
		!strings.Contains(out, "sudo signalith settings list -c "+path+" -file "+svc) {
		t.Errorf("list: %v\n%s", err, out)
	}
	out, err = capture(t, func() error { return cmdSettings([]string{"reset", "-c", path}) })
	if err == nil || strings.Contains(out, "Removed every change") || !strings.Contains(err.Error(), "nothing was reset") {
		t.Errorf("reset all: %v\n%s", err, out)
	}
	_, err = capture(t, func() error { return cmdSettings([]string{"reset", "-c", path, "server.listen"}) })
	if err == nil || !strings.Contains(err.Error(), "-file "+svc+" server.listen") {
		t.Errorf("reset one: %v", err)
	}
	if left, _ := config.ReadPageSettings(svc); len(left.Keys()) != 2 {
		t.Fatalf("the service's file changed: %v", left.Keys())
	}
	out, _ = capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	if !strings.Contains(out, "Note: The Signalith service keeps its settings in "+svc) {
		t.Errorf("validate:\n%s", out)
	}
	// With -file, the service's file.
	out, err = capture(t, func() error { return cmdSettings([]string{"list", "-c", path, "-file", svc}) })
	if err != nil || !strings.Contains(out, `"llama3\nauth:\n  admin_user: eve"`) || strings.Contains(out, "\nauth:") {
		t.Errorf("list -file: %v\n%s", err, out)
	}
	os.Setenv("SIGNALITH_SETTINGS_FILE", "")
	out, err = capture(t, func() error { return cmdValidate([]string{"-c", path, "-file", svc}) })
	if !strings.Contains(out, "Changed on the Settings page ("+svc+"): assistant.model, server.listen.") {
		t.Errorf("validate -file: %v\n%s", err, out)
	}
	os.Setenv("SIGNALITH_SETTINGS_FILE", "")
	out, err = capture(t, func() error { return cmdSettings([]string{"reset", "-c", path, "-file", svc, "server.listen"}) })
	if err != nil || !strings.Contains(out, "Reset server.listen in "+svc) {
		t.Errorf("reset -file: %v\n%s", err, out)
	}
	if left, _ := config.ReadPageSettings(svc); strings.Join(left.Keys(), ",") != "assistant.model" {
		t.Errorf("left: %v", left.Keys())
	}
}

func TestStartWithSignalithYAMLWhenThePageSettingsFail(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	// A listen address saved on the page that is taken by the next start,
	// and a change that keeps the components from starting.
	for name, page := range map[string]map[string]any{
		"listen address taken": {"server.listen": taken.Addr().String(), "search.max_events": 50},
		"components fail":      {"opensearch.index_prefix": "broken"},
	} {
		t.Run(name, func(t *testing.T) {
			rs := startRunner(t, func(c *config.Config) error {
				if c.OpenSearch.IndexPrefix == "broken" {
					return errors.New("the disk is full")
				}
				return nil
			}, page)
			code, view, _ := rs.call("", "GET", "/api/settings", "")
			if code != 200 || !strings.Contains(view["startup_problem"].(string), "Signalith could not start with them") {
				t.Fatalf("settings page %d %q", code, view["startup_problem"])
			}
			// The page's settings wait for a restart, after they are fixed.
			waiting := map[string]bool{}
			for _, p := range view["pending"].([]any) {
				waiting[p.(map[string]any)["key"].(string)] = true
			}
			for k := range page {
				if !waiting[k] {
					t.Errorf("%s is not waiting for a restart: %v", k, view["pending"])
				}
			}
			if l := rs.logs.String(); !strings.Contains(l, "started with signalith.yaml alone") {
				t.Errorf("log:\n%s", l)
			}
		})
	}
}
