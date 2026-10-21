// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// blockPath puts a folder holding a file where a file belongs, so writing
// or removing it fails on every system.
func blockPath(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNewClientCA(t *testing.T) {
	p := testPaths(t)
	a := &Agent{Paths: p}
	c, err := a.newClient()
	if err != nil || c.Transport.(*http.Transport).TLSClientConfig.RootCAs != nil {
		t.Errorf("no ca.pem = %v", err)
	}
	os.WriteFile(p.caFile(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSigned(t)}), 0o644)
	c, err = a.newClient()
	if err != nil || c.Transport.(*http.Transport).TLSClientConfig.RootCAs == nil {
		t.Errorf("ca.pem = %v", err)
	}
	os.WriteFile(p.caFile(), []byte("junk"), 0o644)
	if _, err := a.newClient(); err == nil || !strings.Contains(err.Error(), "holds no certificate") {
		t.Errorf("junk ca.pem = %v", err)
	}
	os.Remove(p.caFile())
	blockPath(t, p.caFile())
	if _, err := a.newClient(); err == nil {
		t.Error("a folder was read as ca.pem")
	}
	// Run stops at a client it cannot make.
	if err := (&Agent{Paths: p, Name: "x", Log: quietLog()}).Run(context.Background()); err == nil {
		t.Error("Run with no client")
	}
	// Or a state folder it cannot make.
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, []byte("x"), 0o600)
	a = &Agent{Paths: Paths{Conf: p.Conf, State: file}, Name: "x", Log: quietLog(), Client: http.DefaultClient}
	if err := a.Run(context.Background()); err == nil {
		t.Error("Run with a file for a state folder")
	}
}

// refusingServer refuses the configuration with a message, and the status
// without one.
type refusingServer struct {
	mu    sync.Mutex
	names []string
	query []string
}

func (s *refusingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.names = append(s.names, r.Header.Get(agentproto.HeaderName))
	s.query = append(s.query, r.URL.RawQuery)
	s.mu.Unlock()
	if r.URL.Path == agentproto.RouteConfig {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"down for maintenance"}`)
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprint(w, "busy")
}

// TestRunWithDefaults: an agent with no name or client takes the
// computer's and makes one; a refused configuration and status show in
// the health file, and the configuration kept from before still runs.
func TestRunWithDefaults(t *testing.T) {
	s := &refusingServer{}
	srv := httptest.NewServer(s)
	defer srv.Close()
	p := testPaths(t)
	p.FluentBit = ""
	p.OsqueryUnit = "signalith-osquery.service"
	// The configuration from before, with osquery, but flags that cannot
	// be written.
	cfg, _ := json.Marshal(agentproto.Config{Revision: "r1", Osquery: &agentproto.Osquery{Flags: "--utc\n"}})
	os.WriteFile(p.configFile(), cfg, 0o600)
	blockPath(t, p.osqueryFlags())
	var shows sync.WaitGroup
	shows.Add(1)
	var once sync.Once
	a := &Agent{Paths: p, Settings: Settings{Server: srv.URL, Token: "t"}, Version: "1.0.0", Log: quietLog(),
		Facts: func() facts { return facts{Sysmon: true, Osquery: true} },
		UnitState: func(context.Context, string) (map[string]string, error) {
			once.Do(shows.Done)
			return map[string]string{"LoadState": "loaded", "ActiveState": "activating", "SubState": "start"}, nil
		}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	host, _ := os.Hostname()
	waitFor(t, "the health file", func() bool {
		b, _ := os.ReadFile(p.HealthFile())
		return strings.Contains(string(b), "config=Signalith answered 500: down for maintenance") && strings.Contains(string(b), "reported=no")
	})
	shows.Wait()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.names[0] != host {
		t.Errorf("name %q, want %q", s.names[0], host)
	}
	if !strings.Contains(s.query[0], "sysmon=true") || !strings.Contains(s.query[0], "osquery=true") {
		t.Errorf("query %q", s.query[0])
	}
	if a.Status().Revision != "r1" {
		t.Errorf("the kept configuration is not in use: %+v", a.Status())
	}
}

// syncAgent is an agent ready to sync, its collectors not running.
func syncAgent(t *testing.T, server string) *Agent {
	t.Helper()
	p := testPaths(t)
	a := &Agent{Paths: p, Settings: Settings{Server: server, Token: "sgl_test"}, Version: "1.0.0", Name: "web-01",
		Client: http.DefaultClient, Log: quietLog(), Facts: func() facts { return facts{} }, now: time.Now}
	a.fluentBit = newProc("fluentbit", a.Log, a.now, nil)
	a.osquery = a.newOsquery()
	return a
}

func TestSyncFailures(t *testing.T) {
	ctx := context.Background()
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()

	a := syncAgent(t, srv.URL)
	body = strings.Repeat(" ", maxConfigBytes+1)
	if err := a.sync(ctx); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("large = %v", err)
	}
	body = "{"
	if err := a.sync(ctx); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("bad JSON = %v", err)
	}
	body = `{"revision":"r1","fluentbit":{"config":"[INPUT]\n"}}`
	blockPath(t, a.Paths.fluentBitConf())
	if err := a.sync(ctx); err == nil || !strings.Contains(err.Error(), "Fluent Bit's configuration") {
		t.Errorf("fluent bit = %v", err)
	}
	os.RemoveAll(a.Paths.fluentBitConf())
	blockPath(t, a.Paths.configFile())
	if err := a.sync(ctx); err == nil || !strings.Contains(err.Error(), "keeping the configuration") {
		t.Errorf("config = %v", err)
	}
	os.RemoveAll(a.Paths.configFile())
	body = `{"revision":"r1","ca":"junk"}`
	if err := a.sync(ctx); err == nil || !strings.Contains(err.Error(), "holds no certificate") {
		t.Errorf("ca = %v", err)
	}
	body = `{"revision":"r1"}`
	blockPath(t, a.Paths.osqueryFlags())
	if err := a.sync(ctx); err == nil || !strings.Contains(err.Error(), "removing osquery's flags") {
		t.Errorf("osquery flags = %v", err)
	}
	os.RemoveAll(a.Paths.osqueryFlags())
	body = `{"revision":"r1","osquery":{"flags":"--utc\n"}}`
	os.WriteFile(a.Paths.osqueryState(), []byte("x"), 0o600)
	if err := a.sync(ctx); err == nil {
		t.Error("osquery flags written with a file for osquery's folder")
	}
	os.Remove(a.Paths.osqueryState())
	blockPath(t, a.Paths.osqueryFlags())
	if err := a.sync(ctx); err == nil || !strings.Contains(err.Error(), "writing osquery's flags") {
		t.Errorf("osquery flags over a folder = %v", err)
	}
	os.RemoveAll(a.Paths.osqueryFlags())
	body = `{"revision":"r1"}`
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	// The same revision again is not applied again.
	os.Remove(a.Paths.configFile())
	if err := a.apply(&agentproto.Config{Revision: a.Status().Revision}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.Paths.configFile()); err == nil {
		t.Error("the same revision was written again")
	}
	// The same CA is not written again.
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSigned(t)}))
	if err := a.writeCA(ca, nil); err != nil {
		t.Fatal(err)
	}
	st1, _ := os.Stat(a.Paths.caFile())
	if err := a.writeCA("-----BEGIN NOTE-----\neA==\n-----END NOTE-----\n"+ca, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.writeCA(ca, nil); err != nil {
		t.Fatal(err)
	}
	if st2, _ := os.Stat(a.Paths.caFile()); st1 == nil || st2 == nil {
		t.Error("ca.pem missing")
	}
	bad := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}))
	if err := a.writeCA(bad, nil); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Errorf("broken certificate = %v", err)
	}

	// A bad address, and a server that is gone.
	a.Settings.Server = "http://[::1"
	if err := a.sync(ctx); err == nil {
		t.Error("synced with a bad address")
	}
	srv.Close()
	a.Settings.Server = srv.URL
	if err := a.sync(ctx); err == nil {
		t.Error("synced with no server")
	}
	if err := a.get(ctx, "/x", nil, io.Discard, 10); err == nil {
		t.Error("got from no server")
	}
	a.Settings.Server = "http://[::1"
	if err := a.get(ctx, "/x", nil, io.Discard, 10); err == nil {
		t.Error("got from a bad address")
	}
}

func TestGetAndStageFailures(t *testing.T) {
	ctx := context.Background()
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	a := syncAgent(t, srv.URL)
	status, body = http.StatusNotFound, `{"error":"no such release"}`
	if err := a.get(ctx, "/x", nil, io.Discard, 100); err == nil || !strings.Contains(err.Error(), "no such release") {
		t.Errorf("404 = %v", err)
	}
	status, body = http.StatusOK, strings.Repeat("x", 11)
	if err := a.get(ctx, "/x", nil, io.Discard, 10); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("too much = %v", err)
	}
	u := &agentproto.Update{Version: "9.9.9"}
	status, body = http.StatusBadGateway, ""
	if err := a.stageUpdate(ctx, u); err == nil || !strings.Contains(err.Error(), "the manifest") {
		t.Errorf("no manifest = %v", err)
	}
	status, body = http.StatusOK, "{"
	if err := a.stageUpdate(ctx, u); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("bad manifest = %v", err)
	}
	os.RemoveAll(a.Paths.updateDir())
	os.WriteFile(a.Paths.updateDir(), []byte("x"), 0o600)
	if err := a.stageUpdate(ctx, u); err == nil {
		t.Error("staged with a file for the update folder")
	}
	// A result that is not JSON is no result.
	os.Remove(a.Paths.updateDir())
	os.MkdirAll(a.Paths.updateDir(), 0o700)
	os.WriteFile(a.Paths.resultFile(), []byte("{"), 0o600)
	if a.readResult() != nil {
		t.Error("a broken result was read")
	}
}

func TestReadSettingsEmptyToken(t *testing.T) {
	p := testPaths(t)
	os.WriteFile(p.settingsFile(), []byte("# set up\nSERVER=\"https://siem:8443\"\nnot a setting\nOSQUERY=yes\n"), 0o600)
	os.WriteFile(p.tokenFile(), []byte("  \n"), 0o600)
	if _, err := ReadSettings(p); err == nil || !strings.Contains(err.Error(), "token file is empty") {
		t.Errorf("empty token = %v", err)
	}
	os.WriteFile(p.tokenFile(), []byte("sgl_x\n"), 0o600)
	s, err := ReadSettings(p)
	if err != nil || s.Server != "https://siem:8443" || !s.Osquery || s.Token != "sgl_x" {
		t.Errorf("settings %+v %v", s, err)
	}
}

func TestLineRing(t *testing.T) {
	r := &lineRing{max: 10}
	r.add(strings.Repeat("x", 600))
	for i := range 12 {
		r.add(fmt.Sprint("line ", i))
	}
	got := strings.Split(r.String(), "\n")
	if len(got) != 8 || got[7] != "line 11" || got[0] != "line 4" {
		t.Errorf("ring %q", got)
	}
	if len(r.lines) != 10 {
		t.Errorf("kept %d", len(r.lines))
	}
	r.reset()
	if r.String() != "" {
		t.Error("reset")
	}
	r = &lineRing{max: 2}
	r.add(strings.Repeat("y", 600))
	if len(r.lines[0]) != 500 {
		t.Errorf("a long line kept %d", len(r.lines[0]))
	}
	// Blank lines are not kept.
	p := newProc("x", quietLog(), time.Now, nil)
	p.out = io.Discard
	p.copyLines(strings.NewReader("a\n\n\r\nb\n"))
	if p.tail.String() != "a\nb" {
		t.Errorf("tail %q", p.tail.String())
	}
}

// TestUnitProcRun: the loop asks systemd, again after a kick, and stops
// with its context.
func TestUnitProcRun(t *testing.T) {
	var mu sync.Mutex
	asks := 0
	u := newUnitProc("osquery", "o.service", quietLog(), time.Now, nil)
	u.show = func(context.Context, string) (map[string]string, error) {
		mu.Lock()
		asks++
		mu.Unlock()
		return map[string]string{"LoadState": "loaded", "ActiveState": "reloading"}, nil
	}
	u.setVersion("5.0.0")
	u.set(&procSpec{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.run(ctx); close(done) }()
	waitFor(t, "a second ask", func() bool {
		mu.Lock()
		defer mu.Unlock()
		if asks == 1 {
			u.set(&procSpec{})
		}
		return asks >= 2
	})
	cancel()
	<-done
	if c := u.component(); c.State != agentproto.StateStarting || c.Version != "5.0.0" {
		t.Errorf("component %+v", c)
	}
}

// TestProcCannotStart: a collector whose program will not start is
// failed, and tried again.
func TestProcCannotStart(t *testing.T) {
	notProgram := filepath.Join(t.TempDir(), "notes.txt")
	os.WriteFile(notProgram, []byte("not a program"), 0o600)
	p := newProc("fluentbit", quietLog(), time.Now, nil)
	p.set(&procSpec{Path: notProgram})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.run(ctx); close(done) }()
	waitFor(t, "the failure", func() bool {
		c := p.component()
		return c.State == agentproto.StateFailed && strings.Contains(c.Error, "could not start")
	})
	cancel()
	<-done

	// A missing program waits, and stops with the context.
	p = newProc("fluentbit", quietLog(), time.Now, nil)
	p.set(&procSpec{Path: filepath.Join(t.TempDir(), "missing")})
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { p.run(ctx); close(done) }()
	waitFor(t, "missing", func() bool { return p.stateNow() == agentproto.StateMissing })
	cancel()
	<-done
}

func TestAgentSmallPaths(t *testing.T) {
	a := syncAgent(t, "http://127.0.0.1:0")
	// A kept configuration that is not JSON is none.
	os.WriteFile(a.Paths.configFile(), []byte("{"), 0o600)
	if _, err := a.loadConfig(); err == nil {
		t.Error("a broken configuration was read")
	}
	// Fluent Bit gets the agent's token and name, not the environment's.
	t.Setenv("SIGNALITH_TOKEN", "from-the-environment")
	a.runFluentBit(&agentproto.Config{FluentBit: &agentproto.FluentBit{}})
	a.fluentBit.mu.Lock()
	env := strings.Join(a.fluentBit.spec.Env, "\n")
	a.fluentBit.mu.Unlock()
	if strings.Contains(env, "from-the-environment") || !strings.Contains(env, "SIGNALITH_TOKEN=sgl_test") || !strings.Contains(env, "HOSTNAME=web-01") {
		t.Errorf("env %q", env)
	}
	if programVersion(filepath.Join(t.TempDir(), "missing")) != "" {
		t.Error("a missing program has a version")
	}
	// The same CA twice is written once; a CA that cannot be written is
	// an error.
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSigned(t)}))
	if err := a.writeCA(ca, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.writeCA(ca, nil); err != nil {
		t.Fatal(err)
	}
	os.Remove(a.Paths.caFile())
	blockPath(t, a.Paths.caFile())
	if err := a.writeCA(ca, nil); err == nil || !strings.Contains(err.Error(), "writing the certificate authority") {
		t.Errorf("blocked ca.pem = %v", err)
	}
	// A status with no configuration yet says so.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	a.Settings.Server = srv.URL
	a.started = time.Now()
	a.sendStatus(context.Background())
	if b, _ := os.ReadFile(a.Paths.HealthFile()); !strings.Contains(string(b), "config=none yet") || !strings.Contains(string(b), "reported=yes") {
		t.Errorf("health %q", b)
	}
}

// TestCheckUpdateStates: a ready update nothing installed, and an
// updater that does not start, are reported.
func TestCheckUpdateStates(t *testing.T) {
	ctx := context.Background()
	a := syncAgent(t, "http://127.0.0.1:0")
	a.Version = "1.0.0"
	a.cfg = &agentproto.Config{Update: &agentproto.Update{Version: "2.0.0"}}
	os.MkdirAll(a.Paths.updateDir(), 0o700)
	os.WriteFile(a.Paths.readyFile(), []byte("2.0.0\n"), 0o600)
	later := time.Now().Add(2 * updaterWait)
	a.now = func() time.Time { return later }
	a.checkUpdate(ctx)
	if a.update == nil || !strings.Contains(a.update.Error, "nothing installed it") {
		t.Errorf("stale ready file = %+v", a.update)
	}
}

// hookService fails the updater's calls on cue.
type hookService struct {
	*fakeService
	mu       sync.Mutex
	stopErr  error
	restarts int
	// restart runs before the n-th Restart (from 1); an error stops it.
	restart func(n int) error
	states  int
	state   func(n int) (bool, string, error)
}

func (h *hookService) Stop(ctx context.Context) error {
	if h.stopErr != nil {
		return h.stopErr
	}
	return h.fakeService.Stop(ctx)
}

func (h *hookService) Restart(ctx context.Context) error {
	h.mu.Lock()
	h.restarts++
	n := h.restarts
	h.mu.Unlock()
	if h.restart != nil {
		if err := h.restart(n); err != nil {
			return err
		}
	}
	return h.fakeService.Restart(ctx)
}

func (h *hookService) State(ctx context.Context) (bool, string, error) {
	h.mu.Lock()
	h.states++
	n := h.states
	h.mu.Unlock()
	if h.state != nil {
		return h.state(n)
	}
	return h.fakeService.State(ctx)
}

func TestUpdaterFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(t *testing.T, c *updaterCase, h *hookService)
		want  string
	}{
		"version before cannot be kept": {func(t *testing.T, c *updaterCase, h *hookService) {
			blockPath(t, c.u.Paths.Prev)
		}, "keeping the version before"},
		"agent does not stop": {func(t *testing.T, c *updaterCase, h *hookService) {
			h.stopErr = fmt.Errorf("access denied")
		}, "stopping the agent"},
		"agent does not restart": {func(t *testing.T, c *updaterCase, h *hookService) {
			h.restart = func(int) error { return fmt.Errorf("unit masked") }
		}, "restarting the agent"},
		"going back cannot copy": {func(t *testing.T, c *updaterCase, h *hookService) {
			c.svc.broken = "silent"
			h.restart = func(n int) error {
				if n == 1 {
					os.Remove(c.u.Paths.Prev)
					// A status that is not JSON is no report.
					os.WriteFile(c.u.Paths.StatusFile(), []byte("{"), 0o600)
				}
				return nil
			}
		}, "going back failed too"},
		"folder of the version before is a file": {func(t *testing.T, c *updaterCase, h *hookService) {
			os.WriteFile(filepath.Dir(c.u.Paths.Prev), []byte("x"), 0o600)
		}, "keeping the version before"},
		"manifest too large": {func(t *testing.T, c *updaterCase, h *hookService) {
			os.WriteFile(c.u.Paths.stagedManifest(), []byte(strings.Repeat(" ", agentproto.MaxManifestBytes+1)), 0o600)
		}, "larger than any update writes"},
		"staged program is a folder": {func(t *testing.T, c *updaterCase, h *hookService) {
			os.Remove(c.u.Paths.stagedProgram())
			blockPath(t, c.u.Paths.stagedProgram())
		}, ""},
		"going back cannot restart": {func(t *testing.T, c *updaterCase, h *hookService) {
			c.svc.broken = "silent"
			h.restart = func(n int) error {
				if n == 2 {
					return fmt.Errorf("unit masked")
				}
				return nil
			}
		}, "going back failed too"},
		"service state unknown": {func(t *testing.T, c *updaterCase, h *hookService) {
			h.state = func(n int) (bool, string, error) {
				if n <= 2 {
					return true, "", nil
				}
				return false, "", fmt.Errorf("no bus")
			}
		}, "no bus"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newUpdaterCase(t, releaseKey(t), "2.0.0")
			h := &hookService{fakeService: c.svc}
			c.u.Service = h
			tc.setup(t, c, h)
			err := c.u.Install(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if r := c.result(t); r.OK {
				t.Errorf("result = %+v", r)
			}
		})
	}
}

// TestUpdaterStopped: an install stopped while it waits for the new
// version goes back to the version before.
func TestUpdaterStopped(t *testing.T) {
	c := newUpdaterCase(t, releaseKey(t), "2.0.0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.svc.broken = "silent"
	c.u.Service = &hookService{fakeService: c.svc, restart: func(n int) error {
		if n == 1 {
			cancel()
		}
		return nil
	}}
	if err := c.u.Install(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if !bytes.Equal(c.installed(t), c.old) {
		t.Error("the version before is not back")
	}
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleepCtx = %v", err)
	}
	// No update folder: nothing to do.
	u := &Updater{Paths: testPaths(t), Version: "1.0.0", Service: c.svc, Log: quietLog()}
	if err := u.Install(context.Background()); err != nil {
		t.Errorf("no folder = %v", err)
	}
}

func TestDefaultPathsAndWrites(t *testing.T) {
	p := DefaultPaths()
	if p.Conf == "" || p.State == "" || p.Program == "" || p.Prev == "" || p.Service == "" {
		t.Errorf("default paths %+v", p)
	}
	if err := writeFile(filepath.Join(t.TempDir(), "missing", "f"), []byte("x"), 0o600); err == nil {
		t.Error("wrote into a missing folder")
	}
	// A settings line too long to read.
	tp := testPaths(t)
	os.WriteFile(tp.settingsFile(), []byte("SERVER="+strings.Repeat("x", 70<<10)+"\n"), 0o600)
	if _, err := ReadSettings(tp); err == nil {
		t.Error("read a settings line longer than the scanner takes")
	}
}
