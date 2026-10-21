// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

// fakeOsqueryd stands in for osqueryd: the test program runs as it when
// it is started under that name. It writes down each start and the flags
// file it was given in AGENTD_FAKE_OSQUERYD_OUT.
func fakeOsqueryd() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("osqueryd version 5.12.1")
		return
	}
	if len(os.Args) != 2 || !strings.HasPrefix(os.Args[1], "--flagfile=") {
		fmt.Println("bad arguments:", os.Args[1:])
		os.Exit(2)
	}
	flags, err := os.ReadFile(strings.TrimPrefix(os.Args[1], "--flagfile="))
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	if out := os.Getenv("AGENTD_FAKE_OSQUERYD_OUT"); out != "" {
		f, err := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "start\n%s", flags)
			f.Close()
		}
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}

// osquerydExe is a copy of the test program named osqueryd.
func osquerydExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "osqueryd")
	if filepath.Ext(exe) == ".exe" {
		dst += ".exe"
	}
	// A copy, not a link: Windows cannot remove a link to the running
	// test program when the test ends.
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestAgentRunsOsquery(t *testing.T) {
	t.Setenv("AGENTD_FAKE_FLUENTBIT", "run")
	out := filepath.Join(t.TempDir(), "osqueryd-seen")
	t.Setenv("AGENTD_FAKE_OSQUERYD_OUT", out)
	p := testPaths(t)
	p.Osqueryd = osquerydExe(t)
	server := "--tls_hostname=siem.example.com:7779\n--config_plugin=tls\n"
	fs := &fakeServer{cfg: agentproto.Config{PollSeconds: 300, FluentBit: &agentproto.FluentBit{Config: "a"},
		Osquery: &agentproto.Osquery{Flags: server + "--extensions_autoload=/tmp/evil\n--enroll_secret_path=/tmp/mine\n"}}}
	srv := httptest.NewTLSServer(fs)
	defer srv.Close()
	a := newAgent(t, srv, p)
	a.Facts = nil
	a.Settings.Osquery = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	osq := func(st agentproto.Status) agentproto.Component {
		for _, c := range st.Components {
			if c.Name == "osquery" {
				return c
			}
		}
		return agentproto.Component{}
	}
	waitFor(t, "a status saying osquery runs", func() bool {
		st, ok := fs.lastStatus()
		return ok && osq(st).State == agentproto.StateRunning && st.Components[0].State == agentproto.StateRunning
	})
	st, _ := fs.lastStatus()
	if c := osq(st); c.Version != "5.12.1" || c.Restarts != 0 {
		t.Errorf("osquery = %+v", c)
	}
	fs.mu.Lock()
	asked := fs.asks[0].URL.Query().Get("osquery")
	fs.mu.Unlock()
	if asked != "true" {
		t.Errorf("the agent did not say the computer has osquery: %q", asked)
	}
	flags, err := os.ReadFile(p.osqueryFlags())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--tls_hostname=siem.example.com:7779\n", "--enroll_secret_path=" + p.tokenFile() + "\n",
		"--database_path=" + filepath.Join(p.State, "osquery", "osquery.db") + "\n", "--disable_extensions=true\n"} {
		if !strings.Contains(string(flags), want) {
			t.Errorf("flags have no %q:\n%s", want, flags)
		}
	}
	for _, not := range []string{"extensions_autoload", "/tmp/mine", "tls_server_certs"} {
		if strings.Contains(string(flags), not) {
			t.Errorf("flags have %q:\n%s", not, flags)
		}
	}
	waitFor(t, "the health file", func() bool {
		h, _ := os.ReadFile(p.HealthFile())
		return string(h) == "config=ok\nfluentbit=running\nosquery=running\nreported=yes\n"
	})
	starts := func() int {
		b, _ := os.ReadFile(out)
		return strings.Count(string(b), "start\n")
	}
	waitFor(t, "osqueryd's start", func() bool { return starts() == 1 })

	// A new configuration with the same flags leaves osquery running.
	fs.mu.Lock()
	fs.cfg.FluentBit = &agentproto.FluentBit{Config: "b"}
	fs.mu.Unlock()
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := starts(); n != 1 {
		t.Errorf("osquery started %d times for a Fluent Bit change", n)
	}
	// New flags restart it.
	fs.mu.Lock()
	fs.cfg.Osquery = &agentproto.Osquery{Flags: server + "--utc\n"}
	fs.mu.Unlock()
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "osquery started again", func() bool { return starts() == 2 })
	// The server says osquery cannot use it: osquery stops, with why.
	fs.mu.Lock()
	fs.cfg.Osquery = &agentproto.Osquery{Error: "use a host name"}
	fs.mu.Unlock()
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	a.sendStatus(ctx)
	st, _ = fs.lastStatus()
	if c := osq(st); c.State != agentproto.StateOff || c.Error != "use a host name" {
		t.Errorf("osquery = %+v", c)
	}
	if _, err := os.Stat(p.osqueryFlags()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("flags file left: %v", err)
	}
	// No osquery part: no osquery in the status.
	fs.mu.Lock()
	fs.cfg.Osquery = nil
	fs.mu.Unlock()
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	a.sendStatus(ctx)
	if st, _ = fs.lastStatus(); len(st.Components) != 1 {
		t.Errorf("components = %+v", st.Components)
	}
}

func TestOsqueryFlagsWithCA(t *testing.T) {
	p := testPaths(t)
	text, dropped := p.osqueryFlagsFile(&agentproto.Config{CA: "x", Osquery: &agentproto.Osquery{Flags: "--utc\n\n--logger_path=/x\nnot a flag\n"}})
	if !strings.Contains(text, "--tls_server_certs="+p.caFile()+"\n") || !strings.Contains(text, "--utc\n") || strings.Contains(text, "logger_path") {
		t.Errorf("flags:\n%s", text)
	}
	if strings.Join(dropped, " ") != "--logger_path not a flag" {
		t.Errorf("dropped = %q", dropped)
	}
}

func TestUnitProc(t *testing.T) {
	var mu sync.Mutex
	state := map[string]string{"LoadState": "not-found"}
	var showErr error
	now := time.Unix(1000, 0)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	u := newUnitProc("osquery", "signalith-osquery.service", slog.New(slog.NewTextHandler(io.Discard, nil)), clock, nil)
	u.show = func(_ context.Context, unit string) (map[string]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if unit != "signalith-osquery.service" {
			t.Errorf("unit = %q", unit)
		}
		m := map[string]string{}
		for k, v := range state {
			m[k] = v
		}
		return m, showErr
	}
	ctx := context.Background()
	set := func(m map[string]string, err error) {
		mu.Lock()
		state, showErr = m, err
		mu.Unlock()
	}
	check := func(want string, says string) {
		t.Helper()
		u.check(ctx)
		c := u.component()
		if c.State != want || !strings.Contains(c.Error, says) {
			t.Errorf("state = %q %q, want %q with %q", c.State, c.Error, want, says)
		}
	}
	check(agentproto.StateOff, "")
	u.set(&procSpec{})
	check(agentproto.StateMissing, "not installed")
	set(map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "NRestarts": "3"}, nil)
	check(agentproto.StateStarting, "")
	set(map[string]string{"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "NRestarts": "3"}, nil)
	check(agentproto.StateRunning, "")
	set(map[string]string{"LoadState": "loaded", "ActiveState": "activating", "SubState": "auto-restart", "NRestarts": "5"}, nil)
	check(agentproto.StateFailed, "journalctl -u signalith-osquery.service")
	if c := u.component(); c.Restarts != 2 {
		t.Errorf("restarts = %d, want 2", c.Restarts)
	}
	set(map[string]string{"LoadState": "loaded", "ActiveState": "failed", "NRestarts": "5"}, nil)
	check(agentproto.StateFailed, "failed")
	set(map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "NRestarts": "5"}, nil)
	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()
	check(agentproto.StateFailed, "is inactive")
	set(nil, errors.New("no bus"))
	check(agentproto.StateFailed, "no bus")
	u.set(nil)
	check(agentproto.StateOff, "")
}

// osquery's service checks the flags file again, outside the agent's
// sandbox: only the flags the agent writes pass.
func TestCheckOsqueryFlags(t *testing.T) {
	p := testPaths(t)
	good, _ := p.osqueryFlagsFile(&agentproto.Config{CA: "x", Osquery: &agentproto.Osquery{Flags: "--tls_hostname=siem:7779\n--utc\n"}})
	out, err := CheckOsqueryFlags(p, good)
	if err != nil || !strings.Contains(out, "--tls_hostname=siem:7779\n") || strings.Contains(out, "#") {
		t.Fatalf("the agent's own file: %v\n%s", err, out)
	}
	for name, bad := range map[string]string{
		"extensions":      good + "--extensions_autoload=/var/lib/signalith-agent/x.ext\n",
		"extensions on":   strings.Replace(good, "--disable_extensions=true", "--disable_extensions=false", 1),
		"extensions kept": strings.Replace(good, "--disable_extensions=true\n", "", 1),
		"other secret":    strings.Replace(good, "--enroll_secret_path="+p.tokenFile(), "--enroll_secret_path=/tmp/x", 1),
		"unknown":         good + "--logger_path=/tmp\n",
		"space":           good + "--utc=true --extensions_autoload=/x\n",
		"not a flag":      good + "extensions_autoload=/x\n",
	} {
		if _, err := CheckOsqueryFlags(p, bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// osquery's curl tables stay off whatever the server sends (ASI-12): the
// agent's own list comes last, which is the one osquery keeps.
func TestOsqueryFlagsDisableCurlTables(t *testing.T) {
	p := testPaths(t)
	cfg := &agentproto.Config{Osquery: &agentproto.Osquery{Flags: "--tls_hostname=siem.example.com:7779\n--disable_tables=processes\n"}}
	text, dropped := p.osqueryFlagsFile(cfg)
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if want := "--disable_tables=curl,curl_certificate"; lines[len(lines)-1] != want || len(dropped) != 0 {
		t.Errorf("flags end %q (dropped %v), want %q:\n%s", lines[len(lines)-1], dropped, want, text)
	}
	if _, err := CheckOsqueryFlags(p, text); err != nil {
		t.Errorf("the check refuses the agent's own flags: %v", err)
	}
}
