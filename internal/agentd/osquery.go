// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

// osquery, when the computer has it: Signalith is its management server.
// The agent writes osquery's flags (osquery.flags in the conf folder):
// the ones the server gives, which point osquery at Signalith, and the
// ones that name the agent's own files. osquery enrolls with the agent
// token (its enroll secret is the agent's token file), then fetches what
// to collect from Signalith itself.
//
// Where osquery runs depends on the system. On Windows (and macOS) the
// agent runs it, as it runs Fluent Bit. On Linux it runs as its own
// systemd service (Paths.OsqueryUnit), set up by the install script:
// osquery reads the whole computer, which the agent's own service, kept to
// reading files, may not, and Fluent Bit stays in that narrow service. A
// path unit restarts osquery's service whenever the agent changes the
// flags file, and the service runs only while the file exists; the agent
// asks systemd how it is. That service checks the file again before
// osquery starts (CheckOsqueryFlags), since anything in the agent's
// service could have written it.

// osqueryCollector is what runs osquery: a proc, or a unitProc on Linux.
type osqueryCollector interface {
	run(ctx context.Context)
	set(s *procSpec)
	setVersion(v string)
	component() agentproto.Component
}

func (p Paths) osqueryFlags() string { return filepath.Join(p.Conf, "osquery.flags") }
func (p Paths) osqueryState() string { return filepath.Join(p.State, "osquery") }

// localOsqueryFlags are the flags that name the agent's own files: the
// enroll secret is the agent token, osquery checks the server with the
// certificate authority the agent keeps (when the server hands one out),
// and its database and pid file are in the agent's state folder.
// Extensions, which load other programs into osquery, are off.
func (p Paths) localOsqueryFlags(withCA bool) []string {
	flags := []string{"--enroll_secret_path=" + p.tokenFile()}
	if withCA {
		flags = append(flags, "--tls_server_certs="+p.caFile())
	}
	return append(flags,
		"--database_path="+filepath.Join(p.osqueryState(), "osquery.db"),
		"--pidfile="+filepath.Join(p.osqueryState(), "osqueryd.pidfile"),
		"--disable_extensions=true",
		// Last, so it is the list osquery keeps whatever the server
		// sent.
		"--disable_tables="+agentproto.OsqueryDisabledTables,
	)
}

// osqueryFlagsFile is the flags file for a configuration: the server's
// flags that the agent runs, then its own. Flags it does not run are left
// out and returned.
func (p Paths) osqueryFlagsFile(cfg *agentproto.Config) (string, []string) {
	var keep, dropped []string
	for _, line := range strings.Split(cfg.Osquery.Flags, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !agentproto.OsqueryFlagAllowed(line) {
			name, _, _ := strings.Cut(line, "=")
			dropped = append(dropped, name)
			continue
		}
		keep = append(keep, line)
	}
	keep = append(keep, p.localOsqueryFlags(cfg.CA != "")...)
	return "# Written by the Signalith Agent from Signalith's configuration; it is written again when that changes.\n" +
		strings.Join(keep, "\n") + "\n", dropped
}

// wantsOsquery says whether a configuration runs osquery.
func wantsOsquery(cfg *agentproto.Config) bool {
	return cfg != nil && cfg.Osquery != nil && cfg.Osquery.Error == "" && cfg.Osquery.Flags != ""
}

// writeOsquery writes osquery's flags file for cfg, or removes it when
// cfg runs no osquery. A file that holds the same already is left alone,
// so osquery's service is not restarted for nothing.
func (a *Agent) writeOsquery(cfg *agentproto.Config) error {
	path := a.Paths.osqueryFlags()
	if !wantsOsquery(cfg) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing osquery's flags: %w", err)
		}
		return nil
	}
	text, dropped := a.Paths.osqueryFlagsFile(cfg)
	if len(dropped) > 0 {
		a.Log.Warn("left out osquery flags the agent does not run", "flags", strings.Join(dropped, " "))
	}
	if old, err := os.ReadFile(path); err == nil && string(old) == text {
		return nil
	}
	if err := os.MkdirAll(a.Paths.osqueryState(), 0o700); err != nil {
		return err
	}
	if err := writeFile(path, []byte(text), 0o600); err != nil {
		return fmt.Errorf("writing osquery's flags: %w", err)
	}
	return nil
}

// runOsquery gives osquery the configuration's spec: osqueryd with the
// flags file. The spec changes, which restarts osquery, only when the
// flags do.
func (a *Agent) runOsquery(cfg *agentproto.Config) {
	if !wantsOsquery(cfg) {
		a.osqueryRun = ""
		a.osquery.set(nil)
		return
	}
	text, _ := a.Paths.osqueryFlagsFile(cfg)
	if text == a.osqueryRun {
		return
	}
	a.osqueryRun = text
	a.osquery.set(&procSpec{Path: a.Paths.Osqueryd, Args: []string{"--flagfile=" + a.Paths.osqueryFlags()}, Env: os.Environ()})
}

// newOsquery makes what runs osquery on this system.
func (a *Agent) newOsquery() osqueryCollector {
	if a.Paths.OsqueryUnit != "" {
		u := newUnitProc("osquery", a.Paths.OsqueryUnit, a.Log, a.now, a.reportSoon)
		if a.UnitState != nil {
			u.show = a.UnitState
		}
		return u
	}
	p := newProc("osquery", a.Log, a.now, a.reportSoon)
	if a.Out != nil {
		p.out = a.Out
	}
	return p
}

// UnitState is what systemd says about a service: its ActiveState,
// SubState, LoadState and NRestarts properties.
type UnitState func(ctx context.Context, unit string) (map[string]string, error)

// systemctlShow asks systemctl for a service's state.
func systemctlShow(ctx context.Context, unit string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,NRestarts").Output()
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m, nil
}

// unitPoll is how often the agent asks systemd about osquery's service.
var unitPoll = 10 * time.Second

// unitProc is a collector that runs as its own systemd service: the agent
// only watches it. It is wanted while its spec is set.
type unitProc struct {
	name, unit string
	log        *slog.Logger
	now        func() time.Time
	changed    func()
	show       UnitState

	mu       sync.Mutex
	want     bool
	wanted   time.Time
	kick     chan struct{}
	state    string
	since    time.Time
	err      string
	version  string
	base     int
	restarts int
	seen     bool
}

func newUnitProc(name, unit string, log *slog.Logger, now func() time.Time, changed func()) *unitProc {
	return &unitProc{name: name, unit: unit, log: log, now: now, changed: changed, show: systemctlShow,
		kick: make(chan struct{}, 1), state: agentproto.StateOff, since: now()}
}

func (u *unitProc) set(s *procSpec) {
	u.mu.Lock()
	want := s != nil
	if want && !u.want {
		u.wanted = u.now()
	}
	u.want = want
	u.mu.Unlock()
	select {
	case u.kick <- struct{}{}:
	default:
	}
}

func (u *unitProc) setVersion(v string) {
	u.mu.Lock()
	u.version = v
	u.mu.Unlock()
}

func (u *unitProc) component() agentproto.Component {
	u.mu.Lock()
	defer u.mu.Unlock()
	return agentproto.Component{Name: u.name, Version: u.version, State: u.state, Restarts: u.restarts,
		Since: u.since.UTC().Format(time.RFC3339), Error: u.err}
}

func (u *unitProc) setState(state, err string) {
	u.mu.Lock()
	if u.state == state && u.err == err {
		u.mu.Unlock()
		return
	}
	u.state, u.err, u.since = state, err, u.now()
	u.mu.Unlock()
	if u.changed != nil {
		u.changed()
	}
}

func (u *unitProc) run(ctx context.Context) {
	for {
		u.check(ctx)
		t := time.NewTimer(unitPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-u.kick:
			t.Stop()
			// The path unit restarts the service a moment after the flags
			// change.
			select {
			case <-ctx.Done():
				return
			case <-time.After(reportDelay):
			}
		case <-t.C:
		}
	}
}

// startGrace is how long a service that is wanted may take to start
// before it counts as failed.
var startGrace = 30 * time.Second

// check asks systemd how the service is.
func (u *unitProc) check(ctx context.Context) {
	u.mu.Lock()
	want, wanted := u.want, u.wanted
	u.mu.Unlock()
	if !want {
		u.setState(agentproto.StateOff, "")
		return
	}
	logs := "sudo journalctl -u " + u.unit + " -n 50 says why"
	m, err := u.show(ctx, u.unit)
	if err != nil {
		u.setState(agentproto.StateFailed, "could not ask systemd about "+u.unit+": "+err.Error())
		return
	}
	if m["LoadState"] == "not-found" {
		u.setState(agentproto.StateMissing, u.unit+" is not installed; run the line from Add data > Signalith Agent again")
		return
	}
	if n, err := strconv.Atoi(m["NRestarts"]); err == nil {
		u.mu.Lock()
		// systemd counts from the service's start; the agent counts from
		// its own.
		if !u.seen {
			u.base, u.seen = n, true
		}
		if n >= u.base {
			u.restarts = n - u.base
		}
		u.mu.Unlock()
	}
	active, sub := m["ActiveState"], m["SubState"]
	switch {
	case active == "active":
		u.setState(agentproto.StateRunning, "")
	case active == "activating" && sub == "auto-restart":
		u.setState(agentproto.StateFailed, "it stopped, and systemd starts it again; "+logs)
	case active == "activating" || active == "reloading":
		u.setState(agentproto.StateStarting, "")
	case active == "failed":
		u.setState(agentproto.StateFailed, "its service failed; "+logs)
	case u.now().Sub(wanted) < startGrace:
		u.setState(agentproto.StateStarting, "")
	default:
		u.setState(agentproto.StateFailed, "its service "+u.unit+" is "+active+"; "+logs)
	}
}

// CheckOsqueryFlags checks an osquery flags file as osquery's own
// service starts, outside the agent's sandbox (signalith-agent
// osquery-flags, in ExecStartPre), and returns the checked copy that
// osquery runs with. Anything in the agent's service can write the file,
// Fluent Bit included, so the agent's own check is not enough: each line
// must be a flag a server may give (agentproto.OsqueryFlagAllowed) or
// one of the agent's own, with the very value the agent writes.
func CheckOsqueryFlags(p Paths, text string) (string, error) {
	own := map[string]bool{}
	for _, f := range p.localOsqueryFlags(true) {
		own[f] = true
	}
	var keep []string
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !own[line] && !agentproto.OsqueryFlagAllowed(line) {
			name, _, _ := strings.Cut(line, "=")
			return "", fmt.Errorf("line %d of osquery's flags (%.60q) is not a flag the agent writes, so osquery was not started", i+1, name)
		}
		keep = append(keep, line)
	}
	if !containsLine(keep, "--disable_extensions=true") {
		return "", errors.New("osquery's flags do not turn extensions off, so osquery was not started")
	}
	return strings.Join(keep, "\n") + "\n", nil
}

func containsLine(lines []string, s string) bool {
	for _, l := range lines {
		if l == s {
			return true
		}
	}
	return false
}
