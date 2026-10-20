// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package agentd is the Signalith Agent: it fetches what to collect from
// Signalith, writes the collectors' configuration, keeps them running and
// reports how they are (see internal/agentproto for what it says to the
// server). cmd/signalith-agent runs it as a service.
//
// The agent keeps working when Signalith cannot be reached: it runs the
// configuration it last had (kept in its state folder), and asks again
// with a growing pause. A configuration it cannot write is not applied;
// the one before keeps running.
package agentd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

// Agent is one run of the agent.
type Agent struct {
	Paths    Paths
	Settings Settings
	// Version is the agent's own version.
	Version string
	Log     *slog.Logger
	// Out gets what the collectors write, each line marked with the
	// collector's name; nil is the standard error.
	Out io.Writer
	// Name is the computer's name, sent to the server and to Fluent Bit
	// (HOSTNAME); empty is os.Hostname.
	Name string
	// Client talks to the server; nil makes one that trusts ca.pem (or
	// the system's authorities when there is none).
	Client *http.Client
	// Facts says what the computer runs; nil looks (see facts).
	Facts func() facts
	// UnitState asks systemd about osquery's service (Paths.OsqueryUnit);
	// nil runs systemctl.
	UnitState UnitState
	now       func() time.Time

	fluentBit *proc
	osquery   osqueryCollector
	// osqueryRun is the flags osquery runs with, "" when it runs none.
	osqueryRun string
	started    time.Time
	// refusals counts the server's refusals of the token in a row, and
	// idle is whether the collectors are stopped for them.
	refusals int
	idle     bool

	// updateTried is when the agent last tried to get each version ready.
	updateTried map[string]time.Time
	// runUpdater starts the updater; nil is startUpdater. Tests replace it.
	runUpdater func() error

	mu        sync.Mutex
	update    *agentproto.Component
	cfg       *agentproto.Config
	configErr string
	reported  bool
	report    chan struct{}
}

// maxConfigBytes caps the configuration the agent reads.
const maxConfigBytes = 4 << 20

// refusedStop is how many refusals of the token in a row stop the
// collectors: Fluent Bit would otherwise read and drop every event, since
// it does not send again a batch Signalith refused. Stopped, they keep
// their place in each log and carry on from it once the token is
// accepted again.
const refusedStop = 3

// errTokenRefused is a server's answer that it revoked or does not know
// the agent's token.
var errTokenRefused = errors.New("Signalith refused this computer's token")

// retry is the shortest pause before asking the server again after a
// failure; it doubles up to the poll interval.
var retry = 30 * time.Second

// Run runs the agent until ctx is done.
func (a *Agent) Run(ctx context.Context) error {
	if a.now == nil {
		a.now = time.Now
	}
	if a.Log == nil {
		a.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if a.Name == "" {
		n, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("the computer's name: %w", err)
		}
		a.Name = n
	}
	if a.Facts == nil {
		a.Facts = func() facts {
			f := lookFacts(a.Paths)
			f.Osquery = f.Osquery && a.Settings.Osquery
			return f
		}
	}
	if a.Client == nil {
		c, err := a.newClient()
		if err != nil {
			return err
		}
		a.Client = c
	}
	a.started = a.now()
	a.report = make(chan struct{}, 1)
	if err := os.MkdirAll(filepath.Join(a.Paths.State, "fluent-bit"), 0o700); err != nil {
		return err
	}
	a.fluentBit = newProc("fluentbit", a.Log, a.now, a.reportSoon)
	if a.Out != nil {
		a.fluentBit.out = a.Out
	}
	a.osquery = a.newOsquery()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		a.fluentBit.run(ctx)
	}()
	go func() {
		defer wg.Done()
		a.osquery.run(ctx)
	}()
	// The configuration it last had runs while the server is asked.
	if cfg, err := a.loadConfig(); err == nil {
		a.mu.Lock()
		a.cfg = cfg
		a.mu.Unlock()
		if err := a.writeOsquery(cfg); err != nil {
			a.Log.Warn("osquery's flags", "err", err)
		}
		a.runFluentBit(cfg)
		a.runOsquery(cfg)
	}
	if a.Paths.FluentBit != "" {
		a.fluentBit.setVersion(programVersion(a.Paths.FluentBit))
	}
	if a.Paths.Osqueryd != "" && exists(a.Paths.Osqueryd) {
		a.osquery.setVersion(programVersion(a.Paths.Osqueryd))
	}
	poll := time.Duration(agentPoll(nil)) * time.Second
	wait := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-time.After(wait):
		}
		if err := a.sync(ctx); err != nil {
			// Only a refusal counts; any other failure (the server is
			// down, a timeout) leaves the count and the collectors as
			// they are, so a revoked token that also meets outages
			// still stops them.
			if errors.Is(err, errTokenRefused) {
				a.refused(true)
			}
			if a.idle {
				a.Log.Warn("Signalith refuses this computer's token; the collectors stay stopped until it is accepted", "err", err)
				a.setConfigErr(err.Error() + "; collectors stopped until it is accepted")
			} else {
				a.Log.Warn("could not get the configuration; the one in use keeps running", "err", err)
				a.setConfigErr(err.Error())
			}
			if wait < retry {
				wait = retry
			} else {
				wait = min(wait*2, poll)
			}
		} else {
			a.refused(false)
			a.setConfigErr("")
			a.mu.Lock()
			poll = time.Duration(agentPoll(a.cfg)) * time.Second
			a.mu.Unlock()
			wait = poll
			a.checkUpdate(ctx)
		}
		a.sendStatus(ctx)
		// Report again soon after a collector changes state, between
		// polls.
		deadline := time.After(wait)
		for waiting := true; waiting; {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil
			case <-a.report:
				time.Sleep(reportDelay)
				a.sendStatus(ctx)
			case <-deadline:
				waiting = false
			}
		}
		wait = 0
	}
}

// reportDelay lets a collector's state settle before it is reported.
var reportDelay = 2 * time.Second

// agentPoll is the configuration's poll interval, in seconds, within
// sane limits.
func agentPoll(c *agentproto.Config) int {
	if c == nil || c.PollSeconds <= 0 {
		return 300
	}
	return max(30, min(c.PollSeconds, 3600))
}

func (a *Agent) reportSoon() {
	select {
	case a.report <- struct{}{}:
	default:
	}
}

// refused counts a refusal of the token, or (no) an accepted answer, and
// stops or starts the collectors to match.
func (a *Agent) refused(yes bool) {
	if !yes {
		a.refusals = 0
		if a.idle {
			a.idle = false
			a.Log.Info("Signalith accepts this computer's token again; the collectors start")
			a.mu.Lock()
			cfg := a.cfg
			a.mu.Unlock()
			if cfg != nil {
				if err := a.writeOsquery(cfg); err != nil {
					a.Log.Warn("osquery's flags", "err", err)
				}
				a.osqueryRun = ""
				a.runFluentBit(cfg)
				a.runOsquery(cfg)
			}
		}
		return
	}
	a.refusals++
	if a.refusals >= refusedStop && !a.idle {
		a.idle = true
		a.fluentBit.set(nil)
		// On Linux osquery is a service of its own, which runs only
		// while its flags file is there.
		if err := os.Remove(a.Paths.osqueryFlags()); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.Log.Warn("removing osquery's flags", "err", err)
		}
		a.osqueryRun = ""
		a.osquery.set(nil)
	}
}

func (a *Agent) setConfigErr(e string) {
	a.mu.Lock()
	a.configErr = e
	a.mu.Unlock()
}

// newClient makes the client that talks to the server: it checks the
// server's certificate against ca.pem when there is one, else against the
// computer's trusted authorities.
func (a *Agent) newClient() (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if b, err := os.ReadFile(a.Paths.caFile()); err == nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("%s holds no certificate", a.Paths.caFile())
		}
		tc.RootCAs = pool
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tc
	tr.Proxy = http.ProxyFromEnvironment
	return &http.Client{Transport: tr, Timeout: time.Minute}, nil
}

// request makes a request to the server with the agent's headers.
func (a *Agent) request(ctx context.Context, method, path string, q url.Values, body []byte) (*http.Request, error) {
	u := strings.TrimSuffix(a.Settings.Server, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.Settings.Token)
	req.Header.Set(agentproto.HeaderName, a.Name)
	req.Header.Set(agentproto.HeaderVersion, a.Version)
	req.Header.Set("User-Agent", "signalith-agent/"+a.Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// serverError is the error of a refused request, with the server's own
// message when it gave one.
func serverError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		return fmt.Errorf("Signalith answered %d: %s", resp.StatusCode, e.Error)
	}
	return fmt.Errorf("Signalith answered %d", resp.StatusCode)
}

// sync fetches the configuration and applies it when it changed.
func (a *Agent) sync(ctx context.Context) error {
	f := a.Facts()
	q := url.Values{"os": {runtime.GOOS}, "arch": {runtime.GOARCH}, "server": {a.Settings.Server}}
	if f.Source != "" {
		q.Set("source", f.Source)
	}
	if f.Sysmon {
		q.Set("sysmon", "true")
	}
	if f.Osquery {
		q.Set("osquery", "true")
	}
	req, err := a.request(ctx, http.MethodGet, agentproto.RouteConfig, q, nil)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.cfg != nil && a.cfg.Revision != "" {
		req.Header.Set("If-None-Match", `"`+a.cfg.Revision+`"`)
	}
	a.mu.Unlock()
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil
	case http.StatusOK:
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %w", errTokenRefused, serverError(resp))
	default:
		return serverError(resp)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxConfigBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxConfigBytes {
		return errors.New("the configuration is larger than the agent reads")
	}
	var cfg agentproto.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("the configuration is not valid JSON: %w", err)
	}
	return a.apply(&cfg, resp.TLS)
}

// apply puts a new configuration in place: the certificate authority, then
// Fluent Bit's configuration and osquery's flags, then the configuration
// itself, and restarts Fluent Bit (and osquery, when its flags changed)
// with it.
func (a *Agent) apply(cfg *agentproto.Config, conn *tls.ConnectionState) error {
	a.mu.Lock()
	same := a.cfg != nil && a.cfg.Revision == cfg.Revision && cfg.Revision != ""
	a.mu.Unlock()
	if same {
		return nil
	}
	if cfg.CA != "" {
		if err := a.writeCA(cfg.CA, conn); err != nil {
			return err
		}
	}
	if cfg.FluentBit != nil {
		if err := writeFile(a.Paths.fluentBitConf(), []byte(cfg.FluentBit.Config), 0o600); err != nil {
			return fmt.Errorf("writing Fluent Bit's configuration: %w", err)
		}
	}
	if err := a.writeOsquery(cfg); err != nil {
		return err
	}
	b, _ := json.Marshal(cfg)
	if err := writeFile(a.Paths.configFile(), b, 0o600); err != nil {
		return fmt.Errorf("keeping the configuration: %w", err)
	}
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	a.Log.Info("applied a new configuration", "revision", cfg.Revision)
	if !a.idle {
		// Stopped for refusals, the collectors start with it once
		// the answer is counted (see refused).
		a.runFluentBit(cfg)
		a.runOsquery(cfg)
	}
	return nil
}

// writeCA keeps the certificate authorities the server hands out, which
// change when Signalith switches to a new one. A set that would not
// trust the server the agent is talking to now is refused: the agent
// could not reach the server again.
func (a *Agent) writeCA(ca string, conn *tls.ConnectionState) error {
	pool := x509.NewCertPool()
	rest := []byte(ca)
	n := 0
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return fmt.Errorf("the certificate authority the server handed out is not valid: %w", err)
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 {
		return errors.New("the certificate authority the server handed out holds no certificate")
	}
	if conn != nil && len(conn.PeerCertificates) > 0 {
		inter := x509.NewCertPool()
		for _, c := range conn.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, err := conn.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter}); err != nil {
			return fmt.Errorf("the certificate authority the server handed out does not vouch for the server's own certificate, so it was not kept: %w", err)
		}
	}
	old, _ := os.ReadFile(a.Paths.caFile())
	if bytes.Equal(old, []byte(ca)) {
		return nil
	}
	if err := writeFile(a.Paths.caFile(), []byte(ca), 0o644); err != nil {
		return fmt.Errorf("writing the certificate authority: %w", err)
	}
	// The next connections trust the new set.
	if tr, ok := a.Client.Transport.(*http.Transport); ok {
		tc := tr.TLSClientConfig.Clone()
		tc.RootCAs = pool
		tr.TLSClientConfig = tc
		tr.CloseIdleConnections()
	}
	return nil
}

// loadConfig reads the configuration the agent last applied.
func (a *Agent) loadConfig() (*agentproto.Config, error) {
	b, err := os.ReadFile(a.Paths.configFile())
	if err != nil {
		return nil, err
	}
	var cfg agentproto.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// runFluentBit gives Fluent Bit the configuration's spec: the agent token
// and the computer's name in its environment, which its configuration
// reads.
func (a *Agent) runFluentBit(cfg *agentproto.Config) {
	if cfg.FluentBit == nil {
		a.fluentBit.set(nil)
		return
	}
	env := []string{"SIGNALITH_TOKEN=" + a.Settings.Token, "HOSTNAME=" + a.Name}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.EqualFold(k, "SIGNALITH_TOKEN") || strings.EqualFold(k, "HOSTNAME") {
			continue
		}
		env = append(env, kv)
	}
	a.fluentBit.set(&procSpec{Path: a.Paths.FluentBit, Args: []string{"-c", a.Paths.fluentBitConf()}, Env: env})
}

var versionText = regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+)`)

// programVersion asks a collector (Fluent Bit, osqueryd) its version; ""
// when it cannot tell.
func programVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	setProcAttr(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	if m := versionText.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

// Status is what the agent reports now.
func (a *Agent) Status() agentproto.Status {
	a.mu.Lock()
	rev, cerr := "", a.configErr
	if a.cfg != nil {
		rev = a.cfg.Revision
	}
	oq := a.osqueryComponent()
	up := a.update
	a.mu.Unlock()
	var comps []agentproto.Component
	if a.Paths.FluentBit != "" {
		comps = append(comps, a.fluentBit.component())
	}
	if oq != nil {
		comps = append(comps, *oq)
	}
	if up != nil {
		comps = append(comps, *up)
	}
	return agentproto.Status{
		Version: a.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, System: systemName(),
		Revision: rev, Started: a.started.UTC().Format(time.RFC3339), ConfigError: cerr,
		Components: comps,
	}
}

// osqueryComponent is osquery as the agent reports it, nil when the
// configuration has no osquery part (the computer has no osquery). When
// the server says osquery cannot use it, osquery is off with that reason.
// a.mu is held.
func (a *Agent) osqueryComponent() *agentproto.Component {
	if a.cfg == nil || a.cfg.Osquery == nil || a.osquery == nil {
		return nil
	}
	c := a.osquery.component()
	if e := a.cfg.Osquery.Error; e != "" {
		c.State, c.Error = agentproto.StateOff, e
	}
	return &c
}

// sendStatus reports the status to the server, and writes it and the
// health file for the install script and signalith-agent status.
func (a *Agent) sendStatus(ctx context.Context) {
	st := a.Status()
	b, _ := json.Marshal(st)
	ok := false
	if req, err := a.request(ctx, http.MethodPost, agentproto.RouteStatus, nil, b); err == nil {
		if resp, err := a.Client.Do(req); err != nil {
			a.Log.Warn("could not report the status", "err", err)
		} else {
			if resp.StatusCode/100 == 2 {
				ok = true
			} else {
				a.Log.Warn("Signalith refused the status", "err", serverError(resp))
			}
			resp.Body.Close()
		}
	}
	a.mu.Lock()
	a.reported = ok
	a.mu.Unlock()
	cfg := "ok"
	if st.ConfigError != "" {
		cfg = oneLine(st.ConfigError)
	} else if st.Revision == "" {
		cfg = "none yet"
	}
	rep := "no"
	if ok {
		rep = "yes"
	}
	health := "config=" + cfg + "\n"
	for _, c := range st.Components {
		line := c.State
		if c.Error != "" {
			line += ": " + oneLine(c.Error)
		}
		health += c.Name + "=" + line + "\n"
	}
	health += "reported=" + rep + "\n"
	// The health file first: the updater takes a new status.json as
	// this run's, then reads the health file for whether it reached
	// Signalith (see Updater.reported).
	if err := writeFile(a.Paths.HealthFile(), []byte(health), 0o644); err != nil {
		// Without this run's health file, a new status.json would
		// vouch for the one before it.
		a.Log.Warn("could not write the health file", "err", err)
		return
	}
	_ = writeFile(a.Paths.StatusFile(), b, 0o600)
}

// oneLine keeps the first line of s.
func oneLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}
