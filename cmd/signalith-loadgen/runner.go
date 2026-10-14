package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// runOptions are the command line's choices for one run.
type runOptions struct {
	// RunID tags every event, account and case the run makes.
	RunID string
	// Keep leaves the accounts and the case made for the run.
	Keep bool
	Log  io.Writer
}

// runner runs one scenario.
type runner struct {
	s    *Scenario
	opts runOptions
	run  string
	tls  *tls.Config
	tr   *http.Transport
	m    *Metrics
	// admin is one admin session per target, when the scenario names
	// admin credentials.
	admin   []*Session
	cluster bool
	servers []string
	os      *osReader
	report  *Report
	// users are the accounts the browsers sign in as; bruteAccounts are
	// the accounts attacked; made are the accounts this run created.
	users         [][2]string
	bruteAccounts []string
	made          []string
	caseID        string
	fleet         *Fleet
	phaseSecs     map[string]float64
	opsPerSecond  map[string]float64
}

func newRunID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (r *runner) logf(f string, a ...any) {
	if r.opts.Log != nil {
		fmt.Fprintf(r.opts.Log, "%s  %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(f, a...))
	}
}

// runScenario runs s and reports. An error means the run could not be
// made (bad credentials, no server), not that a criterion failed.
func runScenario(ctx context.Context, s *Scenario, opts runOptions) (*Report, error) {
	if opts.RunID == "" {
		opts.RunID = newRunID()
	}
	r := &runner{s: s, opts: opts, run: opts.RunID, m: newMetrics(), phaseSecs: map[string]float64{}, opsPerSecond: map[string]float64{}}
	r.report = &Report{Run: r.run, Scenario: s.Name, Started: time.Now().UTC(), Targets: s.Targets}
	defer func() { r.report.Ended = time.Now().UTC() }()
	if len(s.Targets) == 0 {
		return nil, errors.New("no targets: name them in the scenario or with -target")
	}
	for i, t := range s.Targets {
		s.Targets[i] = strings.TrimRight(t, "/")
		if u, err := url.Parse(s.Targets[i]); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("target %q is not an http(s) address", t)
		}
	}
	var err error
	if r.tls, err = tlsConfig(s.caFiles()); err != nil {
		return nil, err
	}
	r.tr = newTransport(r.tls, nil)
	r.tr.MaxIdleConnsPerHost = 1024
	if s.Credentials.AdminFile != "" {
		user, pass, err := readLogin(s.Credentials.AdminFile)
		if err != nil {
			return nil, fmt.Errorf("admin file: %w", err)
		}
		for _, t := range s.Targets {
			r.admin = append(r.admin, newSession(t, r.tr, user, pass))
		}
		if err := r.admin[0].SignIn(ctx); err != nil {
			return nil, fmt.Errorf("signing in as %s to %s: %w", user, s.Targets[0], err)
		}
	}
	if skip := r.checkNeeds(ctx); skip != "" {
		r.report.Skipped = skip
		r.report.finish()
		return r.report, nil
	}
	r.detectCluster(ctx)
	for _, n := range s.Needs {
		if n == "cluster" && !r.cluster {
			r.report.Skipped = "needs a cluster; the targets are one server"
			r.report.finish()
			return r.report, nil
		}
	}
	if s.OpenSearch.URL != "" {
		if r.os, err = newOSReader(s.OpenSearch); err != nil {
			return nil, err
		}
	}
	defer r.cleanup()
	if err := r.prepare(ctx); err != nil {
		return nil, err
	}
	r.phases(ctx)
	r.evaluate()
	r.report.finish()
	return r.report, nil
}

// needSettings are features a scenario may need, by the setting that
// shows a server has them.
var needSettings = map[string]string{
	"proxy_protocol":  "server.proxy_protocol",
	"opensearch_urls": "opensearch.urls",
}

// checkNeeds says why the scenario cannot run on these servers, or "".
func (r *runner) checkNeeds(ctx context.Context) string {
	for _, need := range r.s.Needs {
		if need == "cluster" {
			continue // checked once the cluster is known
		}
		key, ok := needSettings[need]
		if !ok {
			return fmt.Sprintf("needs %s, which this load generator cannot check for yet", need)
		}
		if len(r.admin) == 0 {
			return fmt.Sprintf("needs %s; checking for it takes credentials.admin_file", need)
		}
		var v settingsView
		if err := r.admin[0].Do(ctx, http.MethodGet, "/api/settings", nil, &v); err != nil {
			return fmt.Sprintf("needs %s; could not read the settings: %v", need, err)
		}
		if _, _, ok := v.field(key); !ok {
			return fmt.Sprintf("needs %s, which this server does not have (no %s setting)", need, key)
		}
	}
	return ""
}

// detectCluster asks the first target which servers share its
// OpenSearch.
func (r *runner) detectCluster(ctx context.Context) {
	if len(r.admin) == 0 {
		r.report.Notes = append(r.report.Notes, "no admin credentials, so the servers were not listed and cluster checks are skipped")
		return
	}
	v, ok := r.anyView(ctx)
	if !ok {
		r.report.Notes = append(r.report.Notes, "GET /api/cluster did not answer, so this is treated as one server")
		return
	}
	r.servers = v.live()
	r.cluster = len(r.servers) > 1
	r.report.Cluster, r.report.Servers = r.cluster, r.servers
	r.logf("%d server(s) ready: %s", len(r.servers), strings.Join(r.servers, ", "))
}

// prepare makes the accounts, the case and the seed data the phases use.
func (r *runner) prepare(ctx context.Context) error {
	s := r.s
	nUsers, nBrute, triage, needToken := 0, 0, false, false
	createUsers := false
	for _, p := range s.Phases {
		if u := p.Users; u != nil {
			nUsers = max(nUsers, u.N)
			triage = triage || u.Triage
			createUsers = createUsers || u.Create
		}
		if b := p.Brute; b != nil {
			nBrute = max(nBrute, b.Accounts)
		}
		if p.Agents != nil && p.Agents.N > 0 {
			needToken = true
		}
		if p.Churn != nil && len(r.admin) == 0 {
			return errors.New("churn needs credentials.admin_file")
		}
	}
	if (createUsers || nBrute > 0 || triage || len(s.Seed) > 0) && len(r.admin) == 0 {
		return errors.New("making accounts, cases or seed data needs credentials.admin_file")
	}
	if nUsers > 0 {
		if createUsers {
			for i := range nUsers {
				name := fmt.Sprintf("lg-%s-u%02d", r.run, i+1)
				pw := randomPassword()
				if err := r.makeUser(ctx, name, pw, "analyst"); err != nil {
					return err
				}
				r.users = append(r.users, [2]string{name, pw})
			}
		} else if s.Credentials.UsersFile != "" {
			users, err := readUsers(s.Credentials.UsersFile)
			if err != nil {
				return fmt.Errorf("users file: %w", err)
			}
			r.users = users
		} else {
			return errors.New("users need credentials.users_file, or create: true")
		}
	}
	for i := range nBrute {
		name := fmt.Sprintf("lg-%s-b%02d", r.run, i+1)
		if err := r.makeUser(ctx, name, randomPassword(), "viewer"); err != nil {
			return err
		}
		r.bruteAccounts = append(r.bruteAccounts, name)
	}
	if triage {
		var resp struct {
			Case struct {
				ID string `json:"id"`
			} `json:"case"`
		}
		err := r.admin[0].Do(ctx, http.MethodPost, "/api/cases", map[string]string{"title": caseTitle(r.run),
			"description": "Made by signalith-loadgen; simulated analysts add notes to it."}, &resp)
		if err != nil {
			return fmt.Errorf("making the shared case: %w", err)
		}
		r.caseID = resp.Case.ID
	}
	for _, st := range s.Seed {
		if err := r.seed(ctx, st); err != nil {
			return err
		}
	}
	if needToken {
		token, err := readSecret(s.Credentials.TokenFile)
		if err != nil {
			return fmt.Errorf("agents need an agent token in credentials.token_file: %w", err)
		}
		r.fleet = newFleet(r.run, token, s.Targets, &http.Client{Transport: r.tr}, r.m)
	}
	return nil
}

func caseTitle(run string) string { return "loadgen " + run }

func (r *runner) makeUser(ctx context.Context, name, password, role string) error {
	no := false
	err := r.admin[0].Do(ctx, http.MethodPost, "/api/users", map[string]any{"username": name, "password": password,
		"role": role, "name": "Load test " + name, "must_change_password": &no}, nil)
	if err != nil {
		return fmt.Errorf("making account %s: %w", name, err)
	}
	r.made = append(r.made, name)
	return nil
}

// seed runs one seed step, timing it; S5 records how long the servers
// take with a large configuration.
func (r *runner) seed(ctx context.Context, st SeedStep) error {
	count := max(st.Count, 1)
	start := time.Now()
	failed := 0
	for i := 1; i <= count; i++ {
		fill := func(s string) string {
			return strings.NewReplacer("{i}", strconv.Itoa(i), "{run}", r.run).Replace(s)
		}
		var body any
		if st.Body != "" {
			body = rawJSON(fill(st.Body))
		}
		if err := r.admin[0].Do(ctx, st.Method, fill(st.Path), body, nil); err != nil {
			failed++
			if failed == 1 {
				r.report.Notes = append(r.report.Notes, fmt.Sprintf("seed %s: %v", st.Name, err))
			}
		}
	}
	r.m.Set("seed", "seed_"+st.Name+"_seconds", time.Since(start).Seconds())
	if failed == count {
		return fmt.Errorf("seed %s: every request failed", st.Name)
	}
	return nil
}

// rawJSON is a JSON body passed through as written.
type rawJSON string

func (j rawJSON) MarshalJSON() ([]byte, error) { return []byte(j), nil }

// phases runs the phases in order, with the faults on their own timeline.
func (r *runner) phases(ctx context.Context) {
	if r.report.Skipped != "" {
		return
	}
	start := time.Now()
	bg, stopBG := context.WithCancel(ctx)
	var bgWG sync.WaitGroup
	if r.cluster && len(r.admin) > 1 {
		bgWG.Add(1)
		go func() { defer bgWG.Done(); r.sampleLeaders(bg) }()
	}
	var faults []FaultResult
	var faultWG sync.WaitGroup
	if len(r.s.Faults) > 0 {
		faultWG.Add(1)
		go func() { defer faultWG.Done(); faults = r.faults(ctx, start) }()
	}
	for _, p := range r.s.Phases {
		if ctx.Err() != nil {
			break
		}
		r.phase(ctx, p)
	}
	if r.fleet != nil {
		r.m.SetPhase("drain")
		drain := r.s.Drain.D()
		if drain <= 0 {
			drain = 2 * time.Minute
		}
		r.logf("waiting up to %s for agents to send what they hold", drain)
		timer := time.AfterFunc(drain, r.fleet.StopRetrying)
		stop := context.AfterFunc(ctx, r.fleet.StopRetrying)
		started := time.Now()
		r.fleet.Close()
		r.phaseSecs["drain"] = time.Since(started).Seconds()
		timer.Stop()
		stop()
	}
	faultWG.Wait()
	stopBG()
	bgWG.Wait()
	r.report.Faults = faults
	if r.fleet != nil && r.os != nil && r.fleet.sent.Load() > 0 {
		settle := r.s.Settle.D()
		if settle <= 0 {
			settle = time.Minute
		}
		r.logf("verifying stored events in OpenSearch")
		vctx, cancel := context.WithTimeout(context.Background(), settle+5*time.Minute)
		v, err := verify(vctx, r.os, r.run, r.fleet.Acked(), settle)
		cancel()
		if err != nil {
			r.report.Notes = append(r.report.Notes, "verify: "+err.Error())
		} else {
			r.report.Verify = &v
		}
	}
	for _, name := range r.m.order {
		counts, lat, values := r.m.phaseView(name)
		r.report.Phases = append(r.report.Phases, PhaseReport{Name: name, Seconds: math.Round(r.phaseSecs[name]),
			Counts: counts, Latencies: lat, Values: values})
	}
}

// phase runs one phase's load until its time is up.
func (r *runner) phase(ctx context.Context, p Phase) {
	r.m.SetPhase(p.Name)
	r.logf("phase %s for %s", p.Name, p.For.D())
	pctx, cancel := context.WithTimeout(ctx, p.For.D())
	defer cancel()
	opsStart, opsErr := int64(0), error(nil)
	if r.os != nil {
		opsStart, opsErr = r.os.opsTotal(ctx)
	}
	start := time.Now()
	var wg sync.WaitGroup
	gen := func(f func(ctx context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(pctx) }()
	}
	if a := p.Agents; a != nil && r.fleet != nil {
		gen(func(ctx context.Context) { r.fleet.Run(ctx, *a) })
	}
	if sl := p.Syslog; sl != nil {
		var targets []string
		switch sl.Proto {
		case "udp":
			targets = r.s.SyslogTargets.UDP
		case "tcp":
			targets = r.s.SyslogTargets.TCP
		case "tls":
			targets = r.s.SyslogTargets.TLS
		}
		d := &SyslogDevices{run: r.run, load: *sl, targets: targets, tls: r.tls, m: r.m}
		gen(d.Run)
	}
	if u := p.Users; u != nil {
		b := &Browsers{run: r.run, load: *u, targets: r.s.Targets, tr: r.tr, users: r.users, caseID: r.caseID, m: r.m}
		gen(b.Run)
	}
	if b := p.Brute; b != nil {
		br := &Brute{load: *b, targets: r.s.Targets, accounts: r.bruteAccounts, m: r.m,
			tls: func(dial func(ctx context.Context, network, addr string) (net.Conn, error)) http.RoundTripper {
				t := newTransport(r.tls, dial)
				t.DisableKeepAlives = true
				return t
			}}
		gen(br.Run)
	}
	if c := p.Churn; c != nil {
		ch := &Churn{load: *c, sessions: r.admin, m: r.m}
		gen(ch.Run)
	}
	if c := p.CookieFlood; c != nil {
		cf := &CookieFlooder{rate: c.Rate, targets: r.s.Targets, tr: r.tr, m: r.m}
		gen(cf.Run)
	}
	<-pctx.Done()
	wg.Wait()
	secs := time.Since(start).Seconds()
	r.phaseSecs[p.Name] = secs
	if r.os != nil && opsErr == nil {
		if end, err := r.os.opsTotal(context.Background()); err == nil && secs > 0 {
			ops := float64(end-opsStart) / secs
			r.opsPerSecond[p.Name] = ops
			r.m.Set(p.Name, "os_ops_per_second", ops)
			r.m.Set(p.Name, "os_ops_per_server_per_second", ops/float64(max(len(r.servers), 1)))
		}
	} else if opsErr != nil {
		r.report.Notes = append(r.report.Notes, "OpenSearch operation counts: "+opsErr.Error())
	}
}

// cleanup removes the accounts made for the run and closes its case,
// unless asked to keep them.
func (r *runner) cleanup() {
	if r.opts.Keep || len(r.admin) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, u := range r.made {
		if err := r.admin[0].Do(ctx, http.MethodDelete, "/api/users/"+url.PathEscape(u), nil, nil); err != nil {
			r.report.Notes = append(r.report.Notes, fmt.Sprintf("could not remove account %s: %v", u, err))
		}
	}
	if r.caseID != "" {
		closed := "closed"
		_ = r.admin[0].Do(ctx, http.MethodPatch, "/api/cases/"+url.PathEscape(r.caseID), map[string]any{"status": &closed}, nil)
	}
}

// evaluate measures every criterion.
func (r *runner) evaluate() {
	if r.report.Skipped != "" {
		return
	}
	for _, c := range r.s.Criteria {
		v, skip := r.measure(c)
		r.report.Criteria = append(r.report.Criteria, judge(c, v, skip))
	}
}

func (r *runner) measure(c Criterion) (float64, string) {
	m, ph := r.m, c.Phase
	if clusterOnly[c.Name] && !r.cluster {
		return 0, "not a cluster"
	}
	latency := func(name string, q float64) (float64, string) {
		h := m.Hist(ph, name)
		if h.Count() == 0 {
			return 0, "nothing measured"
		}
		return ms(h.Quantile(q)), ""
	}
	switch c.Name {
	case "events_lost", "events_duplicated":
		switch {
		case r.fleet == nil:
			return 0, "no agents in the scenario"
		case r.os == nil:
			return 0, "not verified: the scenario names no OpenSearch"
		case r.report.Verify == nil:
			return 0, "not verified: OpenSearch could not be read"
		}
		if c.Name == "events_lost" {
			return float64(r.report.Verify.Lost), ""
		}
		return float64(r.report.Verify.Duplicated), ""
	case "events_undelivered":
		if r.fleet == nil {
			return 0, "no agents in the scenario"
		}
		return float64(r.fleet.undelivered.Load()), ""
	case "ingest_error_rate":
		n := m.Count(ph, "ingest_requests")
		if n == 0 {
			return 0, "no agent requests"
		}
		return float64(m.Count(ph, "ingest_errors")) / float64(n), ""
	case "ingest_p99_ms":
		return latency("ingest", 0.99)
	case "syslog_send_errors":
		if m.Count(ph, "syslog_sent")+m.Count(ph, "syslog_send_errors") == 0 {
			return 0, "no syslog sent"
		}
		return float64(m.Count(ph, "syslog_send_errors")), ""
	case "page_p95_ms":
		return latency("page", 0.95)
	case "search_p95_ms":
		return latency("search", 0.95)
	case "write_p95_ms":
		return latency("write", 0.95)
	case "unexpected_signouts", "write_conflicts":
		if m.Count(ph, "user_requests") == 0 {
			return 0, "no user requests"
		}
		return float64(m.Count(ph, c.Name)), ""
	case "takeover_seconds", "brute_checked_per_account", "settings_converge_seconds":
		if c.Name == "settings_converge_seconds" && m.Count(ph, "churn_saved") == 0 {
			if m.Count(ph, "churn_errors")+m.Count(ph, "churn_conflicts")+m.Count(ph, "churn_unknown_key") > 0 {
				return math.NaN(), ""
			}
			return 0, "no setting was changed"
		}
		if c.Name == "settings_converge_seconds" && m.Count(ph, "churn_not_converged") > 0 {
			return math.Inf(1), ""
		}
		v, ok := m.Gauge(ph, c.Name)
		if !ok {
			return 0, "nothing measured"
		}
		return v, ""
	case "leaders_at_once":
		if m.Count(ph, "leader_samples") == 0 {
			return 0, "needs each server listed in targets, with admin credentials"
		}
		v, _ := m.Gauge(ph, c.Name)
		return v, ""
	case "os_ops_per_server_per_second":
		if r.os == nil {
			return 0, "the scenario names no OpenSearch"
		}
		v, ok := m.Gauge(ph, c.Name)
		if !ok {
			return 0, "OpenSearch's counters could not be read"
		}
		return v, ""
	case "os_ops_per_random_cookie":
		if r.os == nil {
			return 0, "the scenario names no OpenSearch"
		}
		flood, ok1 := r.opsPerSecond[c.Phase]
		base, ok2 := r.opsPerSecond[c.Baseline]
		cookies := m.Count(c.Phase, "cookie_requests")
		if !ok1 || !ok2 || cookies == 0 || r.phaseSecs[c.Phase] == 0 {
			return 0, "nothing measured"
		}
		perSecond := float64(cookies) / r.phaseSecs[c.Phase]
		return max(flood-base, 0) / perSecond, ""
	case "brute_lockouts":
		if m.Count(ph, "brute_attempts") == 0 {
			return 0, "no sign-in attempts"
		}
		return float64(m.Count(ph, "brute_lockouts")), ""
	case "generator_lag_ms":
		h := m.Hist(ph, "generator_lag")
		if h.Count() == 0 {
			return 0, "nothing measured"
		}
		return ms(h.Max()), ""
	}
	return 0, "not measured by this version"
}
