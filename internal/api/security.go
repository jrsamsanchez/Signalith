package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/security"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// The Security page's checks run 30 seconds after the process starts (so
// OpenSearch is ready), hourly, after every restart in place, after each
// change of certificate authority, and when an admin asks. Asking runs
// them at most once every recheckEvery; callers who ask at once share
// one run. Each run is capped (security.RunLimit), so no request waits
// long for one.
const (
	securityFirstRun    = 30 * time.Second
	securityAfterReload = 3 * time.Second
	securityEvery       = time.Hour
	recheckEvery        = 10 * time.Second
	// maxPlainSignIns caps the addresses that signed in, and the agents
	// that sent events, over plain HTTP the checker remembers.
	maxPlainSignIns = 50
)

// SecurityChecker runs the security checks and keeps the last report. It
// belongs to the process rather than to one Server: a restart in place
// hands it the new server, so the report, the sign-ins seen over plain
// HTTP and what was logged carry over.
type SecurityChecker struct {
	// OnReport, when set, hears of each new report, such as the cluster
	// node, whose heartbeat sums it up for the other servers.
	OnReport func(*security.Report)
	// Started is when the process started, for the first run.
	Started time.Time

	log     *slog.Logger
	mu      sync.Mutex
	report  *security.Report
	lastRun time.Time
	// runs counts the runs started, and ended is the number of the last
	// run that ended, whether or not it made a report. A fresh request is
	// met only by a run that started after it asked: counting, not
	// comparing times, because Windows clocks can give two moments the
	// same time.
	runs, ended int
	// running is closed when the run in progress ends; nil when none is.
	running chan struct{}
	// logged are the ids at risk that were logged last; nil before the
	// first run.
	logged []string
	// plain are the computers that signed in, and plainAgents the agents
	// that sent events, over plain HTTP, not through a trusted reverse
	// proxy.
	plain, plainAgents addrSeen
}

// NewSecurityChecker returns a checker that logs to log.
func NewSecurityChecker(log *slog.Logger) *SecurityChecker {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &SecurityChecker{log: log, Started: time.Now(), plain: addrSeen{max: maxPlainSignIns}, plainAgents: addrSeen{max: maxPlainSignIns}}
}

// Report is the last report, or nil before the first run ends.
func (c *SecurityChecker) Report() *security.Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.report
}

// notePlain records a sign-in over plain HTTP from another computer.
func (c *SecurityChecker) notePlain(a netip.Addr) { c.plain.note(a) }

// run runs the checks with gather, or joins the run in progress. With
// fresh, a run that started before this call is not enough: it waits for
// that one, then runs again. Without, a run that started less than
// recheckEvery ago is enough. It returns the newest report, nil if none
// came within ctx.
func (c *SecurityChecker) run(ctx context.Context, gather func(context.Context) *security.Report, fresh bool) *security.Report {
	c.mu.Lock()
	asked := c.runs
	c.mu.Unlock()
	for {
		c.mu.Lock()
		if ch := c.running; ch != nil {
			c.mu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				return c.Report()
			}
			if !fresh {
				return c.Report()
			}
			continue
		}
		if fresh && c.ended > asked {
			r := c.report
			c.mu.Unlock()
			return r
		}
		if c.report != nil && !fresh && time.Since(c.lastRun) < recheckEvery {
			r := c.report
			c.mu.Unlock()
			return r
		}
		ch := make(chan struct{})
		c.runs++
		c.running, c.lastRun = ch, time.Now()
		run := c.runs
		c.mu.Unlock()
		// The run is shared, so it does not end with the request that
		// started it; it has its own time limit.
		go c.once(context.WithoutCancel(ctx), gather, ch, run)
		select {
		case <-ch:
			return c.Report()
		case <-ctx.Done():
			return c.Report()
		}
	}
}

// once runs the checks and keeps their report.
func (c *SecurityChecker) once(ctx context.Context, gather func(context.Context) *security.Report, done chan struct{}, run int) {
	var r *security.Report
	defer func() {
		if p := recover(); p != nil {
			c.log.Error("security check failed", "panic", fmt.Sprint(p))
		}
		if r != nil {
			c.logChange(r)
			if c.OnReport != nil {
				c.OnReport(r)
			}
		}
		c.mu.Lock()
		if r != nil {
			c.report = r
		}
		c.ended = run
		c.running = nil
		c.mu.Unlock()
		close(done)
	}()
	r = gather(ctx)
}

// logChange logs the checks at risk when they are not the ones logged
// last.
func (c *SecurityChecker) logChange(r *security.Report) {
	ids := r.AtRisk()
	c.mu.Lock()
	same := c.logged != nil && strings.Join(c.logged, ",") == strings.Join(ids, ",")
	c.logged = append([]string{}, ids...)
	c.mu.Unlock()
	switch {
	case same:
	case len(ids) > 0:
		c.log.Warn("security check: at risk", "checks", strings.Join(ids, ","))
	default:
		c.log.Info("security check: nothing at risk")
	}
}

// security returns the server's checker, made on first use when it was
// given none.
func (s *Server) security() *SecurityChecker {
	s.secOnce.Do(func() {
		s.sec = s.Security
		if s.sec == nil {
			s.sec = NewSecurityChecker(s.Log)
		}
	})
	return s.sec
}

// RunSecurityChecks runs the checks first after delay, then hourly,
// until ctx ends. The process runs it for each instance of the server,
// so each restart in place checks again.
func (s *Server) RunSecurityChecks(ctx context.Context, delay time.Duration) {
	t := time.NewTimer(delay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.security().run(ctx, s.gatherSecurity, true)
		t.Reset(securityEvery)
	}
}

// SecurityDelay is how long a new instance of the server waits before
// its first check: until 30 seconds after the process started, so
// OpenSearch is ready, or a moment after a restart in place.
func SecurityDelay(started time.Time) time.Duration {
	return max(securityFirstRun-time.Since(started), securityAfterReload)
}

// SecuritySummaryOf sums a report up for the cluster heartbeat.
func SecuritySummaryOf(r *security.Report) cluster.SecuritySummary {
	at := r.CheckedAt
	s := cluster.SecuritySummary{CheckedAt: &at, Risk: r.Summary.Risk, Attention: r.Summary.Attention, Unknown: r.Summary.Unknown}
	if r.CA != nil && r.CA.Current != nil {
		s.CAScope = r.CA.Current.Scope
	}
	return s
}

// gatherSecurity gathers the facts and checks them.
func (s *Server) gatherSecurity(ctx context.Context) *security.Report {
	c := s.conf()
	now := time.Now()
	h := security.ServerHost(c, s.inContainer())
	f := security.NewFacts(h, now, security.ServerInfoFor(h, s.serverName(), s.Version))
	if !s.Started.IsZero() {
		f.Uptime = now.Sub(s.Started)
	}
	if f.TLS = security.TLSFactsFrom(s.TLS, c); f.TLS != nil {
		f.TLS.Refusals = s.TLS.Refusals()
		f.TLS.Seen = security.SeenFrom(ctx, s.TLS)
	}
	f.Runtime = s.runtimeFacts(now, h.InContainer)
	f.AgentTokens = TokenFacts(ctx, s.tokens())
	f.Users = security.UserFactsFrom(s.userStore(), c.Auth.AdminUser, now)
	if d := s.dir().Settings(); d.IsEnabled() {
		f.Directory = &d
	}
	if s.Feeds != nil {
		f.Feeds = security.FeedsFrom(s.Feeds.Status())
	}
	collectors := append(security.HostCollectors(h, s.archiving()), security.OpenSearchCollectors(c, h.InContainer, c.StateDir())...)
	r := security.Run(ctx, f, collectors)
	r.Others = s.otherServers()
	return r
}

// archiving reports whether a retention policy archives days.
func (s *Server) archiving() bool {
	if s.Retention == nil {
		return false
	}
	set, err := s.Retention.Settings()
	if err != nil {
		return false
	}
	if set.Default.Archive {
		return true
	}
	for _, p := range set.Policies {
		if p.Archive {
			return true
		}
	}
	return false
}

// serverName is this server's name among those that share its
// OpenSearch, else the computer's.
func (s *Server) serverName() string {
	if s.Cluster != nil {
		for _, sv := range s.Cluster.Status().Servers {
			if sv.Self {
				return sv.Name
			}
		}
	}
	if n := s.conf().Cluster.NodeName; n != "" {
		return n
	}
	name, _ := os.Hostname()
	return name
}

// otherServers sums up the other servers' last checks, from their
// heartbeats.
func (s *Server) otherServers() []security.OtherServer {
	if s.Cluster == nil {
		return nil
	}
	var out []security.OtherServer
	for _, sv := range s.Cluster.Status().Servers {
		if sv.Self {
			continue
		}
		o := security.OtherServer{Name: sv.Name, NotChecked: true}
		if d := sv.Detail; d != nil {
			o.URL = d.NodeURL
			if sec := d.Security; sec != nil {
				o.NotChecked = false
				o.Risk, o.Attention, o.CheckedAt, o.CAScope = sec.Risk, sec.Attention, sec.CheckedAt, sec.CAScope
			}
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// runtimeFacts are what this server saw in the last day.
func (s *Server) runtimeFacts(now time.Time, inContainer bool) *security.RuntimeFacts {
	since := now.Add(-24 * time.Hour)
	rt := &security.RuntimeFacts{SyslogSenders: map[string]int{}}
	rt.DirectPlain = s.security().plain.since(since)
	rt.DirectPlainAgents = s.security().plainAgents.since(since)
	for _, x := range s.Pipeline.PlaintextSenders(since) {
		// Agents on this computer: their events don't cross the network.
		if a, err := netip.ParseAddr(x.Address); err == nil && a.Unmap().IsLoopback() {
			rt.LocalPlainSenders += max(1, len(x.Hosts))
			continue
		}
		rt.PlainSenderCount += max(1, len(x.Hosts))
		if len(x.Hosts) == 0 {
			rt.PlainSenders = append(rt.PlainSenders, x.Address)
		}
		for _, h := range x.Hosts {
			rt.PlainSenders = append(rt.PlainSenders, h+" ("+x.Address+")")
		}
	}
	if s.Syslog != nil {
		gw, haveGW := netip.Addr{}, false
		if inContainer {
			gw, haveGW = security.DefaultGateway()
		}
		plain, natted := 0, 0
		for _, x := range s.Syslog.Stats().Senders {
			if x.LastSeen.Before(since) {
				continue
			}
			rt.SyslogSenders[x.Protocol]++
			if x.Protocol != "tls" {
				plain++
				if a := clientaddr.Parse(x.Address); haveGW && a.IsValid() && a.Unmap() == gw {
					natted++
				}
			}
		}
		rt.SyslogNATed = plain > 0 && natted == plain
	}
	rt.LegacyProxies = s.legacyProxies.since(since)
	if s.Cluster != nil && len(s.Cluster.Status().Servers) > 1 {
		rt.ClusterServer = s.serverName()
	}
	return rt
}

// handleSecurity answers GET api/security: the last report, as JSON or,
// with format=text, as the text signalith security prints.
func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	chk := s.security()
	var rep *security.Report
	if q.Get("recheck") == "1" {
		rep = chk.run(r.Context(), s.gatherSecurity, false)
	} else if rep = chk.Report(); rep == nil {
		// Before the first run: run now, and wait for it.
		ctx, cancel := context.WithTimeout(r.Context(), security.RunLimit+2*time.Second)
		rep = chk.run(ctx, s.gatherSecurity, false)
		cancel()
	}
	w.Header().Set("Cache-Control", "no-store")
	if rep == nil {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, errors.New("The first security check is still running. Try again in a moment."))
		return
	}
	if q.Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if q.Get("download") == "1" {
			w.Header().Set("Content-Disposition", `attachment; filename="`+reportFileName(rep)+`"`)
		}
		_, _ = w.Write([]byte(security.Text(rep)))
		return
	}
	writeJSON(w, http.StatusOK, rep.Typographic())
}

// reportFileName is signalith-security-{server}-{date}.txt, with only
// letters, digits, dots and hyphens from the server's name.
func reportFileName(r *security.Report) string {
	name := strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-':
			return c
		}
		return '-'
	}, r.Server.Name)
	if name = strings.Trim(name, ".-"); name == "" {
		name = "server"
	}
	return "signalith-security-" + name + "-" + r.CheckedAt.UTC().Format("2006-01-02") + ".txt"
}

// caActions are the steps of a change of certificate authority, with
// what each writes to the audit log.
var caActions = map[string]string{
	"prepare":  "certificate authority prepared",
	"switch":   "certificate authority switched",
	"rollback": "certificate authority switched back",
	"discard":  "new certificate authority discarded",
	"prune":    "previous certificate authority removed",
}

// caDoing names each step for a message that it failed, in the page's
// words.
var caDoing = map[string]string{
	"prepare":  "Making the new certificate authority",
	"switch":   "Switching to the new certificate authority",
	"rollback": "Switching back",
	"discard":  "Cancelling the new certificate authority",
	"prune":    "Removing the old certificate authority",
}

// handleSecurityCA answers POST api/security/ca: a step in changing
// Signalith's own certificate authority. The answer is the new report.
func (s *Server) handleSecurityCA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Scope  string `json:"scope"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	msg, ok := caActions[req.Action]
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("action must be prepare, switch, rollback, discard or prune"))
		return
	}
	m := s.TLS
	if !m.LocalCA() {
		writeError(w, http.StatusNotFound, notAutoError(s.conf()))
		return
	}
	s.caMu.Lock()
	defer s.caMu.Unlock()
	from := fingerprintOf(m.CAInfo())
	var err error
	args := []any{}
	switch req.Action {
	case "prepare":
		// Refused before the setting is saved, so a refusal changes
		// nothing.
		switch {
		case m.Previous() != nil:
			writeError(w, http.StatusConflict, tlsauto.ErrPreviousKept)
			return
		case m.Next() != nil:
			writeError(w, http.StatusConflict, tlsauto.ErrNextExists)
			return
		}
		scope := strings.ToLower(strings.TrimSpace(req.Scope))
		switch scope {
		case "":
			scope = s.conf().Server.CAScope()
		case tlsauto.ScopeStandard, tlsauto.ScopeStrict:
			if scope != s.conf().Server.CAScope() {
				if status, err := s.saveSetting(r, "server.tls.ca_scope", scope); err != nil {
					writeError(w, status, err)
					return
				}
			}
		default:
			writeError(w, http.StatusBadRequest, errors.New("scope must be standard or strict"))
			return
		}
		if err = m.Prepare(scope); err == nil {
			args = append(args, "scope", scope, "fingerprint", fingerprintOf(m.Next()))
		}
	case "switch":
		if err = m.Switch(); err == nil {
			args = append(args, "from", from, "to", fingerprintOf(m.CAInfo()))
		}
	case "rollback":
		if err = m.Rollback(); err == nil {
			args = append(args, "from", from, "to", fingerprintOf(m.CAInfo()))
		}
	case "discard":
		err = m.Discard()
	case "prune":
		err = m.Prune()
	}
	var se *tlsauto.StateError
	switch {
	case errors.As(err, &se):
		writeError(w, http.StatusConflict, err)
		return
	case errors.Is(err, tlsauto.ErrNotAuto):
		writeError(w, http.StatusNotFound, notAutoError(s.conf()))
		return
	case err != nil:
		s.Log.Error("could not change the certificate authority", "action", req.Action, "err", err)
		writeError(w, http.StatusInternalServerError, fmt.Errorf("%s didn't work: %w", caDoing[req.Action], err))
		return
	}
	s.audit(r, msg, args...)
	rep := s.security().run(r.Context(), s.gatherSecurity, true)
	if rep == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, rep.Typographic())
}

func notAutoError(c *config.Config) error {
	if !c.Server.HTTPS() && c.Syslog.TLS == "" {
		return errors.New("Signalith doesn't serve HTTPS itself (server.tls.mode is off), so it has no certificate authority of its own to change.")
	}
	return errors.New("Signalith uses your own certificate files, so it has no certificate authority of its own to change.")
}

func fingerprintOf(in *tlsauto.CAInfo) string {
	if in == nil {
		return ""
	}
	return in.Fingerprint
}

// saveSetting saves one setting the way the Settings page does, audited
// as a settings change, and puts it into use when it applies at once.
func (s *Server) saveSetting(r *http.Request, key string, value any) (int, error) {
	if s.Config.Path() == "" {
		return http.StatusConflict, errNoConfigFile
	}
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	pages := s.pages()
	res, err := pages.CheckEdit(config.Edit{Values: map[string]any{key: value}, By: userOf(r)})
	switch {
	case errors.Is(err, config.ErrPageFile):
		return http.StatusConflict, errors.New("Nothing was saved, because the settings file cannot be read. Fix it on the server, or start a new one.")
	case err != nil:
		return http.StatusInternalServerError, err
	}
	if !res.OK() {
		var why []string
		for _, p := range res.Fields {
			why = append(why, p)
		}
		why = append(why, res.Problems...)
		sort.Strings(why)
		return http.StatusBadRequest, errors.New("Nothing was saved: " + strings.Join(why, " "))
	}
	if len(res.Changed) == 0 {
		return http.StatusOK, nil
	}
	if err := pages.Write(res.Page); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("could not save the settings file %s: %w", res.Config.SettingsFile(), err)
	}
	applied := s.applyLive(res.Before, res.Config)
	var restart []string
	running := s.conf()
	for _, k := range res.Changed {
		if !slices.Contains(applied, k) && !config.SameValue(running, res.Config, k) {
			restart = append(restart, k)
		}
	}
	s.audit(r, "settings saved", "changes", describeChanges(res), "applied_now", strings.Join(applied, ","),
		"after_restart", strings.Join(restart, ","), "file", res.Config.SettingsFile())
	return http.StatusOK, nil
}

// notePlainSignIn records a sign-in over plain HTTP from another
// computer, not through a trusted reverse proxy, for the Security page.
func (s *Server) notePlainSignIn(r *http.Request) {
	if r.TLS != nil || s.viaTrustedProxy(r) {
		return
	}
	from := clientaddr.Parse(r.RemoteAddr)
	if !from.IsValid() || from.Unmap().IsLoopback() {
		return
	}
	s.security().notePlain(from)
}

// noteName records the name an HTTPS request asked for, so the Security
// page can tell which names a strict certificate authority would have to
// cover. Only requests from someone signed in, or an agent with a token,
// count: anyone who can reach the port could send any name.
func (s *Server) noteName(r *http.Request) {
	if r.TLS != nil && s.TLS != nil && validHostHeader(r.Host) {
		s.TLS.NoteName(r.Host)
	}
}

// notePlainAgent records an agent that sent events over plain HTTP to a
// server that doesn't serve HTTPS itself, not through a trusted reverse
// proxy, from another computer. Agents on plain HTTP to the HTTPS port
// are noted by the pipeline instead (see PlainHandler).
func (s *Server) notePlainAgent(r *http.Request) {
	if r.TLS != nil || plaintextIngest(r) || s.viaTrustedProxy(r) {
		return
	}
	from := clientaddr.Parse(r.RemoteAddr)
	if !from.IsValid() || from.Unmap().IsLoopback() {
		return
	}
	s.security().plainAgents.note(from)
}

// securityHealth is the Security page's count for the menu, in
// api/health for admins.
func (s *Server) securityHealth() map[string]any {
	rep := s.security().Report()
	if rep == nil {
		return nil
	}
	return map[string]any{"risk": rep.Summary.Risk, "checked_at": rep.CheckedAt}
}
