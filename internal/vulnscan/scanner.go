package vulnscan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// EventWriter writes events to the event indices. *ingest.Pipeline has
// it.
type EventWriter interface {
	IngestEvents(ctx context.Context, events []ingest.Event) (*ingest.Result, error)
}

// Scanner runs the scans: the networks' schedules, and Scan now. It runs
// as one of the background jobs, so of the servers that share one
// OpenSearch, only the one running those scans.
type Scanner struct {
	Store   *Store
	NVD     *NVD
	Checker *Checker
	Events  EventWriter
	// Server names this server in scans and reports.
	Server string
	// Allowed reports whether this server may run scans now; nil always.
	Allowed func() bool
	// Loc is the time zone of the schedules; nil is the server's.
	Loc *time.Location
	Log *slog.Logger
	// Runner runs Nmap; nil finds it.
	Runner *Runner
	// Tick is how often queued and due scans are looked for (default 10
	// seconds).
	Tick time.Duration

	mu      sync.Mutex
	current string // the scan running now
}

// Timings.
const (
	reportEvery   = 2 * time.Minute
	heartbeat     = 15 * time.Second
	staleAfter    = 3 * time.Minute
	cveFresh      = 24 * time.Hour
	cveStale      = 30 * 24 * time.Hour
	maxScanTime   = 12 * time.Hour
	eventBatch    = 1000
	maxScanEvents = 100000
)

func (s *Scanner) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Scanner) allowed() bool { return s.Allowed == nil || s.Allowed() }

// Running returns the ID of the scan running on this server, or "".
func (s *Scanner) Running() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// Run scans until ctx ends.
func (s *Scanner) Run(ctx context.Context) {
	tick := s.Tick
	if tick <= 0 {
		tick = 10 * time.Second
	}
	var lastReport time.Time
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		if s.allowed() {
			if time.Since(lastReport) >= reportEvery {
				s.CheckNow(ctx)
				lastReport = time.Now()
			}
			if err := s.Step(ctx); err != nil && ctx.Err() == nil {
				s.log().Warn("vulnerability scans: could not read or start scans; trying again shortly", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// CheckNow checks this server and records the report the page shows.
func (s *Scanner) CheckNow(ctx context.Context) *Report {
	set, err := s.Store.CachedSettings(ctx)
	if err != nil {
		set = DefaultSettings()
	}
	checks, path := s.checker().Run(ctx, set)
	r := &Report{Server: s.Server, At: time.Now().UTC(), Checks: checks, Ready: Ready(checks)}
	if s.Runner == nil || s.Runner.Exec == nil {
		s.mu.Lock()
		s.Runner = &Runner{Path: path}
		s.mu.Unlock()
	}
	if err := s.Store.PutReport(ctx, r); err != nil && ctx.Err() == nil {
		s.log().Debug("vulnerability scans: could not record the scanner check", "err", err)
	}
	return r
}

func (s *Scanner) checker() *Checker {
	if s.Checker != nil {
		return s.Checker
	}
	return &Checker{NVD: s.NVD}
}

// Step marks scans cut off, queues the scans that are due and runs the
// oldest queued one.
func (s *Scanner) Step(ctx context.Context) error {
	set, _, err := s.Store.Settings(ctx)
	if err != nil {
		return err
	}
	scans, err := s.Store.Scans(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	targets := map[string]Target{}
	for _, t := range set.Targets {
		targets[t.ID] = t
	}
	active := map[string]bool{}
	lastScheduled := map[string]time.Time{}
	for _, sc := range scans {
		switch sc.State {
		case StateRunning:
			if sc.ID != s.Running() && now.Sub(sc.Heartbeat) > staleAfter {
				s.finish(ctx, sc, StateInterrupted, "The scan stopped because the server running it stopped or restarted. It runs again at its next scheduled time, or click Scan now.")
				continue
			}
			active[sc.TargetID] = true
		case StateQueued:
			active[sc.TargetID] = true
		}
		if sc.Trigger == TriggerSchedule && sc.CreatedAt.After(lastScheduled[sc.TargetID]) {
			lastScheduled[sc.TargetID] = sc.CreatedAt
		}
	}
	for _, t := range set.Targets {
		if !t.Enabled || t.Scanner != "" || active[t.ID] {
			continue
		}
		slot := t.Schedule.LastSlot(now, s.Loc)
		if slot.IsZero() || !slot.After(t.CreatedAt) || !slot.After(lastScheduled[t.ID]) {
			continue
		}
		if _, err := s.Store.NewScan(ctx, t, TriggerSchedule, ""); err != nil {
			return err
		}
		active[t.ID] = true
		s.log().Info("vulnerability scan queued on schedule", "network", t.Name)
	}
	// Re-read: the oldest queued scan, including any just queued.
	scans, err = s.Store.Scans(ctx)
	if err != nil {
		return err
	}
	sort.Slice(scans, func(i, j int) bool { return scans[i].CreatedAt.Before(scans[j].CreatedAt) })
	for _, sc := range scans {
		if sc.State != StateQueued {
			continue
		}
		t, ok := targets[sc.TargetID]
		if !ok {
			s.finish(ctx, sc, StateFailed, "The network was removed before the scan started.")
			continue
		}
		if t.Scanner != "" {
			continue
		}
		if sc.Stop {
			s.finish(ctx, sc, StateStopped, "")
			continue
		}
		if !s.allowed() {
			return nil
		}
		s.runScan(ctx, sc, t, set)
		ids := map[string]bool{}
		for id := range targets {
			ids[id] = true
		}
		if err := s.Store.PruneScans(ctx, ids); err != nil {
			s.log().Debug("vulnerability scans: could not prune old scans", "err", err)
		}
		if err := s.Store.DropHosts(ctx, ids); err != nil {
			s.log().Debug("vulnerability scans: could not drop hosts of removed networks", "err", err)
		}
		return nil
	}
	return nil
}

// finish records a scan's end.
func (s *Scanner) finish(ctx context.Context, sc *Scan, state, msg string) {
	f := map[string]any{"state": state, "finished_at": time.Now().UTC()}
	if msg != "" {
		f["error"] = msg
	}
	if err := s.Store.UpdateScan(ctx, sc.ID, f); err != nil && !errors.Is(err, ErrNotFound) {
		s.log().Warn("vulnerability scans: could not record a scan's end", "scan", sc.ID, "err", err)
	}
}

// runScan runs one scan to its end.
func (s *Scanner) runScan(parent context.Context, sc *Scan, t Target, set Settings) {
	s.mu.Lock()
	s.current = sc.ID
	runner := s.Runner
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.current = ""
		s.mu.Unlock()
	}()
	if runner == nil || (runner.Path == "" && runner.Exec == nil) {
		s.CheckNow(parent)
		s.mu.Lock()
		runner = s.Runner
		s.mu.Unlock()
	}
	if runner == nil || runner.Path == "" {
		s.finish(parent, sc, StateFailed, "Nmap is not installed on "+s.Server+". Open Setup on the Vulnerabilities page to see what is needed.")
		return
	}
	started := time.Now().UTC()
	if err := s.Store.UpdateScan(parent, sc.ID, map[string]any{"state": StateRunning, "started_at": started, "heartbeat": started, "scanner": s.Server}); err != nil {
		s.log().Warn("vulnerability scans: could not start a scan", "scan", sc.ID, "err", err)
		return
	}
	s.log().Info("vulnerability scan started", "network", t.Name, "scan", sc.ID, "trigger", sc.Trigger)
	ctx, cancel := context.WithTimeout(parent, maxScanTime)
	defer cancel()

	var pmu sync.Mutex
	prog := Progress{}
	stopped := false
	done := make(chan struct{})
	go func() {
		tk := time.NewTicker(heartbeat)
		defer tk.Stop()
		for {
			select {
			case <-done:
				return
			case <-tk.C:
			}
			pmu.Lock()
			p := prog
			pmu.Unlock()
			_ = s.Store.UpdateScan(ctx, sc.ID, map[string]any{"heartbeat": time.Now().UTC(), "progress": p})
			cur, _, err := s.Store.Scan(ctx, sc.ID)
			if (err == nil && cur.Stop) || errors.Is(err, ErrNotFound) || !s.allowed() {
				pmu.Lock()
				stopped = true
				pmu.Unlock()
				cancel()
				return
			}
		}
	}()
	found, err := runner.Scan(ctx, t, func(p Progress) {
		pmu.Lock()
		defer pmu.Unlock()
		if p.Percent < 0 {
			prog.HostsUp = p.HostsUp
			return
		}
		prog = p
	})
	close(done)
	pmu.Lock()
	wasStopped := stopped
	pmu.Unlock()
	switch {
	case wasStopped:
		s.finish(parent, sc, StateStopped, "")
		s.log().Info("vulnerability scan stopped", "network", t.Name, "scan", sc.ID)
		return
	case errors.Is(err, context.DeadlineExceeded):
		s.finish(parent, sc, StateFailed, fmt.Sprintf("The scan ran longer than %s and was stopped. Split the network into smaller ones, or scan fewer ports.", maxScanTime))
		return
	case err != nil:
		if parent.Err() != nil {
			// This server is stopping; the next one to run scans marks it.
			return
		}
		s.finish(parent, sc, StateFailed, err.Error())
		s.log().Warn("vulnerability scan failed", "network", t.Name, "scan", sc.ID, "err", err)
		return
	}

	finished := time.Now().UTC()
	hosts, counts, cveErr := s.assess(parent, sc, t, found, set.CVELookup, finished)
	if err := s.Store.SaveHosts(parent, t.ID, hosts); err != nil {
		s.finish(parent, sc, StateFailed, "The scan finished but its results could not be saved: "+err.Error())
		return
	}
	if s.Events != nil {
		if err := s.writeEvents(parent, sc, hosts, finished); err != nil {
			s.log().Warn("vulnerability scan results could not be written as events; the Vulnerabilities page has them", "scan", sc.ID, "err", err)
		}
	}
	f := map[string]any{"state": StateDone, "finished_at": finished, "counts": counts,
		"progress": Progress{Percent: 100, HostsUp: len(hosts)}}
	if cveErr != "" {
		f["cve_error"] = cveErr
	}
	if err := s.Store.UpdateScan(parent, sc.ID, f); err != nil {
		s.log().Warn("vulnerability scans: could not record a scan's end", "scan", sc.ID, "err", err)
	}
	s.log().Info("vulnerability scan finished", "network", t.Name, "scan", sc.ID, "hosts", counts.Hosts,
		"services", counts.Services, "critical", counts.Critical, "high", counts.High, "known_exploited", counts.KEV)
}

// assess matches what a scan found to CVEs.
func (s *Scanner) assess(ctx context.Context, sc *Scan, t Target, found []ScannedHost, lookup bool, at time.Time) ([]*Host, Counts, string) {
	m := &matcher{s: s, lookup: lookup && s.NVD != nil, cache: map[string][]CVE{}}
	var counts Counts
	hosts := make([]*Host, 0, len(found))
	for _, f := range found {
		h := &Host{ID: HostID(t.ID, f.Address), TargetID: t.ID, TargetName: t.Name, Address: f.Address, Hostname: f.Hostname,
			MAC: f.MAC, Vendor: f.Vendor, ScanID: sc.ID, FirstSeen: at, LastSeen: at, Services: []HostService{}}
		for _, svc := range f.Services {
			hs := HostService{Service: svc}
			hs.Vulns = m.vulns(ctx, svc)
			for _, v := range hs.Vulns {
				h.Counts.add(v.Severity, v.KEV)
				counts.add(v.Severity, v.KEV)
				h.MaxCVSS = max(h.MaxCVSS, v.CVSS)
			}
			h.Services = append(h.Services, hs)
		}
		h.Counts.Hosts = 1
		h.Counts.Services = len(h.Services)
		counts.Services += len(h.Services)
		hosts = append(hosts, h)
	}
	counts.Hosts = len(hosts)
	SortHosts(hosts)
	return hosts, counts, m.err
}

// matcher looks up and caches CVEs for one scan.
type matcher struct {
	s       *Scanner
	lookup  bool
	cache   map[string][]CVE
	err     string
	offline bool // the database could not be reached: use only what is kept
}

// serviceCPEs are the products a service runs, with versions. Nmap leaves
// the version out of a CPE when it is not sure of it, or names it only in
// the service's version.
func serviceCPEs(svc Service) []CPE {
	var out []CPE
	seen := map[string]bool{}
	for _, raw := range svc.CPEs {
		c, ok := ParseCPE(raw)
		if !ok || c.Part == "h" {
			continue
		}
		if c.Version == "" && svc.Version != "" && c.Part == "a" {
			if v := strings.Fields(svc.Version); len(v) > 0 {
				c.Version = v[0]
			}
		}
		if c.FullVersion() == "" || seen[c.String()] {
			continue
		}
		seen[c.String()] = true
		out = append(out, c)
	}
	return out
}

// aliases are other names the database files a product under: Nmap
// still names nginx after its author, while CVEs since 2020 name F5.
var aliases = map[string][]CPE{
	"a:igor_sysoev:nginx": {{Part: "a", Vendor: "f5", Product: "nginx"}, {Part: "a", Vendor: "nginx", Product: "nginx"}},
	"a:mysql:mysql":       {{Part: "a", Vendor: "oracle", Product: "mysql"}},
	"a:mortbay:jetty":     {{Part: "a", Vendor: "eclipse", Product: "jetty"}},
}

// names returns a product and its aliases, all with its version.
func names(c CPE) []CPE {
	out := []CPE{c}
	for _, a := range aliases[c.Key()] {
		a.Version, a.Update = c.Version, c.Update
		out = append(out, a)
	}
	return out
}

func (m *matcher) vulns(ctx context.Context, svc Service) []Vuln {
	var out []Vuln
	seen := map[string]bool{}
	for _, found := range serviceCPEs(svc) {
		for _, c := range names(found) {
			cves := m.product(ctx, c)
			ver := c.FullVersion()
			for _, cve := range cves {
				if seen[cve.ID] || !cve.Applies(ver) {
					continue
				}
				seen[cve.ID] = true
				out = append(out, Vuln{CVE: cve.ID, Description: cve.Description, CVSS: cve.CVSS, CVSSVersion: cve.CVSSVersion,
					Severity: cve.Severity, Published: cve.Published, KEV: cve.KEVAdded != "", KEVAdded: cve.KEVAdded, CPE: found.String()})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].KEV != out[j].KEV {
			return out[i].KEV
		}
		if out[i].CVSS != out[j].CVSS {
			return out[i].CVSS > out[j].CVSS
		}
		return out[i].CVE > out[j].CVE
	})
	return out
}

// product returns a product's CVEs: kept ones under a day old, else
// looked up, else kept ones under a month old.
func (m *matcher) product(ctx context.Context, c CPE) []CVE {
	if !m.lookup {
		return nil
	}
	key := c.Key()
	if cves, ok := m.cache[key]; ok {
		return cves
	}
	kept, at, found, err := m.s.Store.CachedCVEs(ctx, key)
	if err != nil {
		found = false
	}
	if found && time.Since(at) < cveFresh {
		m.cache[key] = kept
		return kept
	}
	if !m.offline {
		cves, err := m.s.NVD.Product(ctx, c.Part, c.Vendor, c.Product)
		if err == nil {
			if perr := m.s.Store.PutCVEs(ctx, key, cves); perr != nil {
				m.s.log().Debug("vulnerability scans: could not keep looked-up CVEs", "product", key, "err", perr)
			}
			m.cache[key] = cves
			return cves
		}
		if ctx.Err() == nil {
			m.s.log().Warn("vulnerability scans: CVE lookup failed", "product", key, "err", err)
		}
		if m.err == "" {
			m.err = err.Error()
		}
		if errors.Is(err, ErrNVDUnreachable) {
			m.offline = true
		}
	}
	if found && time.Since(at) < cveStale {
		m.cache[key] = kept
		return kept
	}
	m.cache[key] = nil
	return nil
}
