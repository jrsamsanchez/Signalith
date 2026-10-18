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

// Scanner runs the scans: the networks' schedules, and Scan now. Every
// server runs one. Each runs the scans of the networks that name it as
// their scanner, and the server that runs the background jobs also runs
// those that name none, marks scans whose server stopped, and tidies up.
type Scanner struct {
	Store   *Store
	NVD     *NVD
	Checker *Checker
	Events  EventWriter
	// Server names this server in scans and reports, and NodeID is its
	// node ID, which networks name as their scanner.
	Server string
	NodeID string
	// Leader reports whether this server runs the background jobs now;
	// nil always (a server on its own).
	Leader func() bool
	// Paused reports whether no scan may start or write now, as while
	// OpenSearch refuses writes; nil never.
	Paused func() bool
	// Loc is the time zone of the schedules; nil is the server's.
	Loc *time.Location
	Log *slog.Logger
	// Runner runs Nmap; nil finds it.
	Runner *Runner
	// Exploits ranks the CVEs found by CISA's KEV catalog and FIRST's EPSS
	// scores; nil leaves them as the NVD has them.
	Exploits *ExploitFeeds
	// OpenVAS runs the deeper scans of the networks that ask for them;
	// nil or not configured is not set up on this server.
	OpenVAS *OpenVAS
	// Tick is how often queued and due scans are looked for (default 10
	// seconds).
	Tick time.Duration

	mu        sync.Mutex
	running   map[string]bool // the scans running on this server
	lastPrune time.Time
	async     bool
}

// heartbeat is how often a running scan is marked alive; a var so tests
// can shorten it.
var heartbeat = 15 * time.Second

// Timings.
const (
	reportEvery   = 2 * time.Minute
	reportRetry   = 30 * time.Second
	staleAfter    = 3 * time.Minute
	cveFresh      = 24 * time.Hour
	cveStale      = 30 * 24 * time.Hour
	maxScanTime   = 12 * time.Hour
	eventBatch    = 1000
	maxScanEvents = 100000
	pruneEvery    = 10 * time.Minute
	// OfflineAfter is how long a server may go without checking itself
	// before its queued scans fail as not picked up.
	OfflineAfter = 10 * time.Minute
)

func (s *Scanner) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Scanner) leader() bool { return s.Leader == nil || s.Leader() }
func (s *Scanner) paused() bool { return s.Paused != nil && s.Paused() }

// Mine reports whether this server scans t, when leader says whether it
// runs the background jobs.
func (s *Scanner) Mine(t Target, leader bool) bool {
	if t.Scanner == "" {
		return leader
	}
	return s.NodeID != "" && t.Scanner == s.NodeID
}

// Running returns the IDs of the scans running on this server.
func (s *Scanner) Running() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.running))
	for id := range s.running {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (s *Scanner) isRunning(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running[id]
}

func (s *Scanner) busy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.running) > 0
}

// Run checks this server and runs its scans until ctx ends. A scan runs
// in the background, one at a time, while the checks and the tidying go
// on.
func (s *Scanner) Run(ctx context.Context) {
	tick := s.Tick
	if tick <= 0 {
		tick = 10 * time.Second
	}
	s.mu.Lock()
	s.async = true
	s.mu.Unlock()
	var lastReport time.Time
	var lastMine string
	ready := false
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		if !s.paused() {
			every := reportEvery
			if !ready {
				// Someone may be installing Nmap now: look again soon.
				every = reportRetry
			}
			// A network given to this server, or taken away, is checked
			// at once, so its reach shows on the Scanners page.
			mine := s.mineKey(ctx)
			if (time.Since(lastReport) >= every || mine != lastMine) && !s.busy() {
				ready = s.CheckNow(ctx).Ready
				lastReport, lastMine = time.Now(), mine
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

// mineKey sums up the networks this server scans and their addresses,
// from the store's short cache.
func (s *Scanner) mineKey(ctx context.Context) string {
	set, err := s.Store.CachedSettings(ctx)
	if err != nil {
		return ""
	}
	leader := s.leader()
	var b strings.Builder
	for _, t := range set.Targets {
		if s.Mine(t, leader) {
			b.WriteString(t.ID + "=" + strings.Join(t.Networks, ",") + ";")
		}
	}
	return b.String()
}

// CheckNow checks this server and records the report the pages show.
func (s *Scanner) CheckNow(ctx context.Context) *Report {
	set, err := s.Store.CachedSettings(ctx)
	if err != nil {
		set = DefaultSettings()
	}
	leader := s.leader()
	var mine []Target
	for _, t := range set.Targets {
		if s.Mine(t, leader) {
			mine = append(mine, t)
		}
	}
	checks, path := s.checker().Run(ctx, set, mine)
	r := &Report{Server: s.Server, NodeID: s.NodeID, At: time.Now().UTC(), Checks: checks, Ready: Ready(checks)}
	s.mu.Lock()
	if s.Runner == nil || s.Runner.Exec == nil {
		s.Runner = &Runner{Path: path}
	}
	s.mu.Unlock()
	if err := s.Store.PutReport(ctx, r); err != nil && ctx.Err() == nil {
		s.log().Debug("vulnerability scans: could not record the scanner check", "err", err)
	}
	return r
}

// sweepOpenVAS removes what earlier scans left in OpenVAS, such as the
// logins of a scan cut off when this server stopped. The objects of
// scans still queued or running, here or on another server sharing the
// same OpenVAS, are kept.
func (s *Scanner) sweepOpenVAS(ctx context.Context, ov *OpenVAS) {
	scans, err := s.Store.Scans(ctx)
	if err != nil {
		return
	}
	live := map[string]bool{}
	for _, sc := range scans {
		if sc.State == StateQueued || sc.State == StateRunning {
			live[sc.ID] = true
		}
	}
	if _, err := ov.Sweep(ctx, func(id string) bool { return live[id] }); err != nil {
		s.log().Warn("vulnerability scans: could not look for what earlier scans left in OpenVAS", "err", err)
	}
}

func (s *Scanner) openVAS() *OpenVAS {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.OpenVAS
}

func (s *Scanner) checker() *Checker {
	if s.Checker != nil {
		return s.Checker
	}
	return &Checker{NVD: s.NVD}
}

// Step queues this server's scans that are due and starts the oldest
// queued one. On the server that runs the background jobs it also marks
// scans cut off, fails scans whose server is gone, and tidies up.
func (s *Scanner) Step(ctx context.Context) error {
	leader := s.leader()
	var set Settings
	var err error
	if leader {
		set, _, err = s.Store.Settings(ctx)
	} else {
		// A server that runs no background jobs reads the networks from
		// the store's short cache, and nothing more unless one is its.
		set, err = s.Store.CachedSettings(ctx)
	}
	if err != nil {
		return err
	}
	targets := map[string]Target{}
	mine := false
	for _, t := range set.Targets {
		targets[t.ID] = t
		mine = mine || s.Mine(t, leader)
	}
	if !leader && !mine {
		return nil
	}
	scans, err := s.Store.Scans(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	active := map[string]bool{}
	lastScheduled := map[string]time.Time{}
	waiting := false
	for _, sc := range scans {
		switch sc.State {
		case StateRunning:
			if leader && !s.isRunning(sc.ID) && now.Sub(sc.Heartbeat) > staleAfter {
				s.finish(ctx, sc, StateInterrupted, "The scan stopped because the server running it stopped or restarted. It runs again at its next scheduled time, or click Scan now.")
				continue
			}
			active[sc.TargetID] = true
		case StateQueued:
			active[sc.TargetID] = true
			if t, ok := targets[sc.TargetID]; ok && t.Scanner != "" && !s.Mine(t, leader) && now.Sub(sc.CreatedAt) > OfflineAfter {
				waiting = true
			}
		}
		if sc.Trigger == TriggerSchedule && sc.CreatedAt.After(lastScheduled[sc.TargetID]) {
			lastScheduled[sc.TargetID] = sc.CreatedAt
		}
	}
	if leader && waiting {
		s.failUnclaimed(ctx, scans, targets, now)
	}
	for _, t := range set.Targets {
		if !t.Enabled || !s.Mine(t, leader) || active[t.ID] {
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
	if leader {
		s.prune(ctx, targets, false)
	}
	s.exploits(ctx, leader && len(set.Targets) > 0)
	if s.busy() {
		return nil
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
			if leader {
				s.finish(ctx, sc, StateFailed, "The network was removed before the scan started.")
			}
			continue
		}
		if !s.Mine(t, leader) {
			continue
		}
		if sc.Stop {
			s.finish(ctx, sc, StateStopped, "")
			continue
		}
		if s.paused() {
			return nil
		}
		if !s.claim(ctx, sc) {
			continue
		}
		run := func() {
			s.runScan(ctx, sc, t, set)
			if s.leader() {
				s.prune(ctx, targets, true)
			}
		}
		s.mu.Lock()
		async := s.async
		s.mu.Unlock()
		if async {
			go run()
		} else {
			run()
		}
		return nil
	}
	return nil
}

// claim marks a queued scan as running on this server, unless another
// server got to it first.
func (s *Scanner) claim(ctx context.Context, sc *Scan) bool {
	started := time.Now().UTC()
	ok, err := s.Store.ClaimScan(ctx, sc.ID, map[string]any{"started_at": started, "heartbeat": started, "scanner": s.Server, "scanner_id": s.NodeID})
	if err != nil {
		s.log().Warn("vulnerability scans: could not start a scan", "scan", sc.ID, "err", err)
		return false
	}
	if !ok {
		return false
	}
	s.mu.Lock()
	if s.running == nil {
		s.running = map[string]bool{}
	}
	s.running[sc.ID] = true
	s.mu.Unlock()
	sc.State, sc.StartedAt, sc.Heartbeat, sc.Scanner, sc.ScannerID = StateRunning, started, started, s.Server, s.NodeID
	return true
}

// failUnclaimed fails the scans queued for a server that has not checked
// itself for a while: it is stopped, removed or cannot reach OpenSearch.
func (s *Scanner) failUnclaimed(ctx context.Context, scans []*Scan, targets map[string]Target, now time.Time) {
	reports, err := s.Store.Reports(ctx)
	if err != nil {
		return
	}
	seen := map[string]*Report{}
	for _, r := range reports {
		if r.NodeID != "" && seen[r.NodeID] == nil {
			seen[r.NodeID] = r
		}
	}
	for _, sc := range scans {
		t, ok := targets[sc.TargetID]
		if sc.State != StateQueued || !ok || t.Scanner == "" || s.Mine(t, true) || now.Sub(sc.CreatedAt) <= OfflineAfter {
			continue
		}
		r := seen[t.Scanner]
		if r != nil && now.Sub(r.At) <= OfflineAfter {
			continue
		}
		msg := "The scan did not start: the server picked to scan this network has never checked in. Pick another scanner for the network, or start Signalith on that server."
		if r != nil {
			msg = fmt.Sprintf("The scan did not start: %s, the server that scans this network, has not checked in since %s. Make sure Signalith runs there and reaches OpenSearch, or pick another scanner for the network.",
				r.Server, r.At.UTC().Format("2006-01-02 15:04 UTC"))
		}
		s.finish(ctx, sc, StateFailed, msg)
		s.log().Warn("vulnerability scan not picked up by its scanner", "network", t.Name, "scanner", t.Scanner)
	}
}

// exploits keeps the exploit feeds current: every server reads the
// stored copy when it changes, and the server running the jobs downloads
// them once a day while there are networks to scan, then ranks the hosts
// kept again.
func (s *Scanner) exploits(ctx context.Context, download bool) {
	if s.Exploits == nil {
		return
	}
	if err := s.Exploits.Load(ctx, false); err != nil && ctx.Err() == nil {
		s.log().Debug("exploit intelligence: could not read the stored copy", "err", err)
	}
	if !download {
		return
	}
	run := func() {
		kept, err := s.Exploits.Refresh(ctx)
		if err != nil && ctx.Err() == nil {
			s.log().Debug("exploit intelligence: refresh incomplete", "err", err)
		}
		if !kept {
			return
		}
		n, err := s.Store.Reprioritize(ctx, s.Exploits.Current())
		if err != nil && ctx.Err() == nil {
			s.log().Warn("exploit intelligence: could not rank the hosts kept again", "err", err)
		} else if n > 0 {
			s.log().Info("exploit intelligence: hosts ranked again", "hosts", n)
		}
	}
	s.mu.Lock()
	async := s.async
	s.mu.Unlock()
	if async {
		go run()
	} else {
		run()
	}
}

// prune drops old scans and the hosts of removed networks: after a scan
// this server ran, or now and then.
func (s *Scanner) prune(ctx context.Context, targets map[string]Target, now bool) {
	s.mu.Lock()
	due := now || time.Since(s.lastPrune) >= pruneEvery
	if due {
		s.lastPrune = time.Now()
	}
	s.mu.Unlock()
	if !due {
		return
	}
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

// requeue gives back a scan cut short because this server is stopping,
// restarting in place or handing the jobs to another server: it goes back in the queue and runs again from the
// start, here once the server is back or on whichever server takes the
// network. A scan someone stopped is recorded as stopped.
func (s *Scanner) requeue(parent context.Context, sc *Scan, t Target, stopped bool) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer cancel()
	if stopped {
		s.finish(ctx, sc, StateStopped, "")
		return
	}
	ok, err := s.Store.RequeueScan(ctx, sc.ID, s.NodeID)
	switch {
	case err != nil:
		s.log().Warn("vulnerability scans: could not put back a scan this server stopped running; it is marked interrupted shortly", "scan", sc.ID, "err", err)
	case ok:
		s.log().Info("vulnerability scan put back in the queue: this server stopped running it", "network", t.Name, "scan", sc.ID)
	}
}

// runScan runs one scan, already claimed, to its end.
func (s *Scanner) runScan(parent context.Context, sc *Scan, t Target, set Settings) {
	s.mu.Lock()
	runner := s.Runner
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.running, sc.ID)
		s.mu.Unlock()
	}()
	if runner == nil || (runner.Path == "" && runner.Exec == nil) {
		s.CheckNow(parent)
		s.mu.Lock()
		runner = s.Runner
		s.mu.Unlock()
	}
	if runner == nil || (runner.Path == "" && runner.Exec == nil) {
		s.finish(parent, sc, StateFailed, "Nmap is not installed on "+s.Server+". Open Settings > Scanners to see what is needed.")
		return
	}
	// A network with no scanner of its own is scanned by the server that
	// runs the background jobs, only while it does.
	keep := func() bool { return t.Scanner != "" || s.leader() }
	s.log().Info("vulnerability scan started", "network", t.Name, "scan", sc.ID, "trigger", sc.Trigger)
	ctx, cancel := context.WithTimeout(parent, maxScanTime)
	defer cancel()

	var pmu sync.Mutex
	prog := Progress{}
	stopped := false
	handedOff := false // this server stopped running the jobs mid-scan
	done := make(chan struct{})
	beat := heartbeat
	go func() {
		tk := time.NewTicker(beat)
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
			gone := (err == nil && cur.Stop) || errors.Is(err, ErrNotFound)
			if gone || !keep() {
				pmu.Lock()
				stopped, handedOff = true, !gone
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
	// Then OpenVAS, for a network that asks for it, while the heartbeat
	// goes on. Its trouble never fails the scan: Nmap's results stand.
	var deep []Finding
	ovErr := ""
	pmu.Lock()
	stoppedNow := stopped
	pmu.Unlock()
	if err == nil && t.OpenVAS && !stoppedNow {
		switch ov := s.openVAS(); {
		case !ov.Configured():
			ovErr = "OpenVAS is not set up on " + s.Server + ", so only Nmap ran. Settings > Scanners says how to set it up."
		default:
			logins, lerr := s.Store.loginsFor(ctx, t)
			if lerr != nil {
				ovErr = "OpenVAS did not run: " + lerr.Error()
				s.log().Warn("vulnerability scan: OpenVAS scan skipped; the Nmap results are kept", "network", t.Name, "scan", sc.ID, "err", lerr)
				break
			}
			s.sweepOpenVAS(ctx, ov)
			s.log().Info("vulnerability scan: OpenVAS scan started", "network", t.Name, "scan", sc.ID,
				"ssh_login", logins.SSH != nil, "windows_login", logins.SMB != nil,
				"esxi_login", logins.ESXi != nil, "snmp_login", logins.SNMP != nil)
			var oerr error
			deep, oerr = ov.Scan(ctx, t, "Signalith "+t.Name+" "+sc.ID, logins, func(p float64) {
				pmu.Lock()
				prog.Task, prog.Percent, prog.ETA = "OpenVAS", p, time.Time{}
				pmu.Unlock()
			})
			if oerr != nil {
				if errors.Is(oerr, context.DeadlineExceeded) || errors.Is(oerr, context.Canceled) {
					err = oerr
				} else {
					ovErr = oerr.Error()
					s.log().Warn("vulnerability scan: OpenVAS scan failed; the Nmap results are kept", "network", t.Name, "scan", sc.ID, "err", oerr)
				}
			}
		}
	}
	close(done)
	pmu.Lock()
	wasStopped, wasHandedOff := stopped, handedOff
	pmu.Unlock()
	switch {
	case parent.Err() != nil || wasHandedOff:
		// This server is stopping, restarting in place to take new
		// settings, or no longer runs the jobs for a network without a
		// scanner of its own: give the scan back so it is not lost.
		s.requeue(parent, sc, t, wasStopped && !wasHandedOff)
		return
	case wasStopped:
		s.finish(parent, sc, StateStopped, "")
		s.log().Info("vulnerability scan stopped", "network", t.Name, "scan", sc.ID)
		return
	case errors.Is(err, context.DeadlineExceeded):
		s.finish(parent, sc, StateFailed, fmt.Sprintf("The scan ran longer than %s and was stopped. Split the network into smaller ones, or scan fewer ports.", maxScanTime))
		return
	case err != nil:
		s.finish(parent, sc, StateFailed, err.Error())
		s.log().Warn("vulnerability scan failed", "network", t.Name, "scan", sc.ID, "err", err)
		return
	}

	finished := time.Now().UTC()
	hosts, counts, cveErr := s.assess(parent, sc, t, found, set.CVELookup, finished)
	if len(deep) > 0 {
		hosts = MergeOpenVAS(hosts, deep, t, sc.ID, finished)
		counts = Recount(hosts)
	}
	if x := s.Exploits.Current(); x != nil {
		x.Apply(hosts)
		counts = Recount(hosts)
	}
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
	if ovErr != "" {
		f["openvas_error"] = ovErr
	}
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
