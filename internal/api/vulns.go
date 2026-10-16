package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// Vulns backs the Vulnerabilities page: the networks scanned with Nmap,
// what the scans found, and the scanner's own check of what it needs.
type Vulns struct {
	Store *vulnscan.Store
	// Scanner runs the scans when this server runs the background jobs.
	Scanner *vulnscan.Scanner

	mu     sync.Mutex
	report *vulnscan.Report
}

// useNVD puts a CVE database address and API key, and the exploit feeds'
// addresses, saved on the Settings page into use, and has the next setup
// check look again.
func (v *Vulns) useNVD(url, key, kevURL, epssURL string) {
	if v.Scanner != nil && v.Scanner.NVD != nil {
		v.Scanner.NVD.Set(url, key)
	}
	if v.Scanner != nil && v.Scanner.Exploits != nil {
		v.Scanner.Exploits.Set(kevURL, epssURL)
	}
	v.mu.Lock()
	v.report = nil
	v.mu.Unlock()
}

// The Vulnerabilities page.
func (s *Server) routeVulns(api *router) {
	// Analysts see what the scans found and which networks are scanned.
	api.analyst("GET /api/vulns", s.handleVulns)
	api.analyst("GET /api/vulns/hosts/{id}", s.handleVulnHost)
	// The setup check names programs and paths on the server; choosing
	// what to scan, and scanning, are for admins.
	api.admin("GET /api/vulns/setup", s.handleVulnSetup)
	api.admin("GET /api/vulns/scanners", s.handleVulnScanners)
	// What is scanned, and which logins are sent to it: the password is
	// asked again, as a login sent to a host someone added hands that
	// host the login.
	api.sensitive("PUT /api/vulns/settings", s.handleSaveVulnSettings)
	api.admin("POST /api/vulns/networks/{id}/scan", s.handleVulnScanNow)
	api.admin("POST /api/vulns/scans/{id}/stop", s.handleVulnStop)
}

func (s *Server) vulnsMissing(w http.ResponseWriter) bool {
	if s.Vulns == nil || s.Vulns.Store == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("vulnerability scanning is not running on this server"))
		return true
	}
	return false
}

// scansHere reports whether this server runs the scans.
func (s *Server) scansHere() bool { return s.Cluster == nil || s.Cluster.RunsJobs() }

// vulnTarget is a network as the page shows it.
type vulnTarget struct {
	vulnscan.Target
	NextRun  time.Time      `json:"next_run,omitzero"`
	LastScan *vulnscan.Scan `json:"last_scan,omitempty"`
	// Active is the scan queued or running now.
	Active *vulnscan.Scan  `json:"active,omitempty"`
	Hosts  int             `json:"hosts"`
	Counts vulnscan.Counts `json:"counts"`
}

// vulnHostRow is a host in the list, without its services.
type vulnHostRow struct {
	ID         string          `json:"id"`
	TargetID   string          `json:"target_id"`
	TargetName string          `json:"target_name"`
	Address    string          `json:"address"`
	Hostname   string          `json:"hostname,omitempty"`
	Vendor     string          `json:"vendor,omitempty"`
	Counts     vulnscan.Counts `json:"counts"`
	MaxCVSS    float64         `json:"max_cvss"`
	Ports      []int           `json:"ports"`
	TopCVE     string          `json:"top_cve,omitempty"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	if s.vulnsMissing(w) {
		return
	}
	ctx := r.Context()
	set, v, err := s.Vulns.Store.Settings(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	scans, err := s.Vulns.Store.Scans(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	hosts, err := s.Vulns.Store.Hosts(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	now := time.Now()
	targets := make([]vulnTarget, 0, len(set.Targets))
	byTarget := map[string]int{}
	for i, t := range set.Targets {
		vt := vulnTarget{Target: t}
		if t.Enabled {
			vt.NextRun = t.Schedule.NextSlot(now, nil)
		}
		targets = append(targets, vt)
		byTarget[t.ID] = i
	}
	for _, sc := range scans { // newest first
		i, ok := byTarget[sc.TargetID]
		if !ok {
			continue
		}
		switch sc.State {
		case vulnscan.StateQueued, vulnscan.StateRunning:
			if targets[i].Active == nil {
				targets[i].Active = sc
			}
		default:
			if targets[i].LastScan == nil {
				targets[i].LastScan = sc
			}
		}
	}
	var total vulnscan.Counts
	rows := make([]vulnHostRow, 0, len(hosts))
	for _, h := range hosts {
		row := vulnHostRow{ID: h.ID, TargetID: h.TargetID, TargetName: h.TargetName, Address: h.Address, Hostname: h.Hostname,
			Vendor: h.Vendor, Counts: h.Counts, MaxCVSS: h.MaxCVSS, Ports: []int{}, FirstSeen: h.FirstSeen, LastSeen: h.LastSeen}
		for _, svc := range h.Services {
			row.Ports = append(row.Ports, svc.Port)
			for _, vu := range svc.Vulns {
				if row.TopCVE == "" {
					row.TopCVE = vu.CVE
				}
			}
		}
		rows = append(rows, row)
		if i, ok := byTarget[h.TargetID]; ok {
			targets[i].Hosts++
			c := &targets[i].Counts
			c.Critical, c.High, c.Medium, c.Low, c.KEV = c.Critical+h.Counts.Critical, c.High+h.Counts.High, c.Medium+h.Counts.Medium, c.Low+h.Counts.Low, c.KEV+h.Counts.KEV
			c.Services += h.Counts.Services
		}
		total.Hosts++
		total.Services += h.Counts.Services
		total.Critical += h.Counts.Critical
		total.High += h.Counts.High
		total.Medium += h.Counts.Medium
		total.Low += h.Counts.Low
		total.KEV += h.Counts.KEV
		total.Likely += h.Counts.Likely
	}
	recent := scans
	if len(recent) > 30 {
		recent = recent[:30]
	}
	out := map[string]any{
		"settings": set, "version": v.String(), "targets": targets, "hosts": rows, "totals": total, "scans": recent,
		"scans_here": s.scansHere(),
	}
	if x := s.Vulns.Scanner; x != nil && x.Exploits != nil {
		kev, epss := x.Exploits.Status(ctx)
		out["exploits"] = map[string]any{"kev": kev, "epss": epss, "likely_epss": vulnscan.LikelyEPSS}
	}
	reports, err := s.Vulns.Store.Reports(ctx)
	if err != nil {
		reports = nil
	}
	servers := s.vulnServers(set, reports, false)
	out["servers"] = servers
	// Whether scans can run, without the checks: they name programs,
	// paths and OpenVAS's address, which are for admins (GET
	// /api/vulns/setup).
	if rep := jobsReport(servers, reports); rep != nil {
		out["scanner"] = map[string]any{"server": rep.Server, "ready": rep.Ready}
	}
	writeJSON(w, http.StatusOK, out)
}

// vulnServer is a server as a scanner: whether it is ready to scan and
// the networks it scans.
type vulnServer struct {
	// ID is its node ID, which a network names as its scanner; "" for
	// this server when it is on its own.
	ID       string `json:"id"`
	Name     string `json:"name"`
	Self     bool   `json:"self"`
	State    string `json:"state"`
	Online   bool   `json:"online"`
	RunsJobs bool   `json:"runs_jobs"`
	// Scanner is true for a server added as a scanner (cluster.role).
	Scanner bool `json:"scanner,omitempty"`
	// Ready is nil until the server has checked itself.
	Ready     *bool         `json:"ready,omitempty"`
	CheckedAt time.Time     `json:"checked_at,omitzero"`
	Networks  []vulnNetwork `json:"networks"`
	// Report is its latest check of itself, for the Scanners page.
	Report *vulnscan.Report `json:"report,omitempty"`
}

type vulnNetwork struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// stateRemoved is a server a network names as its scanner that is no
// longer among the servers.
const stateRemoved = "removed"

// vulnServers lists the servers that can scan: every server that shares
// this OpenSearch, and any server a network still names that has since
// been removed. full adds each one's latest check of itself.
func (s *Server) vulnServers(set vulnscan.Settings, reports []*vulnscan.Report, full bool) []vulnServer {
	byNode := map[string]*vulnscan.Report{}
	byName := map[string]*vulnscan.Report{}
	for _, r := range reports { // newest first
		if r.NodeID != "" && byNode[r.NodeID] == nil {
			byNode[r.NodeID] = r
		}
		if byName[r.Server] == nil {
			byName[r.Server] = r
		}
	}
	var out []vulnServer
	if s.Cluster == nil {
		sv := vulnServer{Name: "This server", Self: true, State: cluster.StateReady, Online: true, RunsJobs: true}
		if len(reports) > 0 {
			sv.Name = reports[0].Server
		}
		out = append(out, sv)
	} else {
		for _, st := range s.Cluster.Status().Servers {
			sv := vulnServer{ID: st.NodeID, Name: st.Name, Self: st.Self, State: st.State, RunsJobs: st.Jobs == "runs"}
			if st.Detail != nil {
				sv.Scanner = st.Detail.Role == cluster.RoleScanner
			}
			switch st.State {
			case cluster.StateReady, cluster.StateStarting, cluster.StateDraining:
				sv.Online = true
			}
			out = append(out, sv)
		}
	}
	known := map[string]bool{}
	for _, sv := range out {
		known[sv.ID] = true
	}
	for _, t := range set.Targets {
		if t.Scanner != "" && !known[t.Scanner] {
			known[t.Scanner] = true
			sv := vulnServer{ID: t.Scanner, Name: "A removed server", State: stateRemoved}
			if r := byNode[t.Scanner]; r != nil {
				sv.Name = r.Server
			}
			out = append(out, sv)
		}
	}
	for i := range out {
		sv := &out[i]
		sv.Networks = []vulnNetwork{}
		for _, t := range set.Targets {
			if t.Scanner == sv.ID || (t.Scanner == "" && sv.RunsJobs && sv.State != stateRemoved) {
				sv.Networks = append(sv.Networks, vulnNetwork{ID: t.ID, Name: t.Name, Enabled: t.Enabled})
			}
		}
		r := byNode[sv.ID]
		if r == nil && s.Cluster == nil && len(reports) > 0 {
			r = reports[0]
		}
		if r == nil && sv.State != stateRemoved {
			// From a version before per-zone scanners.
			if old := byName[sv.Name]; old != nil && old.NodeID == "" {
				r = old
			}
		}
		if r != nil {
			ready := r.Ready
			sv.Ready, sv.CheckedAt = &ready, r.At
			if full {
				sv.Report = r
			}
		}
	}
	return out
}

// jobsReport is the latest check of the server that runs the background
// jobs, which scans the networks that name no scanner.
func jobsReport(servers []vulnServer, reports []*vulnscan.Report) *vulnscan.Report {
	for _, sv := range servers {
		if !sv.RunsJobs {
			continue
		}
		for _, r := range reports {
			if (sv.ID != "" && r.NodeID == sv.ID) || (r.NodeID == "" && r.Server == sv.Name) {
				return r
			}
		}
	}
	if len(reports) > 0 && len(servers) <= 1 {
		return reports[0]
	}
	return nil
}

// handleVulnScanners lists every server as a scanner, with its checks:
// the Settings > Scanners page. fresh=1 checks this server again first.
func (s *Server) handleVulnScanners(w http.ResponseWriter, r *http.Request) {
	if s.vulnsMissing(w) {
		return
	}
	ctx := r.Context()
	if r.URL.Query().Get("fresh") == "1" && s.Vulns.Scanner != nil {
		cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		rep := s.Vulns.Scanner.CheckNow(cctx)
		cancel()
		s.Vulns.mu.Lock()
		s.Vulns.report = rep
		s.Vulns.mu.Unlock()
	}
	set, _, err := s.Vulns.Store.Settings(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	reports, err := s.Vulns.Store.Reports(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": s.vulnServers(set, reports, true),
		"offline_after_seconds": int(vulnscan.OfflineAfter / time.Second)})
}

func (s *Server) handleVulnHost(w http.ResponseWriter, r *http.Request) {
	if s.vulnsMissing(w) {
		return
	}
	h, err := s.Vulns.Store.Host(r.Context(), r.PathValue("id"))
	if errors.Is(err, vulnscan.ErrNotFound) {
		writeError(w, http.StatusNotFound, errors.New("no such host; a newer scan may not have found it"))
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": h})
}

// setupFresh is how long a check of this server is shown before it is
// run again, unless the page asks for a fresh one.
const setupFresh = 30 * time.Second

func (s *Server) handleVulnSetup(w http.ResponseWriter, r *http.Request) {
	if s.vulnsMissing(w) {
		return
	}
	here := s.scansHere() && s.Vulns.Scanner != nil
	if here {
		s.Vulns.mu.Lock()
		rep := s.Vulns.report
		s.Vulns.mu.Unlock()
		if rep == nil || r.URL.Query().Get("fresh") == "1" || time.Since(rep.At) > setupFresh {
			ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
			rep = s.Vulns.Scanner.CheckNow(ctx)
			cancel()
			s.Vulns.mu.Lock()
			s.Vulns.report = rep
			s.Vulns.mu.Unlock()
		}
		writeJSON(w, http.StatusOK, map[string]any{"report": rep, "here": true})
		return
	}
	// Another server runs the scans: show its latest check of itself.
	reports, err := s.Vulns.Store.Reports(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	out := map[string]any{"here": false}
	if s.Cluster != nil {
		out["scanner_server"] = s.Cluster.JobHolder()
	}
	set, err := s.Vulns.Store.CachedSettings(r.Context())
	if err != nil {
		set = vulnscan.DefaultSettings()
	}
	if rep := jobsReport(s.vulnServers(set, reports, false), reports); rep != nil {
		out["report"] = rep
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSaveVulnSettings(w http.ResponseWriter, r *http.Request) {
	if s.vulnsMissing(w) {
		return
	}
	var req struct {
		Settings vulnscan.Settings `json:"settings"`
		Version  string            `json:"version"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	saved, cur, err := s.Vulns.Store.Settings(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	conflict := errors.New("someone else changed the scan settings since you opened them; reload to see their changes")
	if req.Version != cur.String() {
		writeError(w, http.StatusConflict, conflict)
		return
	}
	if err := s.checkScanners(req.Settings, saved); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Vulns.Store.CheckLogins(r.Context(), req.Settings); err != nil {
		var bad *vulnscan.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err)
		} else {
			writeError(w, http.StatusBadGateway, err)
		}
		return
	}
	set, err := s.Vulns.Store.SaveSettings(r.Context(), req.Settings, cur, userOf(r))
	if err != nil {
		var bad *vulnscan.InputError
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, conflict)
		case errors.As(err, &bad):
			writeError(w, http.StatusBadRequest, err)
		default:
			writeError(w, http.StatusBadGateway, err)
		}
		return
	}
	nets := make([]string, 0, len(set.Targets))
	for _, t := range set.Targets {
		nets = append(nets, t.Name)
	}
	s.audit(r, "vulnerability scan settings saved", "networks", nets, "cve_lookup", set.CVELookup, "changes", vulnChanges(saved, set))
	s.handleVulns(w, r)
}

// checkScanners makes sure every network's scanner is one of the
// servers. A network may keep a scanner that has since been removed, so
// that its other settings can still be changed.
func (s *Server) checkScanners(next, saved vulnscan.Settings) error {
	known := map[string]bool{}
	if s.Cluster != nil {
		for _, st := range s.Cluster.Status().Servers {
			known[st.NodeID] = true
		}
	}
	before := map[string]string{}
	for _, t := range saved.Targets {
		before[t.ID] = t.Scanner
	}
	for _, t := range next.Targets {
		sc := strings.TrimSpace(t.Scanner)
		if sc == "" || known[sc] || before[t.ID] == sc {
			continue
		}
		return fmt.Errorf("%s: the server picked to scan it is not one of this Signalith's servers; reload the page and pick another", t.Name)
	}
	return nil
}

// scannerOffline says why the server that scans t cannot start a scan
// now, or "".
func (s *Server) scannerOffline(t vulnscan.Target) string {
	if t.Scanner == "" || s.Cluster == nil {
		return ""
	}
	for _, st := range s.Cluster.Status().Servers {
		if st.NodeID != t.Scanner {
			continue
		}
		switch st.State {
		case cluster.StateReady, cluster.StateStarting, cluster.StateDraining:
			return ""
		}
		return st.Name + ", the server that scans this network, is " + st.State + ". Start Signalith there, or edit the network and pick another scanner."
	}
	return "The server that scanned this network was removed. Edit the network and pick another scanner."
}

func (s *Server) handleVulnScanNow(w http.ResponseWriter, r *http.Request) {
	if s.vulnsMissing(w) {
		return
	}
	set, _, err := s.Vulns.Store.Settings(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	var target *vulnscan.Target
	for i := range set.Targets {
		if set.Targets[i].ID == r.PathValue("id") {
			target = &set.Targets[i]
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, errors.New("no such network; it may have been removed"))
		return
	}
	if why := s.scannerOffline(*target); why != "" {
		writeError(w, http.StatusConflict, errors.New(why))
		return
	}
	scans, err := s.Vulns.Store.Scans(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	for _, sc := range scans {
		if sc.TargetID == target.ID && (sc.State == vulnscan.StateQueued || sc.State == vulnscan.StateRunning) {
			writeError(w, http.StatusConflict, errors.New("this network is already being scanned or waiting to be"))
			return
		}
	}
	sc, err := s.Vulns.Store.NewScan(r.Context(), *target, vulnscan.TriggerManual, userOf(r))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.audit(r, "vulnerability scan requested", "network", target.Name, "scan", sc.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"scan": sc})
}

func (s *Server) handleVulnStop(w http.ResponseWriter, r *http.Request) {
	if s.vulnsMissing(w) {
		return
	}
	sc, _, err := s.Vulns.Store.Scan(r.Context(), r.PathValue("id"))
	if errors.Is(err, vulnscan.ErrNotFound) {
		writeError(w, http.StatusNotFound, errors.New("no such scan"))
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if sc.State != vulnscan.StateQueued && sc.State != vulnscan.StateRunning {
		writeError(w, http.StatusConflict, errors.New("the scan has already ended"))
		return
	}
	if err := s.Vulns.Store.UpdateScan(r.Context(), sc.ID, map[string]any{"stop": true, "stop_by": userOf(r)}); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.audit(r, "vulnerability scan stopped", "network", sc.TargetName, "scan", sc.ID)
	writeJSON(w, http.StatusOK, map[string]any{"stopping": sc.ID})
}

// vulnChanges says what a save changed in each network: what it scans
// and skips, its scanner and the logins it sends, for the audit log.
func vulnChanges(before, after vulnscan.Settings) []string {
	old := map[string]vulnscan.Target{}
	for _, t := range before.Targets {
		old[t.ID] = t
	}
	list := func(v []string) string {
		if len(v) == 0 {
			return "none"
		}
		return strings.Join(v, ",")
	}
	or := func(v string) string {
		if v == "" {
			return "none"
		}
		return v
	}
	var out []string
	for _, t := range after.Targets {
		p, ok := old[t.ID]
		delete(old, t.ID)
		if !ok {
			out = append(out, fmt.Sprintf("%s added: scans %s, skips %s, scanner %s, SSH login %s, Windows login %s",
				t.Name, list(t.Networks), list(t.Exclude), or(t.Scanner), or(t.SSHLogin), or(t.SMBLogin)))
			continue
		}
		for _, d := range []struct{ what, was, now string }{
			{"addresses", list(p.Networks), list(t.Networks)},
			{"skipped addresses", list(p.Exclude), list(t.Exclude)},
			{"scanner", or(p.Scanner), or(t.Scanner)},
			{"OpenVAS", fmt.Sprint(p.OpenVAS), fmt.Sprint(t.OpenVAS)},
			{"SSH login", or(p.SSHLogin), or(t.SSHLogin)},
			{"Windows login", or(p.SMBLogin), or(t.SMBLogin)},
		} {
			if d.was != d.now {
				out = append(out, fmt.Sprintf("%s: %s %s -> %s", t.Name, d.what, d.was, d.now))
			}
		}
	}
	for _, t := range before.Targets {
		if _, gone := old[t.ID]; gone {
			out = append(out, t.Name+" removed")
		}
	}
	return out
}
