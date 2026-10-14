package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

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

// The Vulnerabilities page.
func (s *Server) routeVulns(api *router) {
	// Analysts see what the scans found and which networks are scanned.
	api.analyst("GET /api/vulns", s.handleVulns)
	api.analyst("GET /api/vulns/hosts/{id}", s.handleVulnHost)
	// The setup check names programs and paths on the server; choosing
	// what to scan, and scanning, are for admins.
	api.admin("GET /api/vulns/setup", s.handleVulnSetup)
	api.admin("PUT /api/vulns/settings", s.handleSaveVulnSettings)
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
	}
	recent := scans
	if len(recent) > 30 {
		recent = recent[:30]
	}
	out := map[string]any{
		"settings": set, "version": v.String(), "targets": targets, "hosts": rows, "totals": total, "scans": recent,
		"scans_here": s.scansHere(),
	}
	if reports, err := s.Vulns.Store.Reports(ctx); err == nil && len(reports) > 0 {
		out["scanner"] = reports[0]
	}
	writeJSON(w, http.StatusOK, out)
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
	if len(reports) > 0 {
		out["report"] = reports[0]
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
	_, cur, err := s.Vulns.Store.Settings(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	conflict := errors.New("someone else changed the scan settings since you opened them; reload to see their changes")
	if req.Version != cur.String() {
		writeError(w, http.StatusConflict, conflict)
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
	s.audit(r, "vulnerability scan settings saved", "networks", nets, "cve_lookup", set.CVELookup)
	s.handleVulns(w, r)
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
