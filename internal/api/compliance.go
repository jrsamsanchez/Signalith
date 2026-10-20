// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/compliance"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/endpoint/checks"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/users"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// Compliance: how detections, data, checks and settings map to the
// controls of common frameworks, and an evidence report to export. Every
// signed-in user may read it, so an auditor can have a Viewer account;
// only admins write notes on controls. See docs/compliance.md.
func (s *Server) routeCompliance(api *router) {
	api.viewer("GET /api/compliance", s.handleCompliance)
	api.viewer("GET /api/compliance/export", s.handleComplianceExport)
	api.admin("PUT /api/compliance/notes", s.handleComplianceNote)
}

// complianceState caches the snapshot of the system the report is worked
// out from, which takes a few searches, and keeps this server's own notes
// on controls (see complianceNotes).
type complianceState struct {
	once  sync.Once
	local *compliance.Notes

	mu   sync.Mutex
	snap *compliance.Snapshot
	at   time.Time
}

// complianceTTL is how long a snapshot is reused.
const complianceTTL = time.Minute

func (s *Server) compliance() *complianceState {
	c := &s.comp
	c.once.Do(func() {
		path := ""
		if dir := s.conf().StateDir(); dir != "" {
			path = filepath.Join(dir, compliance.NotesFile)
		}
		c.local = compliance.NewNotes(path)
	})
	return c
}

// complianceNotes is where the notes on controls are kept: the shared
// settings once this server takes its content from them, so every server
// shows the same notes, else this server's file.
func (s *Server) complianceNotes() compliance.NoteStore {
	if s.ComplianceNotes != nil && s.sharedContent() {
		return s.ComplianceNotes
	}
	return s.compliance().local
}

func (s *Server) complianceReport(r *http.Request) *compliance.Report {
	c := s.compliance()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.snap == nil || r.URL.Query().Get("fresh") == "1" || time.Since(c.at) > complianceTTL {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		c.snap = s.complianceSnapshot(ctx, r)
		cancel()
		c.at = time.Now()
	}
	notes := s.complianceNotes()
	rep := compliance.Evaluate(c.snap, notes.All())
	if err := notes.Err(); err != nil {
		rep.Notes = append(rep.Notes, "The notes on controls could not be read: "+err.Error())
	}
	return rep
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	rep := s.complianceReport(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"generated":    rep.Generated,
		"server":       s.serverName(),
		"frameworks":   rep.Frameworks,
		"capabilities": rep.Capabilities,
		"notes":        rep.Notes,
	})
}

// handleComplianceExport answers GET api/compliance/export?framework=&format=
// with a CSV file or an HTML report to print or save as PDF.
func (s *Server) handleComplianceExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fw := q.Get("framework")
	if _, ok := compliance.FrameworkByID(fw); !ok {
		writeError(w, http.StatusBadRequest, errors.New("framework must be one of "+strings.Join(frameworkIDs(), ", ")))
		return
	}
	format := q.Get("format")
	if format != "csv" && format != "html" {
		writeError(w, http.StatusBadRequest, errors.New(`format must be "csv" or "html"`))
		return
	}
	rep := s.complianceReport(r)
	f, _ := rep.Find(fw)
	server := s.serverName()
	name := "signalith-" + fw + "-evidence-" + rep.Generated.UTC().Format("2006-01-02")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		_ = compliance.WriteCSV(w, rep, f, server)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if q.Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.html"`)
	}
	_ = compliance.WriteHTML(w, rep, f, server, s.Version)
}

func frameworkIDs() []string {
	var ids []string
	for _, f := range compliance.Frameworks() {
		ids = append(ids, f.ID)
	}
	return ids
}

// handleComplianceNote answers PUT api/compliance/notes: an admin marks a
// control as handled outside Signalith or not applicable, with a note, or
// removes the mark with an empty status.
func (s *Server) handleComplianceNote(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Framework string            `json:"framework"`
		Control   string            `json:"control"`
		Status    compliance.Status `json:"status"`
		Note      string            `json:"note"`
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	by := userOf(r)
	a, err := s.complianceNotes().Set(r.Context(), in.Framework, in.Control, in.Status, in.Note, by, time.Now())
	var ie *compliance.InputError
	switch {
	case errors.As(err, &ie):
		writeError(w, http.StatusBadRequest, err)
		return
	case sharedError(w, err):
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.Log.Info("compliance note changed", "framework", in.Framework, "control", in.Control, "status", string(in.Status), "by", by)
	writeJSON(w, http.StatusOK, map[string]any{"attestation": a})
}

// complianceSnapshot gathers what the report needs. Parts that are off or
// fail are left nil, which the report shows as missing.
func (s *Server) complianceSnapshot(ctx context.Context, r *http.Request) *compliance.Snapshot {
	now := time.Now().UTC()
	snap := &compliance.Snapshot{Now: now, Data: map[string]compliance.DataSeen{}, Assets: -1}
	conf := s.conf()
	snap.HTTPS = conf.Server.HTTPS() || s.overHTTPS(r)
	snap.MFA = conf.MFARequiredMode()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.complianceData(ctx, snap)
	}()

	if s.Detections != nil {
		snap.Detections = complianceDetections(s.Detections.List())
		snap.SchedulerOn = conf.Detections.Scheduler
	}
	if s.Endpoints != nil {
		s.complianceChecks(ctx, snap)
	}
	if s.Vulns != nil && s.Vulns.Store != nil {
		v := &compliance.Vulns{}
		if set, err := s.Vulns.Store.CachedSettings(ctx); err == nil {
			v.Networks = len(set.Targets)
		}
		if scans, err := s.Vulns.Store.Scans(ctx); err == nil {
			for _, sc := range scans {
				if sc.State == vulnscan.StateDone && sc.FinishedAt.After(v.LastScan) {
					v.LastScan = sc.FinishedAt
				}
			}
			snap.Vulns = v
		}
	}
	if s.Findings != nil {
		if sum, err := s.Findings.Summary(ctx); err == nil {
			f := &compliance.Findings{Open: sum.Open, New: sum.ByStatus[findings.StatusNew]}
			if _, recent, err := s.Findings.Search(ctx, findings.Filter{Status: []string{findings.StatusNew}, Since: now.Add(-compliance.TriageWindow), Limit: 1}); err == nil {
				f.Stale = max(0, f.New-recent)
			}
			snap.Findings = f
		}
	}
	if s.Cases != nil {
		_, total, err1 := s.Cases.Search(ctx, cases.Filter{Limit: 1})
		_, open, err2 := s.Cases.Search(ctx, cases.Filter{Status: cases.OpenStatuses, Limit: 1})
		if err1 == nil && err2 == nil {
			snap.Cases = &compliance.Cases{Total: total, Open: open}
		}
	}
	if s.Notify != nil && s.Notify.Settings != nil {
		if set, err := s.Notify.Settings.Settings(); err == nil {
			n := &compliance.Notify{Channels: len(set.Channels)}
			for _, rule := range set.Rules {
				if rule.Enabled && len(rule.Channels) > 0 {
					n.Rules++
				}
			}
			snap.Notify = n
		}
	}
	if s.Respond != nil {
		if infos, err := s.Respond.Infos(); err == nil {
			rs := &compliance.Response{}
			for _, in := range infos {
				if in.Problem == "" {
					rs.Actions++
				}
			}
			if s.Playbooks != nil && s.Playbooks.Manager != nil {
				if pbs, err := s.Playbooks.Manager.List(); err == nil {
					rs.Playbooks = len(pbs)
				}
			}
			snap.Response = rs
		}
	}
	if s.Feeds != nil {
		in := &compliance.Intel{}
		for _, f := range s.Feeds.Status() {
			if !f.Enabled {
				continue
			}
			in.Feeds++
			if !f.Status.LastSuccess.IsZero() && now.Sub(f.Status.LastSuccess) <= 7*24*time.Hour {
				in.Fresh++
			}
		}
		snap.Intel = in
	}
	if s.Retention != nil {
		if set, err := s.Retention.Settings(); err == nil {
			rt := &compliance.Retention{KeepDays: set.Default.KeepDays, Archive: set.Default.Archive, MaxSizeGB: set.Default.MaxSizeGB, Guard: set.Guard.IsEnabled()}
			for _, c := range retention.Categories() {
				p, ok := set.Policies[c.ID]
				if !ok || c.Kind != retention.KindEvents || c.ID == strings.ToLower(datamodel.RiskModel) {
					continue
				}
				if p.KeepDays > 0 && (rt.KeepDays == 0 || p.KeepDays < rt.KeepDays) && !p.Archive {
					rt.Shorter = append(rt.Shorter, c.Name+" ("+strconv.Itoa(p.KeepDays)+" days)")
				}
			}
			snap.Retention = rt
		}
	}
	if s.Users != nil {
		u := &compliance.Users{}
		for _, x := range s.Users.List() {
			if x.Source != users.SourceBuiltin && !x.Disabled {
				u.Named++
			}
		}
		u.Directory = s.Directory != nil && s.Directory.Enabled()
		snap.Users = u
	}
	if s.Assets != nil {
		snap.Assets = len(s.Assets.Assets()) + len(s.Assets.Identities())
	}
	wg.Wait()
	return snap
}

// complianceData counts each data model's events in the last week, not
// counting sample data.
func (s *Server) complianceData(ctx context.Context, snap *compliance.Snapshot) {
	if s.Engine == nil {
		snap.DataErr = "search is not available"
		return
	}
	q, err := query.Parse("NOT " + datamodel.SampleField + "=* | stats count, max(_time) as last_seen by datamodel")
	if err != nil {
		snap.DataErr = err.Error()
		return
	}
	q.Earliest = "-7d"
	res, err := s.Engine.Execute(ctx, q)
	if err != nil {
		snap.DataErr = err.Error()
		return
	}
	for _, row := range res.Rows {
		m, _ := row["datamodel"].(string)
		if m == "" {
			continue
		}
		d := compliance.DataSeen{Count: int64(cellNumber(row["count"]))}
		if sec := cellNumber(row["last_seen"]); sec > 0 {
			d.Last = time.Unix(0, int64(sec*1e9)).UTC()
		}
		snap.Data[m] = d
	}
}

// cellNumber reads a numeric search result cell; anything else is 0.
func cellNumber(v any) float64 {
	if f, ok := toFloat(v); ok {
		return f
	}
	var f float64
	switch n := v.(type) {
	case json.Number:
		f, _ = n.Float64()
	case string:
		f, _ = strconv.ParseFloat(strings.TrimSpace(n), 64)
	}
	return f
}

// complianceDetections reads each detection's data models and ATT&CK
// tactics.
func complianceDetections(list []*detect.Detection) []compliance.Detection {
	cat := detect.ATTACK()
	out := make([]compliance.Detection, 0, len(list))
	for _, d := range list {
		cd := compliance.Detection{ID: d.ID, Name: d.BaseTitle(), Enabled: d.Enabled, Tags: d.Tags}
		if q, err := query.Parse(d.Query); err == nil && q.Datamodel != "" {
			if m, ok := datamodel.Get(q.Datamodel); ok {
				cd.Models = []string{m.Name}
			}
		}
		for _, t := range d.MITRE {
			tech, ok := cat.Technique(t)
			if !ok && strings.Contains(t, ".") {
				tech, ok = cat.Technique(t[:strings.Index(t, ".")])
			}
			if !ok {
				continue
			}
			for _, ta := range tech.Tactics {
				if !slices.Contains(cd.Tactics, ta) {
					cd.Tactics = append(cd.Tactics, ta)
				}
			}
		}
		out = append(out, cd)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// complianceChecks sums up each configuration check's latest results
// across the hosts of its platform.
func (s *Server) complianceChecks(ctx context.Context, snap *compliance.Snapshot) {
	nodes, err := s.Endpoints.Nodes(ctx)
	if err != nil {
		return
	}
	all, err := s.Endpoints.Checks(ctx)
	if err != nil {
		return
	}
	byPlatform := map[string]int{}
	for _, n := range nodes {
		byPlatform[n.Platform]++
	}
	snap.Hosts = len(nodes)
	snap.Checks = []compliance.CheckStat{}
	for _, c := range checks.All() {
		st := compliance.CheckStat{ID: c.ID, Title: c.Title, Platform: c.Platform, Refs: c.References}
		for _, n := range nodes {
			if n.Platform != c.Platform {
				continue
			}
			res, ok := all[n.ID].Results[c.ID]
			if !ok {
				st.Pending++
				continue
			}
			switch res.Result {
			case "pass":
				st.Pass++
			case "fail":
				st.Fail++
				st.Failing = append(st.Failing, compliance.HostRef{ID: n.ID, Hostname: cmp.Or(n.Hostname, n.HostIdentifier, n.ID)})
			case "n/a":
				st.NA++
			default:
				st.Error++
			}
		}
		snap.Checks = append(snap.Checks, st)
	}
}
