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
	"sync/atomic"
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

	// sawHTTPS is whether the page was last read over HTTPS, for the
	// monthly record, which no request asks for (see compliancehist.go).
	sawHTTPS atomic.Bool
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
	return s.complianceReportAt(r.Context(), r, r.URL.Query().Get("fresh") == "1")
}

// complianceReportAt works out the report; r is nil for the monthly
// record, which always takes a fresh snapshot.
func (s *Server) complianceReportAt(ctx context.Context, r *http.Request, fresh bool) *compliance.Report {
	c := s.compliance()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.snap == nil || fresh || time.Since(c.at) > complianceTTL {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
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
	x := compliance.Export{Server: s.serverName(), Version: s.Version, By: userOf(r)}
	name := "signalith-" + fw + "-evidence-" + rep.Generated.UTC().Format("2006-01-02")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		if err := compliance.WriteCSV(w, rep, f, x); err != nil {
			s.Log.Warn("compliance: the CSV export was cut short", "framework", fw, "err", err)
		}
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if q.Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.html"`)
	}
	if err := compliance.WriteHTML(w, rep, f, x); err != nil {
		s.Log.Warn("compliance: the report export failed", "framework", fw, "err", err)
	}
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
	// "Handled outside Signalith" is for controls Signalith has no
	// evidence for; on one it has, a note would only hide what it found.
	if in.Status == compliance.External {
		if f, ok := s.complianceReport(r).Find(in.Framework); ok {
			for _, c := range f.Controls {
				if c.ID == in.Control && c.Computed == compliance.Met {
					writeError(w, http.StatusBadRequest, errors.New("Signalith already has evidence for this control, so it cannot be noted as handled outside Signalith."))
					return
				}
			}
		}
	}
	by := userOf(r)
	prev, hadPrev := s.complianceNotes().All()[compliance.Key(in.Framework, in.Control)]
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
	attrs := []any{"audit", true, "by", by, "framework", in.Framework, "control", in.Control, "status", string(in.Status), "note", strings.TrimSpace(in.Note)}
	if hadPrev {
		attrs = append(attrs, "previous_status", string(prev.Status), "previous_note", prev.Note, "previous_by", prev.By)
	}
	s.Log.Info("compliance.note: compliance note changed", slices.Concat(attrs, s.client(r).logAttrs())...)
	writeJSON(w, http.StatusOK, map[string]any{"attestation": a})
}

// complianceSnapshot gathers what the report needs. Parts that are off or
// fail are left nil, which the report shows as missing.
func (s *Server) complianceSnapshot(ctx context.Context, r *http.Request) *compliance.Snapshot {
	now := time.Now().UTC()
	snap := &compliance.Snapshot{Now: now, Data: map[string]compliance.DataSeen{}, Assets: -1}
	conf := s.conf()
	if r != nil {
		s.compliance().sawHTTPS.Store(s.overHTTPS(r))
	}
	snap.HTTPS = conf.Server.HTTPS() || s.compliance().sawHTTPS.Load()
	snap.MFA = conf.MFARequiredMode()
	if conf.Syslog.UDP != "" {
		snap.PlainSyslog = append(snap.PlainSyslog, "UDP "+conf.Syslog.UDP)
	}
	if conf.Syslog.TCP != "" {
		snap.PlainSyslog = append(snap.PlainSyslog, "TCP "+conf.Syslog.TCP)
	}

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
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.complianceComputers(ctx, snap)
	}()
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
			for _, n := range sum.ByStatus {
				f.Total += n
			}
			f.Reviewed = f.Total - f.New
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
				if c.Kind == retention.KindRecords {
					if p, _ := set.For(c.ID); p.KeepDays == 0 {
						rt.Longer = append(rt.Longer, c.Name+" (kept forever)")
					}
					continue
				}
				p, ok := set.Policies[c.ID]
				if ok && c.Kind == retention.KindEvents && rt.KeepDays > 0 && (p.KeepDays == 0 || p.KeepDays > rt.KeepDays) {
					if p.KeepDays == 0 {
						rt.Longer = append(rt.Longer, c.Name+" (kept forever)")
					} else {
						rt.Longer = append(rt.Longer, c.Name+" ("+strconv.Itoa(p.KeepDays)+" days)")
					}
				}
				if !ok || c.Kind != retention.KindEvents || c.ID == strings.ToLower(datamodel.RiskModel) {
					continue
				}
				if p.KeepDays > 0 && (rt.KeepDays == 0 || p.KeepDays < rt.KeepDays) && !p.Archive {
					rt.Shorter = append(rt.Shorter, c.Name+" ("+strconv.Itoa(p.KeepDays)+" days)")
				}
			}
			if ov := s.retentionOverview(ctx); ov != nil && ov.Error == "" {
				rt.OldestRead = true
				for _, c := range ov.Categories {
					if c.Kind != retention.KindEvents || c.ID == strings.ToLower(datamodel.RiskModel) || c.OldestDay == "" {
						continue
					}
					if d, err := time.Parse(time.DateOnly, c.OldestDay); err == nil && (rt.Oldest.IsZero() || d.Before(rt.Oldest)) {
						rt.Oldest = d
					}
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

// complianceComputers adds the computers whose agent sent in the data
// window to those that run osquery, and reads which hosts sent each data
// model every computer should send.
func (s *Server) complianceComputers(ctx context.Context, snap *compliance.Snapshot) {
	if s.Agents != nil {
		agents, _, err := s.Agents.List(ctx)
		if err != nil {
			s.Log.Warn("compliance: the agents could not be read", "err", err)
			snap.HostsErr = "the agents could not be read"
		}
		for _, a := range agents {
			if a.Name != "" && snap.Now.Sub(a.LastSeen) <= compliance.DataWindow {
				snap.Computers = append(snap.Computers, compliance.ShortHost(a.Name))
			}
		}
	}
	slices.Sort(snap.Computers)
	snap.Computers = slices.Compact(slices.DeleteFunc(snap.Computers, func(c string) bool { return c == "" }))
	if len(snap.Computers) == 0 || snap.HostsErr != "" {
		return
	}
	if s.Engine == nil {
		snap.HostsErr = "search is not available"
		return
	}
	snap.DataHosts = map[string]map[string]bool{}
	for _, m := range compliance.HostModels {
		q, err := query.Parse("datamodel=" + m + " NOT " + datamodel.SampleField + "=* | stats count by host")
		if err != nil {
			s.Log.Warn("compliance: the host search does not parse", "err", err)
			snap.HostsErr = "the search failed"
			return
		}
		q.Earliest = "-7d"
		q.MaxRows = complianceHostRows
		res, err := s.Engine.Execute(ctx, q)
		if err != nil {
			s.Log.Warn("compliance: could not read which hosts sent events", "model", m, "err", err)
			snap.HostsErr = "the search failed"
			return
		}
		if res.Truncated {
			snap.HostsErr = "more than " + strconv.Itoa(complianceHostRows) + " hosts sent " + m + " events"
			return
		}
		seen := map[string]bool{}
		for _, row := range res.Rows {
			if h, _ := row["host"].(string); h != "" {
				seen[compliance.ShortHost(h)] = true
			}
		}
		snap.DataHosts[m] = seen
	}
}

// complianceHostRows is the most hosts read for each data model.
const complianceHostRows = 100_000

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
	out := make([]compliance.Detection, 0, len(list))
	for _, d := range list {
		cd := compliance.Detection{ID: d.ID, Name: d.BaseTitle(), Enabled: d.Enabled, Tags: d.Tags}
		if q, err := query.Parse(d.Query); err == nil && q.Datamodel != "" {
			if m, ok := datamodel.Get(q.Datamodel); ok {
				cd.Models = []string{m.Name}
			}
		}
		for _, t := range d.MITRE {
			tech, ok := detect.AnyTechnique(t)
			if !ok && strings.Contains(t, ".") {
				tech, ok = detect.AnyTechnique(t[:strings.Index(t, ".")])
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
		if n.LastSeen.IsZero() {
			continue
		}
		if snap.HostsSeen[0].IsZero() || n.LastSeen.Before(snap.HostsSeen[0]) {
			snap.HostsSeen[0] = n.LastSeen
		}
		if n.LastSeen.After(snap.HostsSeen[1]) {
			snap.HostsSeen[1] = n.LastSeen
		}
	}
	snap.Hosts, snap.Platforms = len(nodes), byPlatform
	for _, n := range nodes {
		// A host gone for a week is likely retired.
		if snap.Now.Sub(n.LastSeen) <= compliance.DataWindow {
			snap.Computers = append(snap.Computers, compliance.ShortHost(cmp.Or(n.Hostname, n.HostIdentifier)))
		}
	}
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

// retentionOverview is the retention page's view of the stored data, for
// how far back events go; nil when retention cannot reach OpenSearch.
func (s *Server) retentionOverview(ctx context.Context) *retention.Overview {
	if s.Retention == nil || s.Retention.Cluster == nil {
		return nil
	}
	return s.Retention.Overview(ctx)
}
