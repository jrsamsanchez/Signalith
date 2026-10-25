// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/geoip"
	"github.com/jrsamsanchez/signalith/internal/safelog"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// ifMatch returns the version a change was based on, from If-Match
// (quoted or not); "" when the request sent none.
func ifMatch(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	if u, err := strconv.Unquote(v); err == nil {
		return u
	}
	return v
}

func (s *Server) routeDetections(api *router) {
	api.viewer("GET /api/detections", s.handleListDetections)
	api.viewer("GET /api/detections/{id}", s.handleGetDetection)
	api.viewer("GET /api/detections/{id}/yaml", s.handleDetectionYAML)
	api.viewer("GET /api/coverage", s.handleCoverage)
	api.viewer("GET /api/detections/packs", s.handleListPacks)
	s.routeContent(api)
	// Writing, testing, importing and running detections is admin work;
	// a run raises findings.
	api.admin("POST /api/detections", s.handleCreateDetection)
	api.admin("POST /api/detections/test", s.handleTestDetection)
	s.routeDetectionDrafts(api)
	api.admin("POST /api/detections/sigma", s.handleSigma)
	api.admin("POST /api/detections/enable", s.handleEnableDetections)
	api.admin("PUT /api/detections/{id}", s.handlePutDetection)
	api.admin("DELETE /api/detections/{id}", s.handleDeleteDetection)
	api.admin("POST /api/detections/{id}/run", s.handleRunDetection)
	// Exceptions change what a detection raises, so they are admin work
	// too, including "don't alert on this again" from a finding.
	api.admin("POST /api/detections/{id}/exceptions", s.handleAddException)
	api.admin("DELETE /api/detections/{id}/exceptions/{exception}", s.handleDeleteException)
	api.admin("POST /api/findings/{id}/suppress", s.handleSuppressFinding)
	// Exceptions for many detections: every rule, a pack's or a tag's,
	// checked before each detection's own.
	api.viewer("GET /api/detections/exceptions", s.handleListScopedExceptions)
	api.admin("POST /api/detections/exceptions", s.handleAddScopedException)
	api.admin("DELETE /api/detections/exceptions/{exception}", s.handleDeleteScopedException)

	api.viewer("GET /api/findings", s.handleListFindings)
	api.viewer("GET /api/findings/summary", s.handleFindingsSummary)
	api.viewer("GET /api/findings/{id}", s.handleGetFinding)
	// Triage is analyst work.
	api.analyst("POST /api/findings", s.handleCreateFinding)
	api.analyst("POST /api/findings/bulk", s.handleBulkFindings)
	api.analyst("PATCH /api/findings/{id}", s.handleUpdateFinding)
}

var errDetectionsOff = errors.New("detections are not configured on this server")

// errNoGeoIP refuses to turn on a rule that runs iplocation on a server
// with no GeoIP database (DQ-03).
var errNoGeoIP = errors.New("this rule runs iplocation, which needs a GeoIP database, and this server has none, so every run would fail. " +
	"Add a GeoIP City database (.mmdb) to the geoip folder first (docs/lookups.md, GeoIP database for iplocation)")

// needsMissingGeoIP reports whether d runs iplocation on a server with no
// GeoIP database. A database still loading counts as there.
func (s *Server) needsMissingGeoIP(d *detect.Detection) bool {
	if !detect.NeedsGeoIP(d) || s.Engine == nil {
		return false
	}
	if s.Engine.GeoIP == nil {
		return true
	}
	_, err := s.Engine.GeoIP.Status()
	return errors.Is(err, geoip.ErrNoDatabase)
}

func (s *Server) detectionsReady(w http.ResponseWriter) bool {
	if s.Detections == nil || s.Scheduler == nil || s.Findings == nil {
		writeError(w, http.StatusServiceUnavailable, errDetectionsOff)
		return false
	}
	return true
}

// writeDetectionError maps library errors to status codes. Validation
// errors carry the full problem list so the form can show each one.
func writeDetectionError(w http.ResponseWriter, err error) {
	if libraryError(w, err) {
		return
	}
	var ve *detect.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "problems": ve.Problems})
	case errors.Is(err, detect.ErrNotFound):
		writeError(w, http.StatusNotFound, err)
	default:
		writeError(w, http.StatusBadRequest, err)
	}
}

// libraryError answers the errors of a change to the shared library: a
// change someone else made first (412, naming who, where and when), and
// changes paused on this server (503). It reports whether err was one.
func libraryError(w http.ResponseWriter, err error) bool {
	var stale *detect.StaleError
	if errors.As(err, &stale) {
		writeJSON(w, http.StatusPreconditionFailed, staleBody(err, &shared.StaleError{By: stale.By, Node: stale.Node, At: stale.At}))
		return true
	}
	return sharedError(w, err)
}

// savedDetection is a detection as a change returns it, with its version
// for If-Match on the next change.
type savedDetection struct {
	*detect.Detection
	ETag string `json:"etag"`
}

// detectionSaved answers a change with the detection as saved.
func (s *Server) detectionSaved(w http.ResponseWriter, status int, id string) {
	saved, err := s.Detections.Get(id)
	if err != nil {
		writeDetectionError(w, err)
		return
	}
	writeJSON(w, status, savedDetection{Detection: saved, ETag: s.Detections.ETag(id)})
}

type detectionView struct {
	*detect.Detection
	// ETag is the version of what was saved of the detection, for
	// If-Match on a change.
	ETag  string          `json:"etag,omitempty"`
	State detect.RunState `json:"state"`
	// StateError says the run state could not be read just now.
	StateError string `json:"state_error,omitempty"`
}

func (s *Server) handleListDetections(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	states, serr := s.Scheduler.StatusCtx(r.Context())
	ds := s.Detections.List()
	etags := s.Detections.ETags()
	out := make([]detectionView, 0, len(ds))
	for _, d := range ds {
		out = append(out, detectionView{Detection: d, ETag: etags[d.ID], State: states[d.ID]})
	}
	// scheduler says whether detections run on this server now; when they
	// run on another one, runs_on names it. The run state is shared, so
	// it is the same on every server.
	resp := map[string]any{"detections": out, "scheduler": s.conf().Detections.Scheduler}
	if s.Detections.Shared() {
		// Every server of the cluster reads and changes the same ones.
		resp["shared"] = true
	}
	if serr != nil {
		resp["state_error"] = "The run state of the detections could not be read just now, so what is shown may be out of date: " + serr.Error()
	}
	if s.Cluster != nil {
		resp["scheduler"] = s.conf().Detections.Scheduler && s.Cluster.RunsJobs()
		if !s.Cluster.RunsJobs() {
			resp["runs_on"] = s.Cluster.JobHolder()
			resp["scheduler_here"] = s.conf().Detections.Scheduler
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetDetection(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	d, err := s.Detections.Get(r.PathValue("id"))
	if err != nil {
		writeDetectionError(w, err)
		return
	}
	states, serr := s.Scheduler.StatusCtx(r.Context())
	v := detectionView{Detection: d, ETag: s.Detections.ETag(d.ID), State: states[d.ID]}
	if serr != nil {
		v.StateError = "The run state of this detection could not be read just now, so what is shown may be out of date: " + serr.Error()
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDetectionYAML(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	d, err := s.Detections.Get(r.PathValue("id"))
	if err != nil {
		writeDetectionError(w, err)
		return
	}
	data, err := detect.Encode(d)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+d.ID+`.yaml"`)
	_, _ = w.Write(data)
}

func (s *Server) handleCreateDetection(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var d detect.Detection
	if err := readJSON(r, &d); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if _, err := s.Detections.Get(d.ID); err == nil {
		writeError(w, http.StatusConflict, errors.New("a detection with id "+d.ID+" already exists"))
		return
	}
	// Saved only over nothing, so one made meanwhile on another server is
	// not overwritten.
	if err := s.Detections.PutIf(r.Context(), userOf(r), &d, detect.ETag(nil, nil)); err != nil {
		var stale *detect.StaleError
		if errors.As(err, &stale) {
			writeError(w, http.StatusConflict, errors.New("a detection with id "+d.ID+" already exists"))
			return
		}
		writeDetectionError(w, err)
		return
	}
	s.audit(r, "detection.create: detection created", "target", d.ID, "enabled", d.Enabled)
	s.detectionSaved(w, http.StatusCreated, d.ID)
}

func (s *Server) handlePutDetection(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var d detect.Detection
	if err := readJSON(r, &d); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if d.ID == "" {
		d.ID = r.PathValue("id")
	}
	if d.ID != r.PathValue("id") {
		writeError(w, http.StatusBadRequest, errors.New("id in the body does not match the URL"))
		return
	}
	if d.Enabled && s.needsMissingGeoIP(&d) {
		if cur, err := s.Detections.Get(d.ID); err != nil || !cur.Enabled {
			writeError(w, http.StatusConflict, errNoGeoIP)
			return
		}
	}
	// With If-Match, a change made since the page read the detection is
	// not overwritten: 412 names who made it.
	if err := s.Detections.PutIf(r.Context(), userOf(r), &d, ifMatch(r)); err != nil {
		writeDetectionError(w, err)
		return
	}
	s.audit(r, "detection.save: detection saved", "target", d.ID, "enabled", d.Enabled)
	s.detectionSaved(w, http.StatusOK, d.ID)
}

func (s *Server) handleDeleteDetection(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.Detections.DeleteIf(r.Context(), userOf(r), id, ifMatch(r)); err != nil {
		writeDetectionError(w, err)
		return
	}
	s.audit(r, "detection.delete: detection deleted", "target", id)
	// Deleting an override brings the built-in back; return what remains.
	if d, err := s.Detections.Get(id); err == nil {
		writeJSON(w, http.StatusOK, map[string]any{"deleted": false, "reverted": d})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// handleTestDetection runs an unsaved detection over its lookback window
// and returns the rows it would turn into findings.
func (s *Server) handleTestDetection(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var d detect.Detection
	if err := readJSON(r, &d); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if d.ID == "" {
		d.ID = "unsaved"
	}
	if d.Title == "" {
		d.Title = "Test"
	}
	d.Defaults()
	if err := d.Validate(); err != nil {
		writeDetectionError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	res, err := s.Scheduler.Preview(ctx, &d)
	if err != nil {
		writeSearchError(w, err)
		return
	}
	titles := make([]string, 0, min(len(res.Rows), 20))
	for _, row := range res.Rows[:min(len(res.Rows), 20)] {
		titles = append(titles, detect.RenderTitle(d.Title, row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": res, "titles": titles})
}

func (s *Server) handleRunDetection(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	d, err := s.Detections.Get(r.PathValue("id"))
	if err != nil {
		writeDetectionError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	res, err := s.Scheduler.RunManual(ctx, d, userOf(r))
	if err != nil {
		writeSearchError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleSigma converts a Sigma rule. The body is the rule's YAML, or JSON
// {"rule": "..."}. The result is not saved; the UI shows it for review.
func (s *Server) handleSigma(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	src := body
	if strings.HasPrefix(strings.TrimSpace(r.Header.Get("Content-Type")), "application/json") {
		var req struct {
			Rule string `json:"rule"`
		}
		if err := decodeJSON(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		src = []byte(req.Rule)
	}
	res, err := detect.ConvertSigma(src)
	if err != nil {
		writeDetectionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// packView is a content pack with how many of its rules are on.
type packView struct {
	*detect.Pack
	Rules      int            `json:"rules"`
	Enabled    int            `json:"enabled"`
	Severities map[string]int `json:"severities"`
}

func (s *Server) handleListPacks(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	ps, _, err := detect.Packs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	views := make([]*packView, 0, len(ps))
	byName := map[string]*packView{}
	for _, p := range ps {
		v := &packView{Pack: p, Severities: map[string]int{}}
		views = append(views, v)
		byName[p.Name] = v
	}
	for _, d := range s.Detections.List() {
		if d.Origin == nil {
			continue
		}
		if v := byName[d.Origin.Pack]; v != nil {
			v.Rules++
			v.Severities[d.Severity]++
			if d.Enabled {
				v.Enabled++
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": views})
}

// maxEnableIDs caps one request that turns detections on or off.
const maxEnableIDs = 5000

// handleEnableDetections turns many detections on or off at once, such
// as every high-severity rule of a content pack.
func (s *Server) handleEnableDetections(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var req struct {
		IDs     []string `json:"ids"`
		Enabled bool     `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > maxEnableIDs {
		writeError(w, http.StatusBadRequest, fmt.Errorf("send between 1 and %d detection ids", maxEnableIDs))
		return
	}
	// DQ-03: a rule that runs iplocation fails every run without a GeoIP
	// database, so it is left off until one is added.
	skipped := []string{}
	if req.Enabled {
		ids := req.IDs[:0:0]
		for _, id := range req.IDs {
			if d, err := s.Detections.Get(id); err == nil && !d.Enabled && s.needsMissingGeoIP(d) {
				skipped = append(skipped, id)
				continue
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			writeError(w, http.StatusConflict, errNoGeoIP)
			return
		}
		req.IDs = ids
	}
	if err := s.Detections.SetEnabledBy(r.Context(), userOf(r), req.IDs, req.Enabled); err != nil {
		writeDetectionError(w, err)
		return
	}
	s.audit(r, "detection.enable: detections turned "+map[bool]string{true: "on", false: "off"}[req.Enabled],
		"enabled", req.Enabled, "count", len(req.IDs), "detections", auditIDs(req.IDs), "skipped_geoip", len(skipped))
	writeJSON(w, http.StatusOK, map[string]any{"changed": len(req.IDs), "enabled": req.Enabled, "skipped_geoip": skipped})
}

func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, detect.ComputeCoverage(s.Detections.List()))
}

// ---- findings ----

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	v := r.URL.Query()
	flt := findings.Filter{
		Status:      splitList(v.Get("status")),
		Severity:    splitList(v.Get("severity")),
		Urgency:     splitList(v.Get("urgency")),
		Owner:       v.Get("owner"),
		DetectionID: v.Get("detection"),
		Text:        v.Get("q"),
		Unowned:     v.Get("unowned") == "true",
		Order:       v.Get("sort"),
	}
	if e := v.Get("entity"); e != "" {
		flt.EntityValues = []string{e}
	}
	sla := s.findingSLA()
	if due := v.Get("due"); due != "" {
		// due=overdue keeps findings late now; due=1h also those due
		// within the hour.
		var within time.Duration
		if due != "overdue" {
			d, err := detect.ParseDuration(due)
			if err != nil || d < 0 || d > 7*24*time.Hour {
				writeError(w, http.StatusBadRequest, errors.New("due must be overdue or a time up to 7d, such as 1h"))
				return
			}
			within = d
		}
		flt.Due = &findings.DueWithin{SLA: sla, Within: within, Now: time.Now()}
	}
	group := v.Get("group")
	if group != "" && group != findings.GroupDetection && group != findings.GroupEntity {
		writeError(w, http.StatusBadRequest, errors.New("group must be detection or entity"))
		return
	}
	if !findings.ValidOrder(flt.Order) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("sort must be one of %s", strings.Join(findings.Orders, ", ")))
		return
	}
	if a := v.Get("after"); a != "" {
		c, err := findings.DecodeCursor(a)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		flt.After = c
	}
	if since := v.Get("since"); since != "" {
		dur, err := detect.ParseDuration(strings.TrimPrefix(since, "-"))
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("since: "+err.Error()))
			return
		}
		flt.Since = time.Now().Add(-dur)
	}
	if l := v.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, errors.New("limit must be 1-1000"))
			return
		}
		flt.Limit = n
	}
	list, total, err := s.Findings.Search(r.Context(), flt)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if list == nil {
		list = []*findings.Finding{}
	}
	// The queue view does not need full history; keep the payload small.
	for _, f := range list {
		f.History = nil
	}
	resp := map[string]any{"findings": list, "total": total}
	if !sla.Off() {
		now := time.Now()
		due := map[string]*findings.Due{}
		for _, f := range list {
			if d := sla.DueOf(f, now); d != nil {
				due[f.ID] = d
			}
		}
		resp["due"] = due
	}
	if uc, ok := s.Findings.(findings.UrgencyCounter); ok && v.Get("counts") == "urgency" {
		// The pills count every urgency the other filters let through.
		cf := flt
		cf.Urgency, cf.After = nil, nil
		counts, err := uc.UrgencyCounts(r.Context(), cf)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		resp["by_urgency"] = counts
	}
	if g, ok := s.Findings.(findings.Grouper); ok && group != "" {
		cf := flt
		cf.After = nil
		groups, err := g.Groups(r.Context(), cf, group)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		resp["groups"] = groups
	}
	limit := flt.Limit
	if limit <= 0 {
		limit = 200
	}
	if len(list) == limit {
		// There may be more: next continues after the last one.
		resp["next"] = findings.CursorOf(list[len(list)-1]).Encode()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	f, err := s.Findings.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, findings.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	resp := map[string]any{"finding": f}
	if d := s.findingSLA().DueOf(f, time.Now()); d != nil {
		resp["due"] = d
	}
	if d, err := s.Detections.Get(f.DetectionID); err == nil {
		resp["detection"] = d
	}
	writeJSON(w, http.StatusOK, resp)
}

// updateFinding applies a triage change. The store writes only over the
// version it read and applies the change again to a newer copy when
// someone else changed the finding meanwhile, so no comment or status
// change made at the same moment is lost.
func (s *Server) updateFinding(ctx context.Context, id string, u findings.Update, author string) (*findings.Finding, error) {
	f, _, err := s.changeFinding(ctx, id, u, author)
	return f, err
}

// changeFinding is updateFinding that also returns what changed, for the
// audit line.
func (s *Server) changeFinding(ctx context.Context, id string, u findings.Update, author string) (*findings.Finding, []findings.Change, error) {
	var changes []findings.Change
	f, err := s.Findings.Modify(ctx, id, func(f *findings.Finding) (bool, error) {
		n := len(f.History)
		changed := f.Apply(u, author, time.Now().UTC())
		changes = slices.Clone(f.History[n:])
		return changed, nil
	})
	return f, changes, err
}

// describeHistory writes history entries for an audit line, such as
// "status: new -> closed, owner: (none) -> bob".
func describeHistory(ch []findings.Change) string {
	parts := make([]string, 0, len(ch))
	for _, c := range ch {
		from, to := c.From, c.To
		if from == "" {
			from = "(none)"
		}
		if to == "" {
			to = "(none)"
		}
		parts = append(parts, c.Field+": "+safelog.Cut(from, 200)+" -> "+safelog.Cut(to, 200))
	}
	return strings.Join(parts, ", ")
}

// auditIDs lists IDs for an audit line, the first 50 of them.
func auditIDs(ids []string) string {
	if len(ids) > 50 {
		return strings.Join(ids[:50], ",") + fmt.Sprintf(" and %d more", len(ids)-50)
	}
	return strings.Join(ids, ",")
}

// errNeedsDisposition is the answer to resolving a finding from the queue
// without saying what it turned out to be, while that is required.
var errNeedsDisposition = errors.New("pick a disposition (true positive, benign, false positive or undetermined) to resolve or close a finding")

// triageFinding is an analyst's change from the queue: updateFinding, but
// resolving or closing an open finding needs a disposition when
// detections.require_disposition is on.
func (s *Server) triageFinding(ctx context.Context, id string, u findings.Update, author string) (*findings.Finding, error) {
	f, _, err := s.triageChanges(ctx, id, u, author)
	return f, err
}

// triageChanges is triageFinding that also returns what changed, for the
// audit line.
func (s *Server) triageChanges(ctx context.Context, id string, u findings.Update, author string) (*findings.Finding, []findings.Change, error) {
	need := u.Status != nil && !findings.IsOpen(*u.Status) && s.conf() != nil && s.conf().Detections.RequireDispositionOn()
	var changes []findings.Change
	f, err := s.Findings.Modify(ctx, id, func(f *findings.Finding) (bool, error) {
		if need && findings.IsOpen(f.Status) && (u.Disposition == nil || *u.Disposition == "") && f.Disposition == "" {
			return false, errNeedsDisposition
		}
		n := len(f.History)
		changed := f.Apply(u, author, time.Now().UTC())
		changes = slices.Clone(f.History[n:])
		return changed, nil
	})
	return f, changes, err
}

// errFindingBusy is what an analyst sees when other changes to the same
// finding kept getting in first.
var errFindingBusy = errors.New("Someone else changed this finding at the same moment. Try again.")

func (s *Server) handleUpdateFinding(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var u findings.Update
	if err := readJSON(r, &u); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := u.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	f, changes, err := s.triageChanges(r.Context(), r.PathValue("id"), u, userOf(r))
	if errors.Is(err, errNeedsDisposition) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if errors.Is(err, findings.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if errors.Is(err, findings.ErrBusy) {
		writeError(w, http.StatusConflict, errFindingBusy)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if len(changes) > 0 || strings.TrimSpace(u.Comment) != "" {
		s.audit(r, "finding.update: finding changed", "target", f.ID, "detection", f.DetectionID,
			"changes", describeHistory(changes), "commented", strings.TrimSpace(u.Comment) != "")
	}
	writeJSON(w, http.StatusOK, f)
}

func (s *Server) handleBulkFindings(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var req struct {
		IDs    []string        `json:"ids"`
		Update findings.Update `json:"update"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 500 {
		writeError(w, http.StatusBadRequest, errors.New("ids must list 1-500 findings"))
		return
	}
	if err := req.Update.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	failed := map[string]string{}
	var updated []string
	for _, id := range req.IDs {
		if _, err := s.triageFinding(r.Context(), id, req.Update, userOf(r)); err != nil {
			failed[id] = err.Error()
			continue
		}
		updated = append(updated, id)
	}
	// One line for the whole request: the update asked for, and which
	// findings took it.
	s.audit(r, "finding.bulk_update: findings changed together", "update", describeUpdate(req.Update),
		"updated", len(updated), "failed", len(failed), "findings", auditIDs(updated))
	writeJSON(w, http.StatusOK, map[string]any{"updated": len(updated), "failed": failed})
}

// describeUpdate writes a triage update for an audit line, such as
// "status=closed, disposition=false_positive, comment".
func describeUpdate(u findings.Update) string {
	var parts []string
	for _, f := range []struct {
		name string
		v    *string
	}{{"status", u.Status}, {"owner", u.Owner}, {"severity", u.Severity}, {"disposition", u.Disposition}} {
		if f.v != nil {
			parts = append(parts, f.name+"="+*f.v)
		}
	}
	if strings.TrimSpace(u.Comment) != "" {
		parts = append(parts, "comment")
	}
	return strings.Join(parts, ", ")
}

// handleCreateFinding raises a finding by hand, for example from a search
// result an analyst wants to track.
func (s *Server) handleCreateFinding(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	var req struct {
		Title       string         `json:"title"`
		Description string         `json:"description"`
		Severity    string         `json:"severity"`
		Query       string         `json:"query"`
		Earliest    string         `json:"earliest"`
		Latest      string         `json:"latest"`
		Result      map[string]any `json:"result"`
		MITRE       []string       `json:"mitre"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		writeError(w, http.StatusBadRequest, errors.New("title is required"))
		return
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}
	sev := req.Severity
	if err := (findings.Update{Severity: &sev}).Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	now := time.Now().UTC()
	ents := map[string]any{}
	for _, f := range detect.EntityFields {
		if v, ok := req.Result[f]; ok && v != nil {
			ents[f] = v
		}
	}
	f := &findings.Finding{
		ID: detect.NewID(now), DetectionID: "manual", Title: req.Title, Description: req.Description,
		Severity: req.Severity, Status: findings.StatusNew, MITRE: req.MITRE, Entities: ents,
		Result: req.Result, Query: req.Query, Earliest: req.Earliest, Latest: req.Latest,
		Created: now, Updated: now,
		History: []findings.Change{{Author: userOf(r), Field: "created", To: "manual", Time: now}},
	}
	f.Context = detect.EntityContext(s.Assets, f.Entities)
	f.Urgency = detect.Urgency(f.Severity, f.Context)
	err := s.Findings.Create(r.Context(), f)
	for try := 0; errors.Is(err, findings.ErrExists) && try < 3; try++ {
		f.ID = detect.NewID(now) // practically never needed
		err = s.Findings.Create(r.Context(), f)
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.audit(r, "finding.create: finding raised by hand", "target", f.ID, "title", f.Title, "severity", f.Severity,
		"query", safelog.Cut(f.Query, 500))
	writeJSON(w, http.StatusCreated, f)
}

func (s *Server) handleFindingsSummary(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	sum, err := s.Findings.Summary(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// findingSLA is the due times of findings in use.
func (s *Server) findingSLA() findings.SLA {
	if c := s.conf(); c != nil {
		return c.FindingSLA()
	}
	return findings.DefaultSLA()
}
