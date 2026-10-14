package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

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

	api.viewer("GET /api/findings", s.handleListFindings)
	api.viewer("GET /api/findings/summary", s.handleFindingsSummary)
	api.viewer("GET /api/findings/{id}", s.handleGetFinding)
	// Triage is analyst work.
	api.analyst("POST /api/findings", s.handleCreateFinding)
	api.analyst("POST /api/findings/bulk", s.handleBulkFindings)
	api.analyst("PATCH /api/findings/{id}", s.handleUpdateFinding)
}

var errDetectionsOff = errors.New("detections are not configured on this server")

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

type detectionView struct {
	*detect.Detection
	State detect.RunState `json:"state"`
}

func (s *Server) handleListDetections(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	states := s.Scheduler.Status()
	ds := s.Detections.List()
	out := make([]detectionView, 0, len(ds))
	for _, d := range ds {
		out = append(out, detectionView{Detection: d, State: states[d.ID]})
	}
	// scheduler says whether detections run on this server now; when they
	// run on another one, runs_on names it, and the run times here are
	// not theirs.
	resp := map[string]any{"detections": out, "scheduler": s.conf().Detections.Scheduler}
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
	writeJSON(w, http.StatusOK, detectionView{Detection: d, State: s.Scheduler.Status()[d.ID]})
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
	if err := s.Detections.Put(&d); err != nil {
		writeDetectionError(w, err)
		return
	}
	s.Log.Info("detection created", "detection", d.ID, "by", userOf(r))
	saved, _ := s.Detections.Get(d.ID)
	writeJSON(w, http.StatusCreated, saved)
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
	if err := s.Detections.Put(&d); err != nil {
		writeDetectionError(w, err)
		return
	}
	s.Log.Info("detection saved", "detection", d.ID, "enabled", d.Enabled, "by", userOf(r))
	saved, _ := s.Detections.Get(d.ID)
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteDetection(w http.ResponseWriter, r *http.Request) {
	if !s.detectionsReady(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.Detections.Delete(id); err != nil {
		writeDetectionError(w, err)
		return
	}
	s.Log.Info("detection deleted", "detection", id, "by", userOf(r))
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
	res, err := s.Scheduler.Run(ctx, d)
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
	if err := s.Detections.SetEnabled(req.IDs, req.Enabled); err != nil {
		writeDetectionError(w, err)
		return
	}
	s.Log.Info("detections turned "+map[bool]string{true: "on", false: "off"}[req.Enabled], "count", len(req.IDs), "by", userOf(r))
	writeJSON(w, http.StatusOK, map[string]any{"changed": len(req.IDs), "enabled": req.Enabled})
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
	writeJSON(w, http.StatusOK, map[string]any{"findings": list, "total": total})
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
	return s.Findings.Modify(ctx, id, func(f *findings.Finding) (bool, error) {
		return f.Apply(u, author, time.Now().UTC()), nil
	})
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
	f, err := s.updateFinding(r.Context(), r.PathValue("id"), u, userOf(r))
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
	updated := 0
	for _, id := range req.IDs {
		if _, err := s.updateFinding(r.Context(), id, req.Update, userOf(r)); err != nil {
			failed[id] = err.Error()
			continue
		}
		updated++
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": updated, "failed": failed})
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
