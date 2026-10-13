package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
)

func (s *Server) routeDashboards(api *router) {
	api.viewer("GET /api/posture", s.handlePosture)
	api.viewer("GET /api/dashboards", s.handleListDashboards)
	api.viewer("GET /api/dashboards/{id}", s.handleGetDashboard)
	api.viewer("GET /api/dashboards/{id}/yaml", s.handleDashboardYAML)
	// Running panels only reads events, like a search.
	api.viewer("POST /api/dashboards/{id}/run", s.handleRunDashboard)
	api.viewer("POST /api/panels/run", s.handleRunPanel)
	api.analyst("POST /api/dashboards", s.handleCreateDashboard)
	api.analyst("PUT /api/dashboards/{id}", s.handlePutDashboard)
	api.analyst("DELETE /api/dashboards/{id}", s.handleDeleteDashboard)
	api.analyst("POST /api/dashboards/{id}/panels", s.handleAddPanel)
}

var errDashboardsOff = errors.New("custom dashboards are not configured on this server; set dashboards.dir")

// errBuiltinIDTaken answers a create that names a built-in dashboard's id.
var errBuiltinIDTaken = errors.New("That id belongs to a built-in dashboard. Choose another.")

// refuseBuiltin answers a change to a built-in panel dashboard, such as
// Malware, and reports whether it did.
func refuseBuiltin(w http.ResponseWriter, id string) bool {
	d, ok := dashboards.GetBuiltin(id)
	if !ok {
		return false
	}
	writeError(w, http.StatusBadRequest, errors.New("The "+d.Title+" dashboard is built in and can’t be changed. Make a copy to change it."))
	return true
}

// builtinDashboard is a built-in panel dashboard as the API returns it.
type builtinDashboard struct {
	*dashboards.Dashboard
	Builtin bool `json:"builtin"`
}

// getDashboard returns a built-in panel dashboard, or a custom one from
// the store. Built-ins work without the store.
func (s *Server) getDashboard(w http.ResponseWriter, id string) (*dashboards.Dashboard, bool) {
	if d, ok := dashboards.GetBuiltin(id); ok {
		return d, true
	}
	if !s.dashboardsReady(w) {
		return nil, false
	}
	d, err := s.Dashboards.Get(id)
	if err != nil {
		writeDashboardError(w, err)
		return nil, false
	}
	return d, true
}

func (s *Server) dashboardsReady(w http.ResponseWriter) bool {
	if s.Dashboards == nil {
		writeError(w, http.StatusServiceUnavailable, errDashboardsOff)
		return false
	}
	return true
}

func writeDashboardError(w http.ResponseWriter, err error) {
	var ve *dashboards.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "problems": ve.Problems})
	case errors.Is(err, dashboards.ErrNotFound):
		writeError(w, http.StatusNotFound, err)
	default:
		writeError(w, http.StatusBadRequest, err)
	}
}

func (s *Server) runner() *dashboards.Runner {
	return &dashboards.Runner{Engine: s.Engine}
}

// parseRange checks a time range such as 24h or -7d; "0" is all time when
// allowed.
func parseRange(v, def string, allowAll bool) (string, time.Duration, error) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "-")
	if v == "" {
		v = def
	}
	if v == "0" && allowAll {
		return v, 0, nil
	}
	d, err := detect.ParseDuration(v)
	if err != nil {
		return "", 0, errors.New("range: " + err.Error())
	}
	if d < time.Minute || d > 366*24*time.Hour {
		return "", 0, errors.New("range must be between 1m and 366d")
	}
	return v, d, nil
}

// handlePosture returns the built-in security posture dashboard.
func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	label, d, err := parseRange(r.URL.Query().Get("range"), "24h", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if d > 90*24*time.Hour {
		writeError(w, http.StatusBadRequest, errors.New("the posture range can be at most 90d"))
		return
	}
	p := &dashboards.Posture{
		Engine: s.Engine, Findings: s.Findings, Detections: s.Detections,
		SchedulerOn: s.conf().Detections.Scheduler, StaleAfter: s.conf().StaleAfter(),
	}
	if s.Scheduler != nil {
		p.Status = s.Scheduler.Status
	}
	if s.Cluster != nil && !s.Cluster.RunsJobs() {
		p.Elsewhere, p.RunsOn = true, s.Cluster.JobHolder()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	writeJSON(w, http.StatusOK, p.Report(ctx, d, label))
}

type dashboardSummary struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	TimeRange   string `json:"time_range,omitempty"`
	Refresh     string `json:"refresh,omitempty"`
	Panels      int    `json:"panels"`
	Builtin     bool   `json:"builtin,omitempty"`
}

func (s *Server) handleListDashboards(w http.ResponseWriter, r *http.Request) {
	out := []dashboardSummary{{ID: dashboards.PostureID, Title: "Security posture", Builtin: true,
		Description: "Findings, triage times, what is firing, risk, ATT&CK tactics, data volume and detection health"}}
	// Built-in panel dashboards are listed even when custom dashboards
	// are off.
	for _, d := range dashboards.Builtin() {
		out = append(out, dashboardSummary{ID: d.ID, Title: d.Title, Description: d.Description, TimeRange: d.TimeRange, Refresh: d.Refresh, Panels: len(d.Panels), Builtin: true})
	}
	resp := map[string]any{"dashboards": out}
	if s.Dashboards == nil {
		resp["error"] = errDashboardsOff.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	list, problems, err := s.Dashboards.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	for _, d := range list {
		out = append(out, dashboardSummary{ID: d.ID, Title: d.Title, Description: d.Description, TimeRange: d.TimeRange, Refresh: d.Refresh, Panels: len(d.Panels)})
	}
	resp["dashboards"], resp["problems"], resp["dir"] = out, problems, s.Dashboards.Dir
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetDashboard(w http.ResponseWriter, r *http.Request) {
	if d, ok := dashboards.GetBuiltin(r.PathValue("id")); ok {
		writeJSON(w, http.StatusOK, builtinDashboard{Dashboard: d, Builtin: true})
		return
	}
	d, ok := s.getDashboard(w, r.PathValue("id"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleDashboardYAML(w http.ResponseWriter, r *http.Request) {
	d, ok := s.getDashboard(w, r.PathValue("id"))
	if !ok {
		return
	}
	data, err := dashboards.Encode(d)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+d.ID+`.yaml"`)
	_, _ = w.Write(data)
}

// handleCreateDashboard saves a new dashboard. Without an id, one is made
// from the title.
func (s *Server) handleCreateDashboard(w http.ResponseWriter, r *http.Request) {
	if !s.dashboardsReady(w) {
		return
	}
	var d dashboards.Dashboard
	if err := readJSON(r, &d); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if id := strings.TrimSpace(d.ID); id == "" {
		d.ID = s.Dashboards.NewID(d.Title)
	} else if id == dashboards.PostureID || dashboards.IsBuiltin(id) {
		writeError(w, http.StatusConflict, errBuiltinIDTaken)
		return
	} else if s.Dashboards.Exists(d.ID) {
		writeError(w, http.StatusConflict, errors.New("a dashboard with id "+d.ID+" already exists"))
		return
	}
	if err := s.Dashboards.Put(&d); err != nil {
		writeDashboardError(w, err)
		return
	}
	s.Log.Info("dashboard created", "dashboard", d.ID, "by", userOf(r))
	writeJSON(w, http.StatusCreated, d)
}

func (s *Server) handlePutDashboard(w http.ResponseWriter, r *http.Request) {
	if refuseBuiltin(w, r.PathValue("id")) || !s.dashboardsReady(w) {
		return
	}
	var d dashboards.Dashboard
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
	if err := s.Dashboards.Put(&d); err != nil {
		writeDashboardError(w, err)
		return
	}
	s.Log.Info("dashboard saved", "dashboard", d.ID, "by", userOf(r))
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleDeleteDashboard(w http.ResponseWriter, r *http.Request) {
	if refuseBuiltin(w, r.PathValue("id")) || !s.dashboardsReady(w) {
		return
	}
	if r.PathValue("id") == dashboards.PostureID {
		writeError(w, http.StatusBadRequest, errors.New("the security posture dashboard is built in and cannot be deleted"))
		return
	}
	if err := s.Dashboards.Delete(r.PathValue("id")); err != nil {
		writeDashboardError(w, err)
		return
	}
	s.Log.Info("dashboard deleted", "dashboard", r.PathValue("id"), "by", userOf(r))
	w.WriteHeader(http.StatusNoContent)
}

// handleAddPanel appends one panel, for "Add to dashboard" on the Search
// page.
func (s *Server) handleAddPanel(w http.ResponseWriter, r *http.Request) {
	if refuseBuiltin(w, r.PathValue("id")) || !s.dashboardsReady(w) {
		return
	}
	var p dashboards.Panel
	if err := readJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	d, err := s.Dashboards.Get(r.PathValue("id"))
	if err != nil {
		writeDashboardError(w, err)
		return
	}
	d.Panels = append(d.Panels, p)
	if err := s.Dashboards.Put(d); err != nil {
		writeDashboardError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

type runRequest struct {
	Range string           `json:"range"`
	Panel dashboards.Panel `json:"panel"`
}

func readRunRequest(r *http.Request) (runRequest, error) {
	var req runRequest
	if r.ContentLength == 0 {
		return req, nil
	}
	return req, readJSON(r, &req)
}

// handleRunDashboard runs every panel of a saved or built-in dashboard in
// parallel. Built-in dashboards need only the search engine.
func (s *Server) handleRunDashboard(w http.ResponseWriter, r *http.Request) {
	req, err := readRunRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	d, ok := s.getDashboard(w, r.PathValue("id"))
	if !ok {
		return
	}
	rng, _, err := parseRange(req.Range, d.TimeRange, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	writeJSON(w, http.StatusOK, map[string]any{"range": rng, "panels": s.runner().Run(ctx, d.Panels, rng)})
}

// handleRunPanel runs one unsaved panel, for the panel editor's preview.
func (s *Server) handleRunPanel(w http.ResponseWriter, r *http.Request) {
	req, err := readRunRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rng, _, err := parseRange(req.Range, "24h", true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	d := dashboards.Dashboard{Panels: []dashboards.Panel{req.Panel}}
	d.Defaults()
	if strings.TrimSpace(req.Panel.Query) == "" {
		writeError(w, http.StatusBadRequest, errors.New("panel.query is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	res := s.runner().RunPanel(ctx, d.Panels[0], rng)
	writeJSON(w, http.StatusOK, map[string]any{"range": rng, "panel": d.Panels[0], "result": res})
}
