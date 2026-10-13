package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Response actions: analysts run them from a finding or a case; admins set
// them up on the Response actions page. See docs/response-actions.md.
func (s *Server) routeRespond(api *router) {
	if s.Respond != nil && s.Respond.Record == nil {
		s.Respond.Record = actionRecorder{s}
	}
	// The Respond menu lists the actions (without their settings) and
	// past runs; running one is analyst work.
	api.analyst("GET /api/respond/actions", s.handleRespondActions)
	api.analyst("GET /api/respond/runs", s.handleRespondRuns)
	api.analyst("POST /api/respond/run", s.handleRespondRun)
	// Setting actions up decides what Signalith can change elsewhere.
	api.admin("GET /api/respond/config", s.handleRespondConfig)
	api.admin("PUT /api/respond/config", s.handleRespondSave)
	api.admin("POST /api/respond/test", s.handleRespondTest)
}

var errRespondOff = errors.New("response actions are not available on this server")

func (s *Server) respondReady(w http.ResponseWriter) bool {
	if s.Respond == nil || s.Respond.Actions == nil {
		writeError(w, http.StatusServiceUnavailable, errRespondOff)
		return false
	}
	return true
}

func (s *Server) handleRespondActions(w http.ResponseWriter, r *http.Request) {
	if !s.respondReady(w) {
		return
	}
	list, err := s.Respond.Infos()
	body := map[string]any{"actions": list}
	if err != nil {
		// Analysts are told it cannot be read, not where the file is.
		body["error"] = "The response actions could not be read. Ask an admin to check the Response actions page."
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleRespondRuns(w http.ResponseWriter, r *http.Request) {
	if !s.respondReady(w) {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	runs, err := s.Respond.Store.List(r.Context(), respond.Filter{FindingID: q.Get("finding_id"), CaseID: q.Get("case_id"),
		Action: q.Get("action"), Limit: limit})
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

func (s *Server) handleRespondRun(w http.ResponseWriter, r *http.Request) {
	if !s.respondReady(w) {
		return
	}
	var req respond.Request
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Actor = respond.Actor{Name: userOf(r)}
	run, err := s.Respond.Run(r.Context(), req)
	if err != nil {
		writeRespondError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// writeRespondError answers a run refused before it started.
func writeRespondError(w http.ResponseWriter, err error) {
	var re *respond.RequestError
	var ae *respond.AuditError
	var fe *respond.FileError
	switch {
	case errors.As(err, &re):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": re.Msg, "field": re.Field})
	case errors.Is(err, respond.ErrNotFound), errors.Is(err, findings.ErrNotFound), errors.Is(err, cases.ErrNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, respond.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": err.Error(), "code": "rate_limited"})
	case errors.As(err, &ae):
		writeError(w, http.StatusServiceUnavailable, err)
	case errors.As(err, &fe):
		writeError(w, http.StatusConflict, errors.New("the response actions could not be read; ask an admin to check the Response actions page"))
	default:
		writeError(w, http.StatusBadGateway, err)
	}
}

// respondConfig is what the Response actions page shows.
func (s *Server) respondConfig() map[string]any {
	list, err := s.Respond.Actions.List()
	views := make([]respond.View, 0, len(list))
	for _, c := range list {
		views = append(views, s.Respond.ViewOf(c))
	}
	dir := map[string]any{"configured": false}
	if s.Respond.Directory != nil {
		d := s.Respond.Directory()
		d.Normalize()
		dir = map[string]any{"configured": d.URL != "" && d.UserBaseDN != "", "type": d.Type, "url": d.URL,
			"domain": users.Domain(d.UserBaseDN), "service_account": d.BindDN, "problem": users.WriteProblem(d)}
	}
	body := map[string]any{
		"actions": views, "file": fullPath(s.Respond.Actions.File), "scripts_dir": fullPath(s.Respond.ScriptsDir),
		"scripts": respond.ListScripts(s.Respond.ScriptsDir), "directory": dir, "templates": respond.Templates(),
		"placeholders": respond.Placeholders, "max_timeout": respond.MaxScriptTimeout,
	}
	if err != nil {
		body["file_error"] = err.Error()
	}
	return body
}

func (s *Server) handleRespondConfig(w http.ResponseWriter, r *http.Request) {
	if !s.respondReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.respondConfig())
}

func writeRespondSettingsError(w http.ResponseWriter, err error) {
	var se *respond.SettingsError
	if errors.As(err, &se) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "action": se.Action, "problems": se.Problems})
		return
	}
	var fe *respond.FileError
	if errors.As(err, &fe) {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeError(w, http.StatusInternalServerError, err)
}

func (s *Server) handleRespondSave(w http.ResponseWriter, r *http.Request) {
	if !s.respondReady(w) {
		return
	}
	var req struct {
		Actions []respond.Input `json:"actions"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := s.Respond.Actions.List()
	if err != nil {
		writeRespondSettingsError(w, err)
		return
	}
	list, err := respond.Merge(saved, req.Actions)
	if err == nil {
		err = s.Respond.Actions.Save(list)
	}
	if err != nil {
		writeRespondSettingsError(w, err)
		return
	}
	names := make([]string, len(list))
	for i, c := range list {
		names[i] = c.Name
	}
	s.Log.Info("response actions changed", "audit", true, "by", userOf(r), "actions", strings.Join(names, ","))
	writeJSON(w, http.StatusOK, s.respondConfig())
}

func (s *Server) handleRespondTest(w http.ResponseWriter, r *http.Request) {
	if !s.respondReady(w) {
		return
	}
	var req struct {
		Action respond.Input `json:"action"`
		Target string        `json:"target"`
		// Send really sends an HTTP action's request; the page asks first.
		Send bool `json:"send"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := s.Respond.Actions.List()
	if err != nil {
		writeRespondSettingsError(w, err)
		return
	}
	list, err := respond.Merge(saved, []respond.Input{req.Action})
	if err != nil {
		writeRespondSettingsError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	rep := s.Respond.Test(ctx, list[0], req.Target, req.Send, userOf(r))
	s.Log.Info("response action tested", "audit", true, "by", userOf(r), "action", list[0].Name, "kind", list[0].Kind,
		"sent", rep.Run != nil, "ok", rep.OK)
	writeJSON(w, http.StatusOK, rep)
}

// actionRecorder notes runs on cases and findings for the runner.
type actionRecorder struct{ s *Server }

func (a actionRecorder) Check(ctx context.Context, findingID, caseID string) error {
	if findingID != "" {
		if a.s.Findings == nil {
			return &respond.RequestError{Field: "finding_id", Msg: "findings are not available on this server"}
		}
		if _, err := a.s.Findings.Get(ctx, findingID); errors.Is(err, findings.ErrNotFound) {
			return &respond.RequestError{Field: "finding_id", Msg: fmt.Sprintf("there is no finding %s", findingID)}
		} else if err != nil {
			return err
		}
	}
	if caseID != "" {
		if a.s.Cases == nil {
			return &respond.RequestError{Field: "case_id", Msg: "cases are not available on this server"}
		}
		if _, err := a.s.Cases.Get(ctx, caseID); errors.Is(err, cases.ErrNotFound) {
			return &respond.RequestError{Field: "case_id", Msg: fmt.Sprintf("there is no case %s", caseID)}
		} else if err != nil {
			return err
		}
	}
	return nil
}

func (a actionRecorder) OnCase(ctx context.Context, caseID string, run *respond.Run) error {
	if a.s.Cases == nil {
		return errCasesOff
	}
	_, err := a.s.modifyCase(ctx, caseID, func(c *cases.Case) (bool, error) {
		_, err := c.AddEntry(cases.Entry{Kind: cases.KindAction, Text: run.Text(), RunID: run.ID, Status: run.Status},
			run.Author(), time.Now().UTC())
		return err == nil, err
	})
	return err
}

func (a actionRecorder) OnFinding(ctx context.Context, findingID string, run *respond.Run) error {
	if a.s.Findings == nil {
		return errors.New("findings are not available on this server")
	}
	_, err := a.s.updateFinding(ctx, findingID, findings.Update{Comment: run.Text()}, run.Author())
	return err
}
