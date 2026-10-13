package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/playbooks"
)

// Playbooks is what the Playbooks and Approvals pages work with. The
// runner itself is a background job of the server that runs the jobs
// (cmd/signalith); every server can show runs and take decisions.
type Playbooks struct {
	Manager *playbooks.Manager
	Runs    playbooks.Runs
}

// Playbooks: admins set them up on the Playbooks page; analysts approve
// or reject the steps that wait on the Approvals page. See
// docs/playbooks.md.
func (s *Server) routePlaybooks(api *router) {
	// What a playbook does decides what Signalith changes by itself.
	api.admin("GET /api/playbooks", s.handlePlaybooks)
	api.admin("PUT /api/playbooks", s.handlePlaybooksSave)
	// Approving is analyst work, like running an action by hand.
	api.analyst("GET /api/playbooks/runs", s.handlePlaybookRuns)
	api.analyst("POST /api/playbooks/runs/{id}/approve", s.handlePlaybookApprove)
	api.analyst("POST /api/playbooks/runs/{id}/reject", s.handlePlaybookReject)
}

var errPlaybooksOff = errors.New("playbooks are not available on this server")

func (s *Server) playbooksOK(w http.ResponseWriter) bool {
	if s.Playbooks == nil || s.Playbooks.Manager == nil || s.Playbooks.Runs == nil {
		writeError(w, http.StatusServiceUnavailable, errPlaybooksOff)
		return false
	}
	return true
}

// errPlaybooksNoJobs refuses changes on a server that does not run
// playbooks: its playbooks file is not the one the running server reads.
var errPlaybooksNoJobs = errors.New("this server does not run playbooks (detections.scheduler is off here), so they are set on the Signalith server that runs the background jobs")

// playbooksElsewhere says why playbooks are not set on this server now,
// or nil. Of the servers that share one OpenSearch, only the one that
// runs the background jobs runs playbooks, with its own.
func (s *Server) playbooksElsewhere() error {
	if s.conf() == nil || !s.conf().Detections.Scheduler {
		return errPlaybooksNoJobs
	}
	if s.Cluster == nil || s.Cluster.RunsJobs() {
		return nil
	}
	if holder := s.Cluster.JobHolder(); holder != "" {
		return fmt.Errorf("this server does not run playbooks right now: %s does, with its own; set them there", holder)
	}
	return errors.New("this server does not run playbooks right now, and no server runs the background jobs at the moment; the Servers page says why")
}

// playbookRefs are the channels and actions on this server.
func (s *Server) playbookRefs() playbooks.Refs {
	var n *notify.Manager
	if s.Notify != nil {
		n = s.Notify.Settings
	}
	return playbooks.BuildRefs(n, s.Respond)
}

type playbookView struct {
	playbooks.Playbook
	Summary string `json:"summary"`
}

type channelRef struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"`
}

type actionRef struct {
	Name string `json:"name"`
	playbooks.ActionRef
}

// playbooksView is the Playbooks page's data.
func (s *Server) playbooksView(list []playbooks.Playbook, fileErr error) map[string]any {
	refs := s.playbookRefs()
	views := make([]playbookView, 0, len(list))
	for _, p := range list {
		if p.Trigger.Detections == nil {
			p.Trigger.Detections = []string{}
		}
		if p.Steps == nil {
			p.Steps = []playbooks.Step{}
		}
		views = append(views, playbookView{Playbook: p, Summary: p.Summary(refs)})
	}
	channels := []channelRef{}
	if s.Notify != nil && s.Notify.Settings != nil {
		if set, err := s.Notify.Settings.Settings(); err == nil {
			for _, c := range set.Channels {
				channels = append(channels, channelRef{ID: c.ID, Label: c.Label(), Type: c.Type})
			}
		}
	}
	actions := []actionRef{}
	for name, a := range refs.Actions {
		actions = append(actions, actionRef{Name: name, ActionRef: a})
	}
	sort.Slice(actions, func(i, j int) bool { return strings.ToLower(actions[i].Label) < strings.ToLower(actions[j].Label) })
	out := map[string]any{
		"playbooks": views, "revision": s.Playbooks.Manager.Revision(), "file": fullPath(s.Playbooks.Manager.File),
		"channels": channels, "actions": actions, "notify": refs.Channels != nil, "respond": refs.Actions != nil,
		"urgencies": notify.Urgencies, "statuses": findings.Statuses, "placeholders": playbooks.Placeholders,
		"approval_hours": int(playbooks.ApprovalWindow / time.Hour),
	}
	if fileErr != nil {
		out["file_error"] = fileErr.Error()
	}
	err := s.playbooksElsewhere()
	out["manage"] = fileErr == nil && err == nil
	if err != nil {
		out["manage_why"] = sentence(err.Error())
		if s.Cluster != nil && !errors.Is(err, errPlaybooksNoJobs) {
			out["runs_on"] = s.Cluster.JobHolder()
		}
	}
	return out
}

func (s *Server) handlePlaybooks(w http.ResponseWriter, r *http.Request) {
	if !s.playbooksOK(w) {
		return
	}
	list, err := s.Playbooks.Manager.List()
	writeJSON(w, http.StatusOK, s.playbooksView(list, err))
}

func (s *Server) handlePlaybooksSave(w http.ResponseWriter, r *http.Request) {
	if !s.playbooksOK(w) {
		return
	}
	if err := s.playbooksElsewhere(); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	var in playbooks.Input
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	list, err := s.Playbooks.Manager.Save(in, s.playbookRefs())
	var ie *playbooks.InputError
	var fe *playbooks.FileError
	switch {
	case errors.As(err, &ie):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": ie.Error(), "problems": ie.Problems})
		return
	case errors.Is(err, playbooks.ErrChanged), errors.As(err, &fe):
		writeError(w, http.StatusConflict, err)
		return
	case err != nil:
		s.Log.Error("could not save the playbooks", "err", err)
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	on := 0
	for _, p := range list {
		if p.Enabled {
			on++
		}
	}
	s.Log.Info("playbooks changed", "audit", true, "by", userOf(r), "playbooks", len(list), "on", on)
	writeJSON(w, http.StatusOK, s.playbooksView(list, nil))
}

func (s *Server) handlePlaybookRuns(w http.ResponseWriter, r *http.Request) {
	if !s.playbooksOK(w) {
		return
	}
	q := r.URL.Query()
	flt := playbooks.Filter{Status: splitList(q.Get("status")), FindingID: q.Get("finding_id"), PlaybookID: q.Get("playbook_id")}
	for _, st := range flt.Status {
		if !slices.Contains(playbooks.Statuses, st) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("status must be one of %s", strings.Join(playbooks.Statuses, ", ")))
			return
		}
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, errors.New("limit must be 1-500"))
			return
		}
		flt.Limit = n
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	list, total, err := s.Playbooks.Runs.List(ctx, flt)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("playbook runs could not be read: %w", err))
		return
	}
	// The count the navigation shows.
	_, waiting, err := s.Playbooks.Runs.List(ctx, playbooks.Filter{Status: []string{playbooks.StatusWaiting}, Limit: 1})
	if err != nil {
		waiting = 0
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": list, "total": total, "waiting": waiting})
}

func (s *Server) handlePlaybookApprove(w http.ResponseWriter, r *http.Request) {
	s.decidePlaybookRun(w, r, true)
}

func (s *Server) handlePlaybookReject(w http.ResponseWriter, r *http.Request) {
	s.decidePlaybookRun(w, r, false)
}

func (s *Server) decidePlaybookRun(w http.ResponseWriter, r *http.Request, approve bool) {
	if !s.playbooksOK(w) {
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	user := userOf(r)
	run, err := playbooks.Decide(r.Context(), s.Playbooks.Runs, s.PlaybookDesk(), r.PathValue("id"), user, req.Note, approve, time.Now())
	var de *playbooks.DecidedError
	switch {
	case errors.Is(err, playbooks.ErrNotFound):
		writeError(w, http.StatusNotFound, err)
		return
	case errors.Is(err, playbooks.ErrNoteTooLong):
		writeError(w, http.StatusBadRequest, err)
		return
	case errors.As(err, &de):
		writeJSON(w, http.StatusConflict, map[string]any{"error": sentence(de.Error()), "code": "decided", "run": de.Run})
		return
	case err != nil:
		writeError(w, http.StatusBadGateway, err)
		return
	}
	verb := "rejected"
	if approve {
		verb = "approved"
	}
	s.Log.Info("playbook step "+verb, "audit", true, "by", user, "playbook", run.PlaybookName, "run", run.ID,
		"finding", run.FindingID, "what", run.Approval.What)
	writeJSON(w, http.StatusOK, run)
}

// PlaybookDesk is how playbooks change findings and cases: through this
// server, so their changes are made one at a time with the analysts'
// own.
func (s *Server) PlaybookDesk() playbooks.Desk { return playbookDesk{s} }

type playbookDesk struct{ s *Server }

func (d playbookDesk) OpenCase(ctx context.Context, f *findings.Finding, title, owner, author string) (string, error) {
	s := d.s
	if s.Cases == nil {
		return "", errCasesOff
	}
	sev := f.EffectiveUrgency()
	if !slices.Contains(cases.Severities, sev) {
		sev = "medium"
	}
	if err := (cases.Update{Title: &title, Severity: &sev, Owner: &owner}).Validate(); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	c := &cases.Case{
		ID: cases.NewID(now), Title: title, Severity: sev, Status: findings.StatusNew, Owner: owner,
		CreatedBy: author, Created: now, Updated: now,
		History: []findings.Change{{Author: author, Field: "created", To: "case", Time: now}},
	}
	if owner != "" {
		c.Status = findings.StatusInProgress
	}
	if err := s.createCase(ctx, c, now); err != nil {
		return "", err
	}
	if err := d.AddToCase(ctx, c.ID, f, author); err != nil {
		return c.ID, err
	}
	return c.ID, nil
}

func (d playbookDesk) AddToCase(ctx context.Context, caseID string, f *findings.Finding, author string) error {
	if d.s.Cases == nil {
		return errCasesOff
	}
	_, failed, err := d.s.addCaseFindings(ctx, caseID, []string{f.ID}, author)
	if err != nil {
		return err
	}
	if msg, ok := failed[f.ID]; ok {
		return errors.New(msg)
	}
	return nil
}

func (d playbookDesk) CaseOpen(ctx context.Context, caseID string) (bool, error) {
	if d.s.Cases == nil {
		return false, errCasesOff
	}
	c, err := d.s.Cases.Get(ctx, caseID)
	if errors.Is(err, cases.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return findings.IsOpen(c.Status), nil
}

func (d playbookDesk) NoteOnCase(ctx context.Context, caseID, text, author string) error {
	if d.s.Cases == nil {
		return errCasesOff
	}
	_, err := d.s.modifyCase(ctx, caseID, func(c *cases.Case) (bool, error) {
		_, err := c.AddEntry(cases.Entry{Kind: cases.KindNote, Text: text}, author, time.Now().UTC())
		return err == nil, err
	})
	return err
}

func (d playbookDesk) UpdateFinding(ctx context.Context, findingID string, u findings.Update, author string) error {
	if d.s.Findings == nil {
		return errDetectionsOff
	}
	_, err := d.s.updateFinding(ctx, findingID, u, author)
	return err
}
