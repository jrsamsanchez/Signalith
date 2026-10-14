package api

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/users"
)

func (s *Server) routeCases(api *router) {
	api.viewer("GET /api/cases", s.handleListCases)
	api.viewer("GET /api/cases/summary", s.handleCasesSummary)
	api.viewer("GET /api/cases/{id}", s.handleGetCase)
	// Working investigations is analyst work.
	api.analyst("POST /api/cases", s.handleCreateCase)
	api.analyst("PATCH /api/cases/{id}", s.handleUpdateCase)
	api.analyst("POST /api/cases/{id}/findings", s.handleAddCaseFindings)
	api.analyst("DELETE /api/cases/{id}/findings/{fid}", s.handleRemoveCaseFinding)
	api.analyst("POST /api/cases/{id}/entries", s.handleAddCaseEntry)
	api.analyst("DELETE /api/cases/{id}/entries/{entry}", s.handleRemoveCaseEntry)
	api.analyst("POST /api/cases/{id}/entities", s.handleAddCaseEntity)
}

var errCasesOff = errors.New("investigation cases are not configured on this server")

func (s *Server) casesReady(w http.ResponseWriter) bool {
	if s.Cases == nil {
		writeError(w, http.StatusServiceUnavailable, errCasesOff)
		return false
	}
	return true
}

// errCaseBusy is what an analyst sees when other changes to the same case
// kept getting in first.
var errCaseBusy = errors.New("Someone else changed this investigation at the same moment. Try again.")

func writeCaseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, cases.ErrNotFound), errors.Is(err, cases.ErrEntryNotFound), errors.Is(err, findings.ErrNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, cases.ErrBusy):
		writeError(w, http.StatusConflict, errCaseBusy)
	default:
		writeError(w, http.StatusBadGateway, err)
	}
}

// modifyCase loads a case, lets change edit it and saves it if change
// reports a modification. The store writes only over the version it read
// and reruns change when someone changed the case meanwhile, on this
// server or another, so nobody's addition is lost; change must therefore
// be safe to run more than once, write nothing else, and reset whatever
// it reports out at its start. Changes on this server also wait for each
// other, so two tabs do not spend tries on each other.
func (s *Server) modifyCase(ctx context.Context, id string, change func(c *cases.Case) (bool, error)) (*cases.Case, error) {
	s.caseMu.Lock()
	defer s.caseMu.Unlock()
	return s.Cases.Modify(ctx, id, change)
}

// badRequest marks an error as the client's fault.
type badRequest struct{ error }

// notYours refuses a change to what someone else added.
type notYours struct{ error }

func (s *Server) writeModifyError(w http.ResponseWriter, err error) {
	var br badRequest
	if errors.As(err, &br) {
		writeError(w, http.StatusBadRequest, br.error)
		return
	}
	var ny notYours
	if errors.As(err, &ny) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": ny.Error(), "code": "not_author"})
		return
	}
	writeCaseError(w, err)
}

func (s *Server) handleListCases(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	v := r.URL.Query()
	flt := cases.Filter{Status: splitList(v.Get("status")), Owner: v.Get("owner"), Text: v.Get("q"), FindingID: v.Get("finding")}
	if l := v.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, errors.New("limit must be 1-1000"))
			return
		}
		flt.Limit = n
	}
	list, total, err := s.Cases.Search(r.Context(), flt)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if list == nil {
		list = []*cases.Case{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"cases": list, "total": total})
}

func (s *Server) handleCasesSummary(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	_, open, err := s.Cases.Search(r.Context(), cases.Filter{Status: cases.OpenStatuses, Limit: 1})
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	resp := map[string]any{"open": open}
	if u := userOf(r); u != "" {
		_, mine, err := s.Cases.Search(r.Context(), cases.Filter{Status: cases.OpenStatuses, Owner: u, Limit: 1})
		if err == nil {
			resp["mine"] = mine
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateCase(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	var req struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Severity    string   `json:"severity"`
		Owner       string   `json:"owner"`
		Findings    []string `json:"findings"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Severity == "" {
		req.Severity = "medium"
	}
	title, desc, sev, owner := strings.TrimSpace(req.Title), req.Description, req.Severity, req.Owner
	if title == "" && len(req.Findings) > 0 && s.Findings != nil {
		// Name the case after its first finding when no title is given.
		if f, err := s.Findings.Get(r.Context(), req.Findings[0]); err == nil {
			// Findings raised before titles were made safe may still
			// hold hidden characters.
			title = detect.ShowHidden(f.Title)
		}
	}
	if title == "" {
		writeError(w, http.StatusBadRequest, errors.New("title is required"))
		return
	}
	if err := (cases.Update{Title: &title, Description: &desc, Severity: &sev, Owner: &owner}).Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Findings) > cases.MaxFindings {
		writeError(w, http.StatusBadRequest, errors.New("too many findings"))
		return
	}
	now := time.Now().UTC()
	user := userOf(r)
	c := &cases.Case{
		ID: cases.NewID(now), Title: title, Description: strings.TrimSpace(desc), Severity: sev,
		Status: findings.StatusNew, Owner: strings.TrimSpace(owner), CreatedBy: user, Created: now, Updated: now,
		History: []findings.Change{{Author: user, Field: "created", To: "case", Time: now}},
	}
	if c.Owner != "" {
		c.Status = findings.StatusInProgress
	}
	if err := s.createCase(r.Context(), c, now); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	failed := map[string]string{}
	if len(req.Findings) > 0 {
		var err error
		c, failed, err = s.addCaseFindings(r.Context(), c.ID, req.Findings, user)
		if err != nil {
			writeCaseError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"case": c, "failed": failed})
}

// createCase stores a new case, with a new ID should its own be taken.
func (s *Server) createCase(ctx context.Context, c *cases.Case, now time.Time) error {
	s.caseMu.Lock()
	defer s.caseMu.Unlock()
	err := s.Cases.Create(ctx, c)
	for try := 0; errors.Is(err, cases.ErrExists) && try < 3; try++ {
		c.ID = cases.NewID(now) // practically never needed
		err = s.Cases.Create(ctx, c)
	}
	return err
}

func (s *Server) handleGetCase(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	c, err := s.Cases.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeCaseError(w, err)
		return
	}
	linked := []*findings.Finding{}
	var missing []string
	if s.Findings != nil {
		for _, id := range c.Findings {
			f, err := s.Findings.Get(r.Context(), id)
			if err != nil {
				missing = append(missing, id)
				continue
			}
			f.History, f.Comments, f.Result = nil, nil, nil
			linked = append(linked, f)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"case": c, "findings": linked, "missing_findings": missing,
		"entity_context": s.entityContext(c.Entities)})
}

// entityContext looks each case entity up in the asset and identity
// lists, so the case page can describe them without a request per entity.
// The list lines up with the entities; an entry is null when the value is
// not listed. It is nil when there are no lists.
func (s *Server) entityContext(ents []cases.Entity) []*assets.Context {
	if s.Assets == nil || len(ents) == 0 {
		return nil
	}
	out := make([]*assets.Context, len(ents))
	for i, e := range ents {
		if c, ok := s.Assets.Lookup(e.Field, e.Value); ok {
			out[i] = c
		}
	}
	return out
}

func (s *Server) handleUpdateCase(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	var req struct {
		cases.Update
		// CloseFindings also sets each open linked finding to the case's
		// new resolved or closed status, with Disposition if given.
		CloseFindings bool   `json:"close_findings"`
		Disposition   string `json:"disposition"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := req.Update.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Disposition != "" {
		if err := (findings.Update{Disposition: &req.Disposition}).Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	user := userOf(r)
	c, err := s.modifyCase(r.Context(), r.PathValue("id"), func(c *cases.Case) (bool, error) {
		status := c.Status
		if req.Status != nil {
			status = *req.Status
		}
		if req.CloseFindings && findings.IsOpen(status) {
			return false, badRequest{errors.New("set the case to resolved or closed to close its findings")}
		}
		return c.Apply(req.Update, user, time.Now().UTC()), nil
	})
	if err != nil {
		s.writeModifyError(w, err)
		return
	}
	resp := map[string]any{"case": c}
	if req.CloseFindings && s.Findings != nil {
		closed, failed := 0, map[string]string{}
		for _, id := range c.Findings {
			f, err := s.Findings.Get(r.Context(), id)
			if err != nil {
				failed[id] = err.Error()
				continue
			}
			if !findings.IsOpen(f.Status) {
				continue
			}
			st := c.Status
			u := findings.Update{Status: &st, Comment: "Closed with case " + c.ID}
			if req.Disposition != "" {
				u.Disposition = &req.Disposition
			}
			if _, err := s.updateFinding(r.Context(), id, u, user); err != nil {
				failed[id] = err.Error()
				continue
			}
			closed++
		}
		resp["findings_closed"], resp["failed"] = closed, failed
	}
	writeJSON(w, http.StatusOK, resp)
}

// addCaseFindings links findings to a case. A finding already in another
// case moves to this one, since a finding belongs to one investigation.
// The case is changed first, then each finding, then any case a finding
// left, each with its own versioned write: if two analysts link one
// finding to two cases at once, the finding names the last, and that
// last link's "moved" step takes it out of the other case.
func (s *Server) addCaseFindings(ctx context.Context, caseID string, ids []string, user string) (*cases.Case, map[string]string, error) {
	failed := map[string]string{}
	if s.Findings == nil {
		return nil, nil, errDetectionsOff
	}
	var read []*findings.Finding
	for _, id := range ids {
		f, err := s.Findings.Get(ctx, id)
		if err != nil {
			failed[id] = err.Error()
			continue
		}
		read = append(read, f)
	}
	var linked []string
	var refused map[string]string
	c, err := s.modifyCase(ctx, caseID, func(c *cases.Case) (bool, error) {
		linked, refused = nil, map[string]string{}
		changed := false
		now := time.Now().UTC()
		for _, f := range read {
			added, err := c.AddFinding(f, user, now)
			if err != nil {
				refused[f.ID] = err.Error()
				continue
			}
			changed = changed || added
			linked = append(linked, f.ID)
		}
		return changed, nil
	})
	if err != nil {
		return nil, nil, err
	}
	maps.Copy(failed, refused)
	for _, id := range linked {
		var prev string
		_, err := s.Findings.Modify(ctx, id, func(f *findings.Finding) (bool, error) {
			prev = ""
			if f.CaseID == c.ID {
				return false, nil
			}
			now := time.Now().UTC()
			prev = f.CaseID
			f.History = append(f.History, findings.Change{Author: user, Field: "case", From: f.CaseID, To: c.ID, Time: now})
			f.CaseID = c.ID
			if f.Status == findings.StatusNew {
				f.History = append(f.History, findings.Change{Author: user, Field: "status", From: f.Status, To: findings.StatusInProgress, Time: now})
				f.Status = findings.StatusInProgress
			}
			f.Updated = now
			return true, nil
		})
		if err != nil {
			failed[id] = err.Error()
			continue
		}
		if prev == "" || prev == c.ID {
			continue
		}
		_, err = s.modifyCase(ctx, prev, func(old *cases.Case) (bool, error) {
			if !old.RemoveFinding(id, user, time.Now().UTC()) {
				return false, nil
			}
			old.History[len(old.History)-1].To = "moved to " + c.ID
			return true, nil
		})
		if err != nil && !errors.Is(err, cases.ErrNotFound) {
			failed[id] = err.Error()
		}
	}
	return c, failed, nil
}

func (s *Server) handleAddCaseFindings(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > cases.MaxFindings {
		writeError(w, http.StatusBadRequest, errors.New("ids must list 1-500 findings"))
		return
	}
	c, failed, err := s.addCaseFindings(r.Context(), r.PathValue("id"), req.IDs, userOf(r))
	if err != nil {
		writeCaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"case": c, "failed": failed})
}

func (s *Server) handleRemoveCaseFinding(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	fid, user := r.PathValue("fid"), userOf(r)
	c, err := s.modifyCase(r.Context(), r.PathValue("id"), func(c *cases.Case) (bool, error) {
		if !c.RemoveFinding(fid, user, time.Now().UTC()) {
			return false, findings.ErrNotFound
		}
		return true, nil
	})
	if err != nil {
		writeCaseError(w, err)
		return
	}
	if s.Findings != nil {
		// Only while the finding still names this case: if it moved on to
		// another meanwhile, that link stays.
		_, _ = s.Findings.Modify(r.Context(), fid, func(f *findings.Finding) (bool, error) {
			if f.CaseID != c.ID {
				return false, nil
			}
			now := time.Now().UTC()
			f.History = append(f.History, findings.Change{Author: user, Field: "case", From: c.ID, To: "", Time: now})
			f.CaseID, f.Updated = "", now
			return true, nil
		})
	}
	writeJSON(w, http.StatusOK, c)
}

// handleAddCaseEntry adds a note, a search or an event to the timeline.
// A search is run here and a snapshot of its first rows is kept, so the
// case shows what the analyst saw even after the events age out.
func (s *Server) handleAddCaseEntry(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	var req struct {
		Kind     string         `json:"kind"`
		Text     string         `json:"text"`
		Query    string         `json:"query"`
		Earliest string         `json:"earliest"`
		Latest   string         `json:"latest"`
		Event    map[string]any `json:"event"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	text := strings.TrimSpace(req.Text)
	if len(text) > cases.MaxTextLen {
		writeError(w, http.StatusBadRequest, errors.New("text is too long"))
		return
	}
	e := cases.Entry{Kind: req.Kind, Text: text}
	switch req.Kind {
	case cases.KindNote:
		if text == "" {
			writeError(w, http.StatusBadRequest, errors.New("a note needs text"))
			return
		}
	case cases.KindSearch:
		qs := strings.TrimSpace(req.Query)
		if qs == "" {
			writeError(w, http.StatusBadRequest, errors.New("query is required"))
			return
		}
		q, err := query.Parse(qs)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if q.Earliest == "" {
			q.Earliest = req.Earliest
		}
		if q.Latest == "" {
			q.Latest = req.Latest
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		res, err := s.Engine.Execute(ctx, q)
		cancel()
		if err != nil {
			writeSearchError(w, err)
			return
		}
		e.Query, e.Earliest, e.Latest = qs, req.Earliest, req.Latest
		e.Result, e.Columns, e.Matched = res.Kind, res.Columns, res.Matched
		e.Truncated = res.Truncated || len(res.Rows) > cases.MaxRows
		for _, row := range res.Rows[:min(len(res.Rows), cases.MaxRows)] {
			e.Rows = append(e.Rows, map[string]any(row))
		}
		if e.Rows == nil {
			e.Rows = []map[string]any{}
		}
	case cases.KindEvent:
		if len(req.Event) == 0 {
			writeError(w, http.StatusBadRequest, errors.New("event is required"))
			return
		}
		ev, err := cases.TrimEvent(req.Event)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		e.Event = ev
	default:
		writeError(w, http.StatusBadRequest, errors.New("kind must be note, search or event"))
		return
	}
	user := userOf(r)
	var added *cases.Entry
	c, err := s.modifyCase(r.Context(), r.PathValue("id"), func(c *cases.Case) (bool, error) {
		ent, err := c.AddEntry(e, user, time.Now().UTC())
		if err != nil {
			return false, badRequest{err}
		}
		added = ent
		if e.Kind == cases.KindEvent {
			c.AddEntities(e.Event)
		}
		return true, nil
	})
	if err != nil {
		s.writeModifyError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"case": c, "entry": added})
}

func (s *Server) handleRemoveCaseEntry(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	id, user := r.PathValue("entry"), userOf(r)
	p := principalOf(r)
	c, err := s.modifyCase(r.Context(), r.PathValue("id"), func(c *cases.Case) (bool, error) {
		i := slices.IndexFunc(c.Entries, func(e cases.Entry) bool { return e.ID == id })
		if i >= 0 && c.Entries[i].Kind == cases.KindFinding {
			return false, badRequest{errors.New("remove the finding from the case instead")}
		}
		if i >= 0 && c.Entries[i].Kind == cases.KindAction {
			return false, badRequest{errors.New("a response action stays on the timeline: it is the record of what was done")}
		}
		// Notes, pinned events and searches are evidence: analysts remove
		// only their own, admins anyone's.
		if i >= 0 && !p.Role.AtLeast(users.Admin) && !strings.EqualFold(c.Entries[i].Author, p.Username) {
			return false, notYours{fmt.Errorf("only %s or an admin can remove this; you can remove what you added yourself", c.Entries[i].Author)}
		}
		return true, c.RemoveEntry(id, user, time.Now().UTC())
	})
	if err != nil {
		s.writeModifyError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleAddCaseEntity(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	var e cases.Entity
	if err := readJSON(r, &e); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(e.Field) == "" || strings.TrimSpace(e.Value) == "" || len(e.Field)+len(e.Value) > 1000 {
		writeError(w, http.StatusBadRequest, errors.New("field and value are required"))
		return
	}
	user := userOf(r)
	c, err := s.modifyCase(r.Context(), r.PathValue("id"), func(c *cases.Case) (bool, error) {
		if !c.AddEntity(e) {
			return false, nil
		}
		now := time.Now().UTC()
		c.History = append(c.History, findings.Change{Author: user, Field: "entity", To: e.Field + "=" + e.Value, Time: now})
		c.Updated = now
		return true, nil
	})
	if err != nil {
		writeCaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}
