// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/notebooks"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

func (s *Server) routeNotebooks(api *router) {
	api.viewer("GET /api/notebooks", s.handleListNotebooks)
	api.viewer("GET /api/notebooks/{id}", s.handleGetNotebook)
	api.viewer("GET /api/notebooks/{id}/markdown", s.handleNotebookMarkdown)
	// Running a notebook only reads events, like a search. The results
	// are kept with the notebook only for someone who may change it.
	api.viewer("POST /api/notebooks/{id}/run", s.handleRunNotebook)
	// Hunting is analyst work; who may change which notebook is checked
	// in each handler (notebooks.Notebook.CanEdit and CanManage).
	api.analyst("POST /api/notebooks", s.handleCreateNotebook)
	api.analyst("PUT /api/notebooks/{id}", s.handlePutNotebook)
	api.analyst("DELETE /api/notebooks/{id}", s.handleDeleteNotebook)
	api.analyst("POST /api/notebooks/{id}/cells", s.handleAddNotebookCell)
	api.analyst("POST /api/notebooks/{id}/cases", s.handleLinkNotebookCase)
	api.analyst("DELETE /api/notebooks/{id}/cases/{case}", s.handleUnlinkNotebookCase)
}

var errNotebooksOff = errors.New("hunting notebooks are not configured on this server")

// errNotebookBusy is what an analyst sees when other changes to the same
// notebook kept getting in first.
var errNotebookBusy = errors.New("Someone else changed this notebook at the same moment. Try again.")

// forbidden refuses a change the user's role allows but this notebook's
// owner or sharing does not.
type forbidden struct{ error }

// staleNotebook is a save over a version someone else has changed since.
type staleNotebook struct{ n *notebooks.Notebook }

func (e staleNotebook) Error() string {
	return fmt.Sprintf("%s changed this notebook since you opened it. Reload it to see their changes, then make yours again.", e.n.UpdatedBy)
}

func (s *Server) notebooksReady(w http.ResponseWriter) bool {
	if s.Notebooks == nil {
		writeError(w, http.StatusServiceUnavailable, errNotebooksOff)
		return false
	}
	return true
}

func writeNotebookError(w http.ResponseWriter, err error) {
	var ve *notebooks.ValidationError
	var fb forbidden
	var br badRequest
	var st staleNotebook
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": strings.Join(ve.Problems, "; "), "problems": ve.Problems})
	case errors.As(err, &fb):
		writeError(w, http.StatusForbidden, fb.error)
	case errors.As(err, &br):
		writeError(w, http.StatusBadRequest, br.error)
	case errors.As(err, &st):
		writeJSON(w, http.StatusPreconditionFailed, map[string]any{"error": st.Error(), "code": "stale", "by": st.n.UpdatedBy, "version": notebookVersion(st.n)})
	case errors.Is(err, notebooks.ErrNotFound), errors.Is(err, cases.ErrNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, notebooks.ErrBusy):
		writeError(w, http.StatusConflict, errNotebookBusy)
	default:
		writeError(w, http.StatusBadGateway, err)
	}
}

// notebookVersion is a saved notebook's version, for If-Match.
func notebookVersion(n *notebooks.Notebook) string {
	if n.Starter {
		return ""
	}
	return n.Updated.UTC().Format(time.RFC3339Nano)
}

// rights are what the signed-in user may do with one notebook.
type rights struct {
	Edit   bool `json:"edit"`
	Manage bool `json:"manage"`
	Copy   bool `json:"copy"`
}

func rightsOf(r *http.Request, n *notebooks.Notebook) rights {
	p := principalOf(r)
	analyst, admin := p != nil && p.Role.AtLeast(users.Analyst), p != nil && p.Role.AtLeast(users.Admin)
	// The demo's visitor is an analyst who only reads: a run of theirs
	// is never saved, even into a notebook shared for editing.
	if p != nil && p.Source == sourceDemo {
		analyst = false
	}
	return rights{
		Edit:   n.CanEdit(userOf(r), analyst, admin),
		Manage: n.CanManage(userOf(r), admin),
		Copy:   analyst,
	}
}

func isAdmin(r *http.Request) bool {
	p := principalOf(r)
	return p != nil && p.Role.AtLeast(users.Admin)
}

// loadNotebook returns a starter hunt or a saved notebook the user may
// see. One they may not see is not found, so its existence is not told.
func (s *Server) loadNotebook(ctx context.Context, r *http.Request, id string) (*notebooks.Notebook, error) {
	if n, ok := notebooks.Starter(id); ok {
		return n, nil
	}
	if s.Notebooks == nil {
		return nil, errNotebooksOff
	}
	n, err := s.Notebooks.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !n.CanSee(userOf(r), isAdmin(r)) {
		return nil, notebooks.ErrNotFound
	}
	return n, nil
}

// modifyNotebook changes a saved notebook the user may edit. A starter
// hunt, or one they may not see, is refused before change runs.
func (s *Server) modifyNotebook(r *http.Request, id string, change func(n *notebooks.Notebook) (bool, error)) (*notebooks.Notebook, error) {
	if _, ok := notebooks.Starter(id); ok {
		return nil, forbidden{errors.New("starter hunts can’t be changed; make a copy to change one")}
	}
	if s.Notebooks == nil {
		return nil, errNotebooksOff
	}
	user, admin := userOf(r), isAdmin(r)
	return s.Notebooks.Modify(r.Context(), id, func(n *notebooks.Notebook) (bool, error) {
		if !n.CanSee(user, admin) {
			return false, notebooks.ErrNotFound
		}
		if !n.CanEdit(user, true, admin) {
			return false, forbidden{fmt.Errorf("only %s or an admin can change this notebook; make a copy to change it", n.Owner)}
		}
		return change(n)
	})
}

type notebookResponse struct {
	Notebook *notebooks.Notebook `json:"notebook"`
	Version  string              `json:"version,omitempty"`
	Can      rights              `json:"can"`
}

func (s *Server) writeNotebook(w http.ResponseWriter, r *http.Request, status int, n *notebooks.Notebook) {
	writeJSON(w, status, notebookResponse{Notebook: n, Version: notebookVersion(n), Can: rightsOf(r, n)})
}

func (s *Server) handleListNotebooks(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	f := notebooks.Filter{User: userOf(r), Admin: isAdmin(r), Text: v.Get("q"), Technique: v.Get("technique"), Case: v.Get("case"), Limit: 500}
	starters := []*notebooks.Summary{}
	if f.Case == "" {
		for _, n := range notebooks.Starters() {
			if f.Matches(n) {
				starters = append(starters, notebooks.Summarize(n))
			}
		}
	}
	resp := map[string]any{"notebooks": []any{}, "starters": starters, "total": 0}
	if s.Notebooks == nil {
		resp["error"] = errNotebooksOff.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	list, total, err := s.Notebooks.Search(r.Context(), f)
	if err != nil {
		writeNotebookError(w, err)
		return
	}
	resp["notebooks"], resp["total"] = list, total
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetNotebook(w http.ResponseWriter, r *http.Request) {
	n, err := s.loadNotebook(r.Context(), r, r.PathValue("id"))
	if err != nil {
		writeNotebookError(w, err)
		return
	}
	s.writeNotebook(w, r, http.StatusOK, n)
}

// handleNotebookMarkdown downloads a notebook and its last results as a
// Markdown document.
func (s *Server) handleNotebookMarkdown(w http.ResponseWriter, r *http.Request) {
	n, err := s.loadNotebook(r.Context(), r, r.PathValue("id"))
	if err != nil {
		writeNotebookError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+n.ID+`.md"`)
	_, _ = w.Write(notebooks.Markdown(n, 25))
}

// notebookInput is what a page sends to create or save a notebook: cells
// come without their results, which the server keeps.
type notebookInput struct {
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Techniques  []string         `json:"techniques"`
	TimeRange   string           `json:"time_range"`
	Sharing     string           `json:"sharing"`
	Cells       []notebooks.Cell `json:"cells"`
	From        string           `json:"from"`
}

func cellsWithoutResults(in []notebooks.Cell) []notebooks.Cell {
	out := slices.Clone(in)
	for i := range out {
		out[i].Result = nil
	}
	return out
}

// handleCreateNotebook saves a new notebook, empty or as a copy of a
// starter hunt or of a notebook the user can see ("from"). The copy is
// the user's and private.
func (s *Server) handleCreateNotebook(w http.ResponseWriter, r *http.Request) {
	if !s.notebooksReady(w) {
		return
	}
	var in notebookInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	now := time.Now().UTC()
	user := userOf(r)
	n := &notebooks.Notebook{Title: in.Title, Description: in.Description, Techniques: in.Techniques, TimeRange: in.TimeRange,
		Cells: cellsWithoutResults(in.Cells)}
	if from := strings.TrimSpace(in.From); from != "" {
		src, err := s.loadNotebook(r.Context(), r, from)
		if err != nil {
			writeNotebookError(w, err)
			return
		}
		n.Title, n.Description, n.Techniques, n.TimeRange, n.Cells = src.Title, src.Description, src.Techniques, src.TimeRange, src.Cells
		if !src.Starter {
			n.Title = strings.TrimSpace(src.Title + " (copy)")
		}
		if t := strings.TrimSpace(in.Title); t != "" {
			n.Title = t
		}
		n.From = src.ID
	}
	n.ID, n.Owner, n.Sharing = notebooks.NewID(now), user, notebooks.Private
	if in.Sharing != "" {
		n.Sharing = in.Sharing
	}
	n.Created, n.Updated, n.UpdatedBy = now, now, user
	n.Normalize()
	if err := n.Validate(); err != nil {
		writeNotebookError(w, err)
		return
	}
	if err := s.Notebooks.Create(r.Context(), n); err != nil {
		writeNotebookError(w, err)
		return
	}
	s.Log.Info("hunting notebook created", "audit", true, "by", user, "notebook", n.ID, "from", n.From, "sharing", n.Sharing)
	s.writeNotebook(w, r, http.StatusCreated, n)
}

// handlePutNotebook saves a notebook's text, cells, techniques and
// sharing. With If-Match, a change made since the page read it is not
// overwritten: 412 names who made it. Only the owner and admins change
// the sharing.
func (s *Server) handlePutNotebook(w http.ResponseWriter, r *http.Request) {
	var in notebookInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, admin, version := userOf(r), isAdmin(r), ifMatch(r)
	var sharedFrom string
	n, err := s.modifyNotebook(r, r.PathValue("id"), func(n *notebooks.Notebook) (bool, error) {
		sharedFrom = ""
		if version != "" && notebookVersion(n) != version {
			return false, staleNotebook{n}
		}
		if in.Sharing != "" && in.Sharing != n.Sharing {
			if !n.CanManage(user, admin) {
				return false, forbidden{fmt.Errorf("only %s or an admin can change who this notebook is shared with", n.Owner)}
			}
			sharedFrom = n.Sharing
			n.Sharing = in.Sharing
		}
		old := *n
		n.Title, n.Description, n.Techniques, n.TimeRange = in.Title, in.Description, in.Techniques, in.TimeRange
		n.Cells = cellsWithoutResults(in.Cells)
		n.Normalize()
		n.KeepResults(&old)
		if err := n.Validate(); err != nil {
			return false, err
		}
		n.Touch(user, time.Now().UTC())
		return true, nil
	})
	if err != nil {
		writeNotebookError(w, err)
		return
	}
	if sharedFrom != "" {
		s.Log.Info("hunting notebook sharing changed", "audit", true, "by", user, "notebook", n.ID, "from", sharedFrom, "to", n.Sharing)
	}
	if !n.IsOwner(user) {
		// The owner's own edits are routine; someone else changing their
		// hunt (an admin, or an analyst on a notebook shared to edit) is
		// recorded.
		s.Log.Info("hunting notebook changed by someone other than its owner", "audit", true, "by", user, "notebook", n.ID, "owner", n.Owner)
	}
	s.writeNotebook(w, r, http.StatusOK, n)
}

func (s *Server) handleDeleteNotebook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := notebooks.Starter(id); ok {
		writeError(w, http.StatusForbidden, errors.New("starter hunts are built in and can’t be deleted"))
		return
	}
	if !s.notebooksReady(w) {
		return
	}
	n, err := s.loadNotebook(r.Context(), r, id)
	if err != nil {
		writeNotebookError(w, err)
		return
	}
	if !n.CanManage(userOf(r), isAdmin(r)) {
		writeError(w, http.StatusForbidden, fmt.Errorf("only %s or an admin can delete this notebook", n.Owner))
		return
	}
	if err := s.Notebooks.Delete(r.Context(), id); err != nil {
		writeNotebookError(w, err)
		return
	}
	s.Log.Info("hunting notebook deleted", "audit", true, "by", userOf(r), "notebook", id, "title", n.Title, "owner", n.Owner)
	w.WriteHeader(http.StatusNoContent)
}

// handleAddNotebookCell appends one cell, for "Add to notebook" on the
// Search page. The cell is added to the notebook as it is now, so a
// change made meanwhile is kept.
func (s *Server) handleAddNotebookCell(w http.ResponseWriter, r *http.Request) {
	var c notebooks.Cell
	if err := readJSON(r, &c); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	c.ID, c.Result = "", nil
	var added string
	n, err := s.modifyNotebook(r, r.PathValue("id"), func(n *notebooks.Notebook) (bool, error) {
		n.Cells = append(n.Cells, c)
		n.Normalize()
		if err := n.Validate(); err != nil {
			return false, err
		}
		added = n.Cells[len(n.Cells)-1].ID
		n.Touch(userOf(r), time.Now().UTC())
		return true, nil
	})
	if err != nil {
		writeNotebookError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"notebook": n, "version": notebookVersion(n), "can": rightsOf(r, n), "cell": added})
}

// notebookRunRequest names one cell to run (all searches when empty) and,
// optionally, a time range other than the notebook's.
type notebookRunRequest struct {
	Cell  string `json:"cell"`
	Range string `json:"range"`
}

// handleRunNotebook runs a notebook's searches, one after another, and
// returns the notebook with their results. They are saved with it when
// the user may change it; otherwise (a viewer, a starter hunt, a notebook
// shared for reading) only this answer has them.
func (s *Server) handleRunNotebook(w http.ResponseWriter, r *http.Request) {
	var req notebookRunRequest
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	n, err := s.loadNotebook(r.Context(), r, r.PathValue("id"))
	if err != nil {
		writeNotebookError(w, err)
		return
	}
	rng := n.TimeRange
	if req.Range != "" {
		if rng, _, err = parseRange(req.Range, n.TimeRange, true); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	var todo []int
	for i, c := range n.Cells {
		if c.Kind == notebooks.KindSearch && (req.Cell == "" || c.ID == req.Cell) {
			todo = append(todo, i)
		}
	}
	if req.Cell != "" && len(todo) == 0 {
		writeError(w, http.StatusNotFound, errors.New("that search is not in the notebook; it may have been removed"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	user := userOf(r)
	results := map[string]*notebooks.Result{}
	queries := map[string]string{}
	for _, i := range todo {
		c := n.Cells[i]
		res := s.runNotebookCell(ctx, c.Query, rng)
		attrs := []any{"notebook", n.ID, "cell", c.ID, "query", auditQuery(c.Query), "range", rng, "outcome", "ok"}
		if res.Error != "" {
			attrs[len(attrs)-1] = "failed"
		} else {
			attrs = append(attrs, "matched", res.Matched)
		}
		s.auditSearch(r, "search.notebook: ran a notebook search", attrs...)
		res.RanBy = user
		results[c.ID], queries[c.ID] = res, c.Query
		n.Cells[i].Result = res
	}
	saved := false
	if rightsOf(r, n).Edit {
		// Kept only for cells whose query is still the one that ran.
		m, err := s.modifyNotebook(r, n.ID, func(cur *notebooks.Notebook) (bool, error) {
			changed := false
			for id, res := range results {
				if c, ok := cur.Cell(id); ok && c.Query == queries[id] {
					c.Result = res
					changed = true
				}
			}
			return changed, nil
		})
		if err != nil {
			writeNotebookError(w, err)
			return
		}
		n, saved = m, true
		for i := range n.Cells {
			if res, ok := results[n.Cells[i].ID]; ok && n.Cells[i].Result == nil {
				n.Cells[i].Result = res
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"notebook": n, "version": notebookVersion(n), "can": rightsOf(r, n), "saved": saved, "range": rng})
}

// runNotebookCell runs one search over the last rng (unless its query sets
// earliest=) and returns its snapshot, or the reason it failed.
func (s *Server) runNotebookCell(ctx context.Context, src, rng string) *notebooks.Result {
	now := time.Now().UTC()
	q, err := query.Parse(src)
	if err != nil {
		return &notebooks.Result{RanAt: now, Error: queryErrText(err)}
	}
	earliest := ""
	if q.Earliest == "" && rng != "0" {
		q.Earliest = "-" + rng
		earliest = q.Earliest
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	res, err := s.Engine.Execute(cctx, q)
	if err != nil {
		return &notebooks.Result{RanAt: now, Earliest: earliest, Error: searchErrText(err)}
	}
	rows := make([]map[string]any, len(res.Rows))
	for i, row := range res.Rows {
		rows[i] = map[string]any(row)
	}
	out := notebooks.Snapshot(res.Kind, res.Columns, rows, res.Matched, res.Truncated)
	out.RanAt, out.Earliest = now, earliest
	return out
}

func queryErrText(err error) string {
	var qe *query.Error
	if errors.As(err, &qe) {
		return fmt.Sprintf("%s (at character %d)", qe.Msg, qe.Pos+1)
	}
	return err.Error()
}

// searchErrText says why a search failed in words for the page.
func searchErrText(err error) string {
	var qe *search.QueryError
	switch {
	case errors.As(err, &qe):
		return err.Error()
	case errors.Is(err, search.ErrBusy), errors.Is(err, search.ErrUserBusy):
		return "Too many searches are running. Run it again in a moment."
	case errors.Is(err, context.DeadlineExceeded):
		return "The search took too long. Narrow it or shorten the time range."
	}
	return "The search failed: " + err.Error()
}

// handleLinkNotebookCase links a notebook to an investigation: the case
// gets a timeline entry that opens the notebook and, with_results, each
// search's last result as a saved search.
func (s *Server) handleLinkNotebookCase(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	var req struct {
		CaseID      string `json:"case_id"`
		WithResults bool   `json:"with_results"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	caseID := strings.TrimSpace(req.CaseID)
	if caseID == "" {
		writeError(w, http.StatusBadRequest, errors.New("case_id is required"))
		return
	}
	if _, err := s.Cases.Get(r.Context(), caseID); err != nil {
		writeNotebookError(w, err)
		return
	}
	user := userOf(r)
	n, err := s.modifyNotebook(r, r.PathValue("id"), func(n *notebooks.Notebook) (bool, error) {
		if slices.Contains(n.Cases, caseID) {
			return false, nil
		}
		if len(n.Cases) >= notebooks.MaxCases {
			return false, badRequest{fmt.Errorf("a notebook can be linked to at most %d cases", notebooks.MaxCases)}
		}
		n.Cases = append(n.Cases, caseID)
		return true, nil
	})
	if err != nil {
		writeNotebookError(w, err)
		return
	}
	c, err := s.modifyCase(r.Context(), caseID, func(c *cases.Case) (bool, error) {
		changed := false
		now := time.Now().UTC()
		if !slices.ContainsFunc(c.Entries, func(e cases.Entry) bool { return e.Kind == cases.KindNotebook && e.NotebookID == n.ID }) {
			if _, err := c.AddEntry(cases.Entry{Kind: cases.KindNotebook, Text: n.Title, NotebookID: n.ID}, user, now); err != nil {
				return false, badRequest{err}
			}
			changed = true
		}
		if req.WithResults {
			for _, cell := range n.Cells {
				if cell.Kind != notebooks.KindSearch || cell.Result == nil || cell.Result.Error != "" {
					continue
				}
				e := cases.Entry{Kind: cases.KindSearch, Text: cell.Title, Query: cell.Query, Earliest: cell.Result.Earliest, NotebookID: n.ID,
					Result: cell.Result.Kind, Columns: cell.Result.Columns, Matched: cell.Result.Matched,
					Truncated: cell.Result.Truncated || len(cell.Result.Rows) > cases.MaxRows}
				e.Rows = slices.Clone(cell.Result.Rows[:min(len(cell.Result.Rows), cases.MaxRows)])
				if e.Rows == nil {
					e.Rows = []map[string]any{}
				}
				// Linking again adds only results that changed since the
				// last link, so repeated links cannot fill the case.
				if slices.ContainsFunc(c.Entries, func(x cases.Entry) bool { return sameCopiedResult(x, e) }) {
					continue
				}
				if _, err := c.AddEntry(e, user, now); err != nil {
					return false, badRequest{err}
				}
				changed = true
			}
		}
		return changed, nil
	})
	if err != nil {
		s.writeModifyError(w, err)
		return
	}
	s.Log.Info("hunting notebook linked to a case", "audit", true, "by", user, "notebook", n.ID, "case", caseID, "with_results", req.WithResults)
	writeJSON(w, http.StatusOK, map[string]any{"notebook": n, "version": notebookVersion(n), "can": rightsOf(r, n), "case": map[string]any{"id": c.ID, "title": c.Title}})
}

// sameCopiedResult reports whether case entry x is a copy of the same
// notebook search result as e.
func sameCopiedResult(x, e cases.Entry) bool {
	if x.Kind != cases.KindSearch || x.NotebookID != e.NotebookID || x.Query != e.Query || x.Earliest != e.Earliest ||
		x.Text != e.Text || x.Matched != e.Matched || x.Result != e.Result || len(x.Rows) != len(e.Rows) {
		return false
	}
	if len(x.Rows) == 0 {
		return true // nil and empty rows are the same result
	}
	a, err1 := json.Marshal(x.Rows)
	b, err2 := json.Marshal(e.Rows)
	return err1 == nil && err2 == nil && bytes.Equal(a, b)
}

// handleUnlinkNotebookCase unlinks a notebook from a case and takes the
// notebook's entry off the case timeline; searches copied to the case stay
// there as evidence.
func (s *Server) handleUnlinkNotebookCase(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("case")
	n, err := s.modifyNotebook(r, r.PathValue("id"), func(n *notebooks.Notebook) (bool, error) {
		i := slices.Index(n.Cases, caseID)
		if i < 0 {
			return false, nil
		}
		n.Cases = slices.Delete(n.Cases, i, i+1)
		return true, nil
	})
	if err != nil {
		writeNotebookError(w, err)
		return
	}
	if s.Cases != nil {
		user := userOf(r)
		_, err := s.modifyCase(r.Context(), caseID, func(c *cases.Case) (bool, error) {
			changed := false
			for _, e := range slices.Clone(c.Entries) {
				if e.Kind == cases.KindNotebook && e.NotebookID == n.ID {
					if err := c.RemoveEntry(e.ID, user, time.Now().UTC()); err != nil {
						return false, err
					}
					changed = true
				}
			}
			return changed, nil
		})
		if err != nil && !errors.Is(err, cases.ErrNotFound) {
			s.writeModifyError(w, err)
			return
		}
	}
	s.Log.Info("hunting notebook unlinked from a case", "audit", true, "by", userOf(r), "notebook", n.ID, "case", caseID)
	s.writeNotebook(w, r, http.StatusOK, n)
}

// releaseNotebooks clears the owner of a deleted user's notebooks, so an
// account made later with the same name does not inherit them. Private
// ones are then seen only by admins, who can share, hand on or delete them.
// A provider user may have made notebooks in every tenant: theirs are
// released in each tenant's too, whether it runs or not. It runs again
// before an account of that name is made (releaseBeforeCreate), so a
// release that failed at the delete is done then.
func (s *Server) releaseNotebooks(ctx context.Context, username, by string, provider bool) error {
	if username == "" {
		return nil
	}
	err := releaseNotebooksIn(ctx, s.Notebooks, s.Log, username, by)
	if provider && s.TenantID == "" && s.TenantRuntime != nil {
		for id, store := range s.TenantRuntime.NotebookStores() {
			err = errors.Join(err, releaseNotebooksIn(ctx, store, s.Log.With("tenant", id), username, by))
		}
	}
	return err
}

// releaseBeforeCreate releases the notebooks a former user of this name
// still owns before an account of the name is made, and refuses the
// account when that cannot be done.
func (s *Server) releaseBeforeCreate(ctx context.Context, username, by string, provider bool) error {
	if _, taken := s.userStore().Get(username); taken {
		// The account exists: making it again fails, and its notebooks
		// are its own.
		return nil
	}
	if err := s.releaseNotebooks(ctx, username, by, provider); err != nil {
		return errors.New("the hunting notebooks of a former user with this name could not be checked; try again in a moment")
	}
	return nil
}

func releaseNotebooksIn(ctx context.Context, nb notebooks.Store, log *slog.Logger, username, by string) error {
	if nb == nil {
		return nil
	}
	list, _, err := nb.Search(ctx, notebooks.Filter{Admin: true, Owner: username, Limit: 10000})
	var missing *store.Error
	if errors.As(err, &missing) && missing.Status == http.StatusNotFound {
		// No notebook was ever saved there.
		return nil
	}
	if err != nil {
		log.Warn("could not release the deleted user's hunting notebooks", "user", username, "err", err)
		return err
	}
	var failed error
	for _, sum := range list {
		_, err := nb.Modify(ctx, sum.ID, func(n *notebooks.Notebook) (bool, error) {
			if !n.IsOwner(username) {
				return false, nil
			}
			n.Owner = ""
			return true, nil
		})
		if err != nil {
			log.Warn("could not release a deleted user's hunting notebook", "user", username, "notebook", sum.ID, "err", err)
			failed = errors.Join(failed, err)
			continue
		}
		log.Info("hunting notebook owner removed with their account", "audit", true, "by", by, "notebook", sum.ID, "former_owner", username)
	}
	return failed
}
