// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/casetemplates"
)

// A case's tasks are its checklist; templates fill it for a kind of
// investigation. Analysts work the tasks; admins keep the templates.
func (s *Server) routeCaseTasks(api *router) {
	api.analyst("POST /api/cases/{id}/tasks", s.handleAddCaseTasks)
	api.analyst("PATCH /api/cases/{id}/tasks/{task}", s.handleUpdateCaseTask)
	api.analyst("DELETE /api/cases/{id}/tasks/{task}", s.handleRemoveCaseTask)
	api.viewer("GET /api/case-templates", s.handleGetCaseTemplates)
	api.admin("PUT /api/case-templates", s.handlePutCaseTemplates)
}

func (s *Server) caseTemplates() casetemplates.Store {
	if s.CaseTemplates != nil {
		return s.CaseTemplates
	}
	return &s.caseTemplatesMem
}

func (s *Server) handleAddCaseTasks(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	var req struct {
		Titles []string `json:"titles"`
		// Template adds a template's tasks.
		Template string `json:"template,omitempty"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	titles := req.Titles
	if req.Template != "" {
		t, err := s.findCaseTemplate(r, req.Template)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		titles = slices.Concat(titles, t.Tasks)
	}
	if len(titles) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("give the titles of the tasks to add, or a template"))
		return
	}
	user := userOf(r)
	var added []cases.Task
	c, err := s.modifyCase(r.Context(), r.PathValue("id"), func(c *cases.Case) (bool, error) {
		ts, err := c.AddTasks(titles, user, time.Now().UTC())
		if err != nil {
			return false, badRequest{err}
		}
		added = ts
		return len(ts) > 0, nil
	})
	if err != nil {
		s.writeModifyError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"case": c, "tasks": added})
}

func (s *Server) handleUpdateCaseTask(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	var u cases.TaskUpdate
	if err := readJSON(r, &u); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, id := userOf(r), r.PathValue("task")
	var task *cases.Task
	c, err := s.modifyCase(r.Context(), r.PathValue("id"), func(c *cases.Case) (bool, error) {
		t, changed, err := c.UpdateTask(id, u, user, time.Now().UTC())
		if errors.Is(err, cases.ErrTaskNotFound) {
			return false, err
		}
		if err != nil {
			return false, badRequest{err}
		}
		cp := *t
		task = &cp
		return changed, nil
	})
	if errors.Is(err, cases.ErrTaskNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		s.writeModifyError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"case": c, "task": task})
}

func (s *Server) handleRemoveCaseTask(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	user, id := userOf(r), r.PathValue("task")
	c, err := s.modifyCase(r.Context(), r.PathValue("id"), func(c *cases.Case) (bool, error) {
		return true, c.RemoveTask(id, user, time.Now().UTC())
	})
	if errors.Is(err, cases.ErrTaskNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		s.writeModifyError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"case": c})
}

func (s *Server) findCaseTemplate(r *http.Request, id string) (casetemplates.Template, error) {
	custom, err := s.caseTemplates().Get(r.Context())
	if err != nil {
		return casetemplates.Template{}, err
	}
	t, ok := casetemplates.Find(custom, id)
	if !ok {
		return t, errors.New("no case template " + id)
	}
	return t, nil
}

func (s *Server) handleGetCaseTemplates(w http.ResponseWriter, r *http.Request) {
	custom, err := s.caseTemplates().Get(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": slices.Concat(casetemplates.Builtin, custom)})
}

// handlePutCaseTemplates replaces the admins' templates; built-in ones
// sent back are left out.
func (s *Server) handlePutCaseTemplates(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Templates []casetemplates.Template `json:"templates"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	custom := slices.DeleteFunc(req.Templates, func(t casetemplates.Template) bool { return t.Builtin })
	ts, err := casetemplates.Validate(custom)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.caseTemplates().Put(r.Context(), ts); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.audit(r, "case templates saved", "templates", len(ts))
	writeJSON(w, http.StatusOK, map[string]any{"templates": slices.Concat(casetemplates.Builtin, ts)})
}
