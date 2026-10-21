// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findingviews"
)

// routeFindingViews adds each user's saved views of the findings queue.
// They are the user's own, like their setup guide answers, so every role
// that sees the queue keeps its own.
func (s *Server) routeFindingViews(api *router) {
	api.viewer("GET /api/me/finding-views", s.handleGetFindingViews)
	api.viewer("PUT /api/me/finding-views", s.handlePutFindingViews)
}

func (s *Server) findingViews() findingviews.Store {
	if s.FindingViews != nil {
		return s.FindingViews
	}
	return &s.findingViewsMem
}

func (s *Server) handleGetFindingViews(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	vs, err := s.findingViews().Get(ctx, principalOf(r).Username)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("could not read your saved views: "+err.Error()))
		return
	}
	if vs == nil {
		vs = []findingviews.View{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"views": vs})
}

// handlePutFindingViews replaces the user's views with the list sent:
// adding, renaming, reordering and deleting are all one PUT.
func (s *Server) handlePutFindingViews(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Views []findingviews.View `json:"views"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	vs, err := findingviews.Validate(body.Views)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.findingViews().Put(ctx, principalOf(r).Username, vs); err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("could not save your views: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"views": vs})
}
