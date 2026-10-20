// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/casereport"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

// reportPolicy is the report page's own Content-Security-Policy: it loads
// nothing, runs nothing and submits nothing, even when opened from the
// server rather than saved first.
const reportPolicy = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// caseFileID is a case ID safe to put in a download's file name.
var caseFileID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// A case's report is everything it holds, hashed, for a ticket, an
// auditor or a lawyer. Exporting is an analyst's step and is audited:
// the report carries events out of Signalith.
func (s *Server) routeCaseReport(api *router) {
	api.analyst("GET /api/cases/{id}/report", s.handleCaseReport)
}

func (s *Server) handleCaseReport(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "html"
	}
	if format != "html" && format != "json" {
		writeError(w, http.StatusBadRequest, errors.New("format must be html or json"))
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
			linked = append(linked, f)
		}
	}
	rep, err := casereport.New(c, linked, missing, userOf(r), s.conf().Server.PublicURL, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var body []byte
	if format == "json" {
		body, err = rep.JSON()
	} else {
		body, err = rep.HTML()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "case report exported", "case", c.ID, "format", format, "sha256", rep.SHA256)
	name := "signalith-case-report." + format
	if caseFileID.MatchString(c.ID) {
		name = "signalith-" + strings.ToLower(c.ID) + "." + format
	}
	h := w.Header()
	if format == "json" {
		h.Set("Content-Type", "application/json")
	} else {
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", reportPolicy)
	}
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
