// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/casereport"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
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
	api.analyst("POST /api/cases/reports/verify", s.handleVerifyCaseReport)
	api.viewer("GET /api/cases/reports/keys", s.handleCaseReportKeys)
	api.admin("POST /api/cases/reports/keys/{id}/revoke", s.handleRevokeCaseReportKey)
}

// reportKey is the key to sign a report with, recorded in the list of
// keys first, so no report is signed with a key the list lacks. nil
// (with the reason) exports the report unsigned.
func (s *Server) reportKey(r *http.Request) (ed25519.PrivateKey, string) {
	if s.ReportSigner == nil || s.ReportKeys == nil {
		return nil, "this server has no report key"
	}
	key, source, err := s.ReportSigner()
	if err == nil && key == nil {
		err = errors.New("no key")
	}
	if err == nil {
		err = s.ReportKeys.Use(r.Context(), key.Public().(ed25519.PublicKey), source, time.Now())
	}
	if err != nil {
		s.Log.Warn("a case report is exported unsigned", "err", err)
		return nil, err.Error()
	}
	return key, ""
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
	rep, err := casereport.New(c, linked, missing, userOf(r), s.conf().Server.PublicURL, s.conf().OpenSearch.IndexPrefix, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	key, why := s.reportKey(r)
	signed, err := rep.Sign(key)
	var body []byte
	if err == nil {
		if format == "json" {
			body, err = signed.JSON()
		} else {
			body, err = signed.HTML()
		}
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if signed.KeyID != "" {
		s.audit(r, "case report exported", "case", c.ID, "format", format, "sha256", rep.SHA256, "key", signed.KeyID)
	} else {
		s.audit(r, "case report exported", "case", c.ID, "format", format, "sha256", rep.SHA256, "unsigned", why)
	}
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

// handleVerifyCaseReport checks a report file someone was sent against
// this server's report keys: the signature over its exact bytes first,
// then its hashes and page, and that it is this tenant's. Each check is
// audited, so a forged report someone tried shows in the log.
func (s *Server) handleVerifyCaseReport(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, casereport.MaxSize+1))
	if err != nil || len(data) > casereport.MaxSize {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("a case report is at most %d MiB", casereport.MaxSize>>20))
		return
	}
	if s.ReportKeys == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("this server keeps no report keys"))
		return
	}
	ks, err := s.ReportKeys.List(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	res, err := casereport.Verify(data, reportkeys.Lookup(ks), true)
	if err == nil && res.Report.Tenant != s.conf().OpenSearch.IndexPrefix {
		err = fmt.Errorf("%w: it was made for another tenant (%s)", casereport.ErrChanged, res.Report.Tenant)
	}
	out := map[string]any{"verified": err == nil}
	if res != nil {
		out["signed"], out["key_id"], out["key_status"] = res.Signed, res.KeyID, res.KeyStatus
		if rep := res.Report; rep != nil {
			out["case"], out["title"], out["generated"], out["generated_by"], out["sha256"] = rep.Case.ID, rep.Case.Title, rep.Generated, rep.GeneratedBy, rep.SHA256
		}
	}
	keyID := ""
	if res != nil {
		keyID = res.KeyID
	}
	if err != nil {
		out["error"] = err.Error()
		s.audit(r, "case report verify failed", "key", keyID, "err", err.Error())
		writeJSON(w, http.StatusOK, out)
		return
	}
	if res.KeyStatus == reportkeys.Revoked {
		out["warning"] = "It was signed with a key that was replaced because it may have leaked: someone who had that key could have made or backdated this report."
	}
	s.audit(r, "case report verified", "case", res.Report.Case.ID, "sha256", res.Report.SHA256, "key", keyID, "key_status", res.KeyStatus)
	writeJSON(w, http.StatusOK, out)
}

// handleCaseReportKeys lists the public keys that signed case reports,
// to hand to whoever checks them.
func (s *Server) handleCaseReportKeys(w http.ResponseWriter, r *http.Request) {
	if s.ReportKeys == nil {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []reportkeys.Key{}})
		return
	}
	ks, err := s.ReportKeys.List(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if ks == nil {
		ks = []reportkeys.Key{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": ks})
}

// handleRevokeCaseReportKey marks a report key as possibly leaked, after
// the cluster key or master key it comes from leaked: reports it signed
// then say so when checked.
func (s *Server) handleRevokeCaseReportKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !reportkeys.ValidID(id) {
		writeError(w, http.StatusNotFound, reportkeys.ErrNotFound)
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	reason, err := reportkeys.CheckReason(req.Reason)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.ReportKeys == nil {
		writeError(w, http.StatusNotFound, reportkeys.ErrNotFound)
		return
	}
	err = s.ReportKeys.Revoke(r.Context(), id, userOf(r), reason, time.Now())
	if errors.Is(err, reportkeys.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.audit(r, "case report key revoked", "key", id, "reason", reason)
	s.handleCaseReportKeys(w, r)
}
