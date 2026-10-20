// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/casereport"
)

func TestCaseReport(t *testing.T) {
	ts, _ := newTestServerWith(t, func(*Server) {})
	_, out := do(t, ts, "POST", "/api/cases", `{"title":"Phish at <b>finance</b>","template":"phishing"}`, true)
	id := out["case"].(map[string]any)["id"].(string)
	if code, out := do(t, ts, "POST", "/api/cases/"+id+"/entries", `{"kind":"event","event":{"host":"web-01","bytes":12}}`, true); code != http.StatusCreated {
		t.Fatalf("pin: %d %v", code, out)
	}

	resp, page := get(t, ts, "/api/cases/"+id+"/report")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("page: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, strings.ToLower(id)+".html") {
		t.Errorf("disposition %q", cd)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'none'") {
		t.Errorf("csp %q", csp)
	}
	if strings.Contains(page, "<b>finance") || !strings.Contains(page, "Find every recipient") {
		t.Error("page did not escape the title or lacks the template's tasks")
	}
	r, err := casereport.Verify([]byte(page))
	if err != nil {
		t.Fatalf("verify page: %v", err)
	}
	if r.GeneratedBy != "admin" || len(r.Evidence) != 1 {
		t.Errorf("report %+v", r)
	}

	resp, js := get(t, ts, "/api/cases/"+id+"/report?format=json")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("json: %d", resp.StatusCode)
	}
	if _, err := casereport.Verify([]byte(js)); err != nil {
		t.Fatalf("verify json: %v", err)
	}

	if resp, _ := get(t, ts, "/api/cases/"+id+"/report?format=pdf"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("pdf: %d", resp.StatusCode)
	}
	if resp, _ := get(t, ts, "/api/cases/CASE-nope/report"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing case: %d", resp.StatusCode)
	}
}
