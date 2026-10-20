// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/ed25519"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/casereport"
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
)

func TestCaseReport(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	keys := &reportkeys.Memory{}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.ReportSigner = func() (ed25519.PrivateKey, string, error) { return priv, reportkeys.FromMaster, nil }
		s.ReportKeys = keys
	})
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
	ks, _ := keys.List(t.Context())
	if len(ks) != 1 || ks[0].ID != reportkeys.KeyID(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("keys after an export: %+v", ks)
	}
	res, err := casereport.Verify([]byte(page), reportkeys.Lookup(ks), true)
	if err != nil || res.Report.GeneratedBy != "admin" || res.Report.Tenant == "" || len(res.Report.Evidence) != 1 {
		t.Fatalf("verify page: %+v %v", res, err)
	}

	resp, js := get(t, ts, "/api/cases/"+id+"/report?format=json")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" || !strings.Contains(js, casereport.PayloadType) {
		t.Fatalf("json: %d %.80s", resp.StatusCode, js)
	}

	verify := func(body string) map[string]any {
		t.Helper()
		_, out := do(t, ts, "POST", "/api/cases/reports/verify", body, true)
		return out
	}
	if out := verify(js); out["verified"] != true || out["key_status"] != reportkeys.Current || out["case"] != id {
		t.Errorf("verify json: %v", out)
	}
	if out := verify(strings.Replace(page, "<dd>Medium</dd>", "<dd>Low</dd>", 1)); out["verified"] != false || !strings.Contains(out["error"].(string), "page") {
		t.Errorf("verify edited page: %v", out)
	}
	// Revoked by an admin: still verifies, with a warning.
	if code, _ := do(t, ts, "POST", "/api/cases/reports/keys/"+ks[0].ID+"/revoke", `{"reason":"master key in a leaked backup"}`, true); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if out := verify(js); out["verified"] != true || out["key_status"] != reportkeys.Revoked || out["warning"] == nil {
		t.Errorf("verify after revoke: %v", out)
	}
	if code, _ := do(t, ts, "POST", "/api/cases/reports/keys/abcdefabcdef/revoke", `{}`, true); code != http.StatusNotFound {
		t.Errorf("revoke unknown: %d", code)
	}

	if resp, _ := get(t, ts, "/api/cases/"+id+"/report?format=pdf"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("pdf: %d", resp.StatusCode)
	}
	if resp, _ := get(t, ts, "/api/cases/CASE-nope/report"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing case: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/cases/reports/verify", io.LimitReader(zeros{}, casereport.MaxSize+10))
	req.SetBasicAuth("admin", "s3cret-pass")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized verify: %v %v", resp, err)
	}
}

// A server without a key exports reports unsigned, and says so.
func TestCaseReportUnsigned(t *testing.T) {
	ts, _ := newTestServerWith(t, func(*Server) {})
	_, out := do(t, ts, "POST", "/api/cases", `{"title":"x"}`, true)
	id := out["case"].(map[string]any)["id"].(string)
	_, page := get(t, ts, "/api/cases/"+id+"/report")
	if !strings.Contains(page, "Not signed") {
		t.Error("unsigned page does not say so")
	}
	if res, err := casereport.Verify([]byte(page), nil, false); err != nil || res.Signed {
		t.Errorf("verify: %+v %v", res, err)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}
