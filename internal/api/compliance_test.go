package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComplianceReport(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	ts, _ := newRoleServer(t)

	// Every signed-in user can read it, so an auditor can be a Viewer.
	code, out := doAs(t, ts, "vera", "role-password", "GET", "/api/compliance", "")
	if code != 200 {
		t.Fatalf("viewer GET = %d %v", code, out)
	}
	fws, _ := out["frameworks"].([]any)
	if len(fws) < 6 {
		t.Fatalf("frameworks = %d", len(fws))
	}
	first := fws[0].(map[string]any)
	if first["id"] != "nist-800-53" || len(first["controls"].([]any)) < 20 {
		t.Errorf("first framework = %v", first["id"])
	}
	if caps, _ := out["capabilities"].([]any); len(caps) < 20 {
		t.Errorf("capabilities = %d", len(caps))
	}

	// Only admins write notes, and a note needs words.
	body := `{"framework":"pci-dss","control":"10.6.1","status":"external","note":"Chrony on every host."}`
	if code, _ := doAs(t, ts, "andy", "role-password", "PUT", "/api/compliance/notes", body); code != 403 {
		t.Errorf("analyst PUT = %d", code)
	}
	if code, out := do(t, ts, "PUT", "/api/compliance/notes", `{"framework":"pci-dss","control":"10.6.1","status":"external","note":""}`, true); code != 400 {
		t.Errorf("empty note = %d %v", code, out)
	}
	if code, out := do(t, ts, "PUT", "/api/compliance/notes", `{"framework":"pci-dss","control":"nope","status":"na","note":"x"}`, true); code != 400 {
		t.Errorf("unknown control = %d %v", code, out)
	}
	code, out = do(t, ts, "PUT", "/api/compliance/notes", body, true)
	if code != 200 {
		t.Fatalf("admin PUT = %d %v", code, out)
	}
	if a, _ := out["attestation"].(map[string]any); a["by"] != "admin" || a["status"] != "external" {
		t.Errorf("attestation = %v", out)
	}
	if _, err := os.Stat(filepath.Join(state, complianceFile)); err != nil {
		t.Errorf("notes file: %v", err)
	}
	_, out = do(t, ts, "GET", "/api/compliance", "", true)
	found := false
	for _, f := range out["frameworks"].([]any) {
		fm := f.(map[string]any)
		if fm["id"] != "pci-dss" {
			continue
		}
		for _, c := range fm["controls"].([]any) {
			cm := c.(map[string]any)
			if cm["id"] == "10.6.1" {
				found = cm["status"] == "external" && cm["attestation"] != nil
			}
		}
	}
	if !found {
		t.Error("the note does not show on the control")
	}
}

func TestComplianceExport(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	ts, _ := newRoleServer(t)
	get := func(path string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		req.SetBasicAuth("vera", "role-password")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b := new(strings.Builder)
		_, _ = io.Copy(b, resp.Body)
		return resp, b.String()
	}
	resp, body := get("/api/compliance/export?framework=pci-dss&format=csv")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "signalith-pci-dss-evidence-") || !strings.HasPrefix(body, "framework,control,") {
		t.Errorf("csv = %d %v %.80q", resp.StatusCode, resp.Header, body)
	}
	resp, body = get("/api/compliance/export?framework=iso-27001&format=html")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || !strings.Contains(body, "ISO/IEC 27001") {
		t.Errorf("html = %d %v", resp.StatusCode, resp.Header)
	}
	if resp.Header.Get("Content-Disposition") != "" {
		t.Error("the HTML report should open in the browser unless download=1")
	}
	if resp, _ = get("/api/compliance/export?framework=nope&format=csv"); resp.StatusCode != 400 {
		t.Errorf("unknown framework = %d", resp.StatusCode)
	}
	if resp, _ = get("/api/compliance/export?framework=soc2&format=pdf"); resp.StatusCode != 400 {
		t.Errorf("unknown format = %d", resp.StatusCode)
	}
}
