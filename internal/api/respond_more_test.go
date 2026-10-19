package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Each refusal of a run has its status.
func TestWriteRespondError(t *testing.T) {
	for _, c := range []struct {
		err  error
		code int
	}{
		{&respond.RequestError{Field: "target", Msg: "enter a target"}, http.StatusBadRequest},
		{respond.ErrNotFound, http.StatusNotFound},
		{findings.ErrNotFound, http.StatusNotFound},
		{cases.ErrNotFound, http.StatusNotFound},
		{respond.ErrRateLimited, http.StatusTooManyRequests},
		{&respond.AuditError{Err: errDown}, http.StatusServiceUnavailable},
		{&respond.FileError{Path: "actions.yaml", Err: errDown}, http.StatusConflict},
		{errDown, http.StatusBadGateway},
	} {
		w := httptest.NewRecorder()
		writeRespondError(w, c.err)
		if w.Code != c.code {
			t.Errorf("%v: %d, want %d", c.err, w.Code, c.code)
		}
		if c.code == http.StatusTooManyRequests && w.Header().Get("Retry-After") != "60" {
			t.Errorf("rate limited without Retry-After")
		}
	}
	for _, c := range []struct {
		err  error
		code int
	}{
		{&respond.SettingsError{Action: "block", Problems: []respond.Problem{{Field: "url", Message: "enter a URL"}}}, http.StatusBadRequest},
		{&respond.FileError{Path: "actions.yaml", Err: errDown}, http.StatusConflict},
		{errDown, http.StatusInternalServerError},
	} {
		w := httptest.NewRecorder()
		writeRespondSettingsError(w, c.err)
		if w.Code != c.code {
			t.Errorf("settings %v: %d, want %d", c.err, w.Code, c.code)
		}
	}
}

// Runs are noted on findings and cases only where they exist.
func TestActionRecorder(t *testing.T) {
	ctx := context.Background()
	off := actionRecorder{&Server{}}
	var re *respond.RequestError
	if err := off.Check(ctx, "f1", ""); !errors.As(err, &re) || re.Field != "finding_id" {
		t.Errorf("no findings: %v", err)
	}
	if err := off.Check(ctx, "", "c1"); !errors.As(err, &re) || re.Field != "case_id" {
		t.Errorf("no cases: %v", err)
	}
	if err := off.OnCase(ctx, "c1", &respond.Run{}); !errors.Is(err, errCasesOff) {
		t.Errorf("OnCase: %v", err)
	}
	if err := off.OnFinding(ctx, "f1", &respond.Run{}); err == nil {
		t.Error("OnFinding without findings")
	}

	fs := &failFindings{}
	cs := &failCases{Store: cases.NewMemory()}
	var srv *Server
	newTestServerWith(t, func(s *Server) {
		fs.Store = s.Findings
		s.Findings, s.Cases, srv = fs, cs, s
	})
	a := actionRecorder{srv}
	if err := a.Check(ctx, "nope", ""); !errors.As(err, &re) || re.Field != "finding_id" {
		t.Errorf("missing finding: %v", err)
	}
	if err := a.Check(ctx, "", "CASE-nope"); !errors.As(err, &re) || re.Field != "case_id" {
		t.Errorf("missing case: %v", err)
	}
	fs.failing(errDown)
	cs.failing(errDown)
	if err := a.Check(ctx, "f1", ""); !errors.Is(err, errDown) {
		t.Errorf("findings down: %v", err)
	}
	if err := a.Check(ctx, "", "c1"); !errors.Is(err, errDown) {
		t.Errorf("cases down: %v", err)
	}
	fs.failing(nil)
	cs.failing(nil)
}

// The Response actions page shows the directory a disable-user action
// writes to, and the file's problem when it cannot be read.
func TestRespondConfigPage(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "actions.yaml")
	if err := os.WriteFile(file, []byte("actions: [not: valid: yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Respond = &respond.Runner{Actions: &respond.Actions{File: file}, Store: &respond.Memory{}, Log: s.Log, ScriptsDir: dir,
			Directory: func() users.LDAPSettings {
				return users.LDAPSettings{Type: "ad", URL: "ldaps://dc1.corp.example.com", UserBaseDN: "DC=corp,DC=example,DC=com", BindDN: "CN=svc"}
			}}
	})
	code, out := do(t, ts, "GET", "/api/respond/config", "", true)
	if code != http.StatusOK || out["file_error"] == nil {
		t.Fatalf("config: %d %v", code, out)
	}
	if d := out["directory"].(map[string]any); d["configured"] != true || d["domain"] != "corp.example.com" {
		t.Errorf("directory %v", d)
	}
	for _, rt := range []struct{ method, path, body string }{
		{"PUT", "/api/respond/config", `{"actions":[]}`},
		{"POST", "/api/respond/test", `{"action":{"name":"x"}}`},
	} {
		if code, _ := do(t, ts, rt.method, rt.path, rt.body, true); code != http.StatusConflict {
			t.Errorf("%s %s with an unreadable file: %d", rt.method, rt.path, code)
		}
	}
	for _, rt := range []struct{ method, path string }{{"PUT", "/api/respond/config"}, {"POST", "/api/respond/test"}} {
		if code, _ := do(t, ts, rt.method, rt.path, `{`, true); code != http.StatusBadRequest {
			t.Errorf("%s %s bad JSON: %d", rt.method, rt.path, code)
		}
	}
}
