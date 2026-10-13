package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// newRespondServer starts a server with response actions, a viewer (vera)
// and an analyst (andy), and a fake firewall API that counts requests.
func newRespondServer(t *testing.T) (*httptest.Server, *Server, *respond.Memory, *atomic.Int32, string) {
	t.Helper()
	var hits atomic.Int32
	fw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-Api-Key") != "fw-key-0001" {
			http.Error(w, "bad key", http.StatusUnauthorized)
			return
		}
		io.WriteString(w, `{"status":"done"}`)
	}))
	t.Cleanup(fw.Close)
	audit := &respond.Memory{}
	file := filepath.Join(t.TempDir(), "response.yaml")
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Users = users.NewMemory()
		for name, role := range map[string]users.Role{"vera": users.Viewer, "andy": users.Analyst} {
			if _, err := s.Users.Create(users.NewUser{Username: name, Role: role, Password: "role-password"}); err != nil {
				t.Fatal(err)
			}
		}
		s.Respond = &respond.Runner{Actions: &respond.Actions{File: file, Log: s.Log}, Store: audit, Log: s.Log}
	})
	return ts, srv, audit, &hits, fw.URL
}

func TestRespondFlow(t *testing.T) {
	ts, s, audit, hits, fwURL := newRespondServer(t)
	ctx := t.Context()
	f := &findings.Finding{ID: "F-1", Title: "Brute force", Severity: "high", Status: "new", Created: time.Now().UTC(),
		Entities: map[string]any{"src": "203.0.113.7"}}
	if err := s.Findings.Create(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := s.Cases.Create(ctx, &cases.Case{ID: "CASE-1", Title: "Brute force", Severity: "high", Status: "new"}); err != nil {
		t.Fatal(err)
	}

	// Only admins see and change the settings.
	cfg := `{"actions":[{"name":"block-ip","label":"Block IP on the firewall","kind":"http","target":"ip","allow_loopback":true,
		"url":"` + fwURL + `/api/alias/add/{{.ip}}","body":"{\"address\": \"{{.ip}}\"}","headers":[{"name":"X-Api-Key","value":"fw-key-0001"}]}]}`
	if code, _ := doAs(t, ts, "andy", "role-password", "PUT", "/api/respond/config", cfg); code != 403 {
		t.Errorf("analyst PUT config = %d", code)
	}
	if code, _ := doAs(t, ts, "andy", "role-password", "GET", "/api/respond/config", ""); code != 403 {
		t.Errorf("analyst GET config = %d", code)
	}
	code, body := do(t, ts, "PUT", "/api/respond/config", cfg, true)
	if code != 200 {
		t.Fatalf("PUT config = %d %v", code, body)
	}
	raw, _ := os.ReadFile(s.Respond.Actions.File)
	if strings.Contains(string(raw), "fw-key-0001") {
		t.Errorf("the key is saved in plain text")
	}
	acts := body["actions"].([]any)
	if len(acts) != 1 || acts[0].(map[string]any)["headers"].([]any)[0].(map[string]any)["set"] != true || strings.Contains(mustJSON(body), "fw-key-0001") {
		t.Errorf("config view %v", body)
	}
	// Saving again keeps the key without sending it.
	keep := strings.Replace(cfg, `"value":"fw-key-0001"`, `"keep":true`, 1)
	if code, body := do(t, ts, "PUT", "/api/respond/config", keep, true); code != 200 {
		t.Fatalf("keep = %d %v", code, body)
	}
	moved := strings.Replace(keep, fwURL, "https://elsewhere.example.com", 1)
	if code, body := do(t, ts, "PUT", "/api/respond/config", moved, true); code != 400 || !strings.Contains(body["error"].(string), "somewhere else") {
		t.Errorf("moved key = %d %v", code, body)
	}

	// Analysts list actions without settings, and run them.
	code, body = doAs(t, ts, "andy", "role-password", "GET", "/api/respond/actions", "")
	if code != 200 || len(body["actions"].([]any)) != 1 || strings.Contains(mustJSON(body), fwURL) {
		t.Errorf("actions = %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "vera", "role-password", "POST", "/api/respond/run", `{"action":"block-ip","target":"203.0.113.7","reason":"x"}`); code != 403 {
		t.Errorf("viewer run = %d", code)
	}
	code, body = doAs(t, ts, "andy", "role-password", "POST", "/api/respond/run", `{"action":"block-ip","target":"203.0.113.7","finding_id":"F-1","case_id":"CASE-1"}`)
	if code != 400 || body["field"] != "reason" || hits.Load() != 0 {
		t.Errorf("no reason = %d %v", code, body)
	}
	code, body = doAs(t, ts, "andy", "role-password", "POST", "/api/respond/run", `{"action":"block-ip","target":"203.0.113.7","finding_id":"F-1","case_id":"CASE-404","reason":"x"}`)
	if code != 400 || body["field"] != "case_id" {
		t.Errorf("missing case = %d %v", code, body)
	}
	code, body = doAs(t, ts, "andy", "role-password", "POST", "/api/respond/run",
		`{"action":"block-ip","target":"203.0.113.7","finding_id":"F-1","case_id":"CASE-1","reason":"Brute force from this IP"}`)
	if code != 200 || body["status"] != "succeeded" || body["actor"] != "andy" || hits.Load() != 1 {
		t.Fatalf("run = %d %v", code, body)
	}
	// The case timeline, the finding and the audit log have it.
	c, _ := s.Cases.Get(ctx, "CASE-1")
	if len(c.Entries) != 1 || c.Entries[0].Kind != cases.KindAction || c.Entries[0].Author != "andy" || c.Entries[0].Status != "succeeded" ||
		!strings.Contains(c.Entries[0].Text, "Ran Block IP on the firewall on IP address 203.0.113.7: succeeded.") ||
		!strings.Contains(c.Entries[0].Text, "Reason: Brute force from this IP") {
		t.Errorf("case entries %+v", c.Entries)
	}
	got, _ := s.Findings.Get(ctx, "F-1")
	if len(got.Comments) != 1 || got.Comments[0].Author != "andy" || !strings.HasPrefix(got.Comments[0].Text, "Ran Block IP") {
		t.Errorf("finding comments %+v", got.Comments)
	}
	if runs, _ := audit.List(ctx, respond.Filter{}); len(runs) != 1 || runs[0].FindingID != "F-1" {
		t.Errorf("audit %+v", runs)
	}
	code, body = doAs(t, ts, "andy", "role-password", "GET", "/api/respond/runs?case_id=CASE-1", "")
	if code != 200 || len(body["runs"].([]any)) != 1 {
		t.Errorf("runs = %d %v", code, body)
	}
	// The action stays on the timeline.
	code, _ = do(t, ts, "DELETE", "/api/cases/CASE-1/entries/"+c.Entries[0].ID, "", true)
	if code != 400 {
		t.Errorf("removing an action entry = %d", code)
	}

	// The test sends only when asked.
	test := `{"action":{"name":"block-ip","kind":"http","target":"ip","allow_loopback":true,"url":"` + fwURL + `/api/alias/add/{{.ip}}","body":"{\"address\": \"{{.ip}}\"}","headers":[{"name":"X-Api-Key","keep":true}]},"target":"198.51.100.1"}`
	code, body = do(t, ts, "POST", "/api/respond/test", test, true)
	if code != 200 || body["ok"] != true || hits.Load() != 1 {
		t.Errorf("test = %d %v", code, body)
	}
	code, body = do(t, ts, "POST", "/api/respond/test", strings.Replace(test, `"target":"198.51.100.1"`, `"target":"198.51.100.1","send":true`, 1), true)
	if code != 200 || body["ok"] != true || hits.Load() != 2 {
		t.Errorf("test send = %d %v", code, body)
	}
}

func TestRespondRateLimit(t *testing.T) {
	ts, _, _, _, fwURL := newRespondServer(t)
	cfg := `{"actions":[{"name":"note","kind":"http","target":"ip","disruptive":false,"allow_loopback":true,"url":"` + fwURL + `/x/{{.ip}}","headers":[{"name":"X-Api-Key","value":"fw-key-0001"}]}]}`
	if code, body := do(t, ts, "PUT", "/api/respond/config", cfg, true); code != 200 {
		t.Fatalf("PUT = %d %v", code, body)
	}
	for i := range respond.RunsPerMinute {
		if code, body := doAs(t, ts, "andy", "role-password", "POST", "/api/respond/run", `{"action":"note","target":"10.1.1.1"}`); code != 200 {
			t.Fatalf("run %d = %d %v", i, code, body)
		}
	}
	code, body := doAs(t, ts, "andy", "role-password", "POST", "/api/respond/run", `{"action":"note","target":"10.1.1.1"}`)
	if code != http.StatusTooManyRequests || body["code"] != "rate_limited" {
		t.Errorf("over the limit = %d %v", code, body)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
