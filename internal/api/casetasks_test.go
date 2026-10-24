// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cases"
)

// A case opened from a template gets its tasks; analysts tick them off
// and add their own; admins keep their own templates.
func TestCaseTasksAndTemplates(t *testing.T) {
	ts, _ := newTestServer(t)
	code, out := do(t, ts, "POST", "/api/cases", `{"title":"Bob's account","template":"account-compromise"}`, true)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	c := out["case"].(map[string]any)
	if c["severity"] != "high" || c["template"] != "account-compromise" || !strings.Contains(c["description"].(string), "someone else") {
		t.Errorf("case %v", c)
	}
	tasks := c["tasks"].([]any)
	if len(tasks) != 5 {
		t.Fatalf("tasks %v", tasks)
	}
	id := c["id"].(string)
	task := tasks[0].(map[string]any)["id"].(string)

	code, out = do(t, ts, "PATCH", "/api/cases/"+id+"/tasks/"+task, `{"done":true,"owner":"ana"}`, true)
	if code != 200 {
		t.Fatalf("tick: %d %v", code, out)
	}
	if tk := out["task"].(map[string]any); tk["done"] != true || tk["done_by"] != "admin" || tk["owner"] != "ana" || tk["done_at"] == nil {
		t.Errorf("task %v", tk)
	}
	for _, c := range []struct {
		method, path, body string
		code               int
	}{
		{"PATCH", "/api/cases/" + id + "/tasks/nope", `{"done":true}`, 404},
		{"PATCH", "/api/cases/" + id + "/tasks/" + task, `{"title":"  "}`, 400},
		{"POST", "/api/cases/" + id + "/tasks", `{}`, 400},
		{"POST", "/api/cases/" + id + "/tasks", `{"titles":["two\nlines"]}`, 400},
		{"POST", "/api/cases/" + id + "/tasks", `{"template":"nope"}`, 400},
		{"POST", "/api/cases", `{"title":"x","template":"nope"}`, 400},
		{"DELETE", "/api/cases/" + id + "/tasks/nope", ``, 404},
	} {
		if code, out := do(t, ts, c.method, c.path, c.body, true); code != c.code {
			t.Errorf("%s %s %s: %d %v", c.method, c.path, c.body, code, out)
		}
	}
	code, out = do(t, ts, "POST", "/api/cases/"+id+"/tasks", `{"titles":["Call the user's manager"]}`, true)
	if code != http.StatusCreated || len(out["case"].(map[string]any)["tasks"].([]any)) != 6 {
		t.Fatalf("add: %d %v", code, out)
	}
	if code, out := do(t, ts, "DELETE", "/api/cases/"+id+"/tasks/"+task, ``, true); code != 200 || len(out["case"].(map[string]any)["tasks"].([]any)) != 5 {
		t.Errorf("remove: %d %v", code, out)
	}
	// A case holds at most 100 tasks.
	many := make([]string, 100)
	for i := range many {
		many[i] = fmt.Sprintf("%q", fmt.Sprint("step ", i))
	}
	if code, _ := do(t, ts, "POST", "/api/cases/"+id+"/tasks", `{"titles":[`+strings.Join(many, ",")+`]}`, true); code != 400 {
		t.Errorf("too many: %d", code)
	}

	// Admins add templates; built-in IDs and bad ones are refused.
	for body, want := range map[string]int{
		`{"templates":[{"id":"phishing","name":"Mine"}]}`:                       400,
		`{"templates":[{"id":"Bad ID","name":"x"}]}`:                            400,
		`{"templates":[{"id":"ot","name":"OT incident","severity":"urgent"}]}`:  400,
		`{"templates":[{"id":"ot","name":"OT incident","tasks":["a\u0007b"]}]}`: 400,
	} {
		if code, out := do(t, ts, "PUT", "/api/case-templates", body, true); code != want {
			t.Errorf("%s: %d %v", body, code, out)
		}
	}
	code, out = do(t, ts, "PUT", "/api/case-templates", `{"templates":[{"id":"phishing","name":"Phishing","builtin":true},{"id":"ot","name":" OT incident ","severity":"critical","tasks":["Call the plant"]}]}`, true)
	if code != 200 {
		t.Fatalf("put: %d %v", code, out)
	}
	_, out = do(t, ts, "GET", "/api/case-templates", "", true)
	list := out["templates"].([]any)
	if last := list[len(list)-1].(map[string]any); last["id"] != "ot" || last["name"] != "OT incident" || last["builtin"] != nil {
		t.Errorf("templates %v", list)
	}
	code, out = do(t, ts, "POST", "/api/cases", `{"title":"Line 2 HMI","template":"ot"}`, true)
	if code != http.StatusCreated || out["case"].(map[string]any)["severity"] != "critical" {
		t.Errorf("from a custom template: %d %v", code, out)
	}
}

// Pinned evidence carries the hash taken when it was pinned, and a case
// whose evidence changed outside Signalith says so.
func TestCaseEvidenceHash(t *testing.T) {
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) { srv = s })
	_, out := do(t, ts, "POST", "/api/cases", `{"title":"x"}`, true)
	id := out["case"].(map[string]any)["id"].(string)
	code, out := do(t, ts, "POST", "/api/cases/"+id+"/entries", `{"kind":"event","event":{"host":"web-01","bytes":12}}`, true)
	if code != http.StatusCreated || len(out["entry"].(map[string]any)["sha256"].(string)) != 64 {
		t.Fatalf("pin: %d %v", code, out)
	}
	_, out = do(t, ts, "GET", "/api/cases/"+id, "", true)
	if ch := out["evidence_changed"].([]any); len(ch) != 0 {
		t.Errorf("changed %v", ch)
	}
	if _, err := srv.Cases.Modify(context.Background(), id, func(c *cases.Case) (bool, error) {
		c.Entries[0].Event["host"] = "web-02"
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	_, out = do(t, ts, "GET", "/api/cases/"+id, "", true)
	if ch := out["evidence_changed"].([]any); len(ch) != 1 {
		t.Errorf("changed %v", ch)
	}
}
