// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
	"testing"
)

// Routes that change things refuse malformed or out-of-range input with
// 400 (or 404 for a key that cannot exist) and say what is wrong, before
// they act on anything.
func TestRoutesRefuseBadInput(t *testing.T) {
	ts, _ := newRoleServer(t)
	_, out := do(t, ts, "POST", "/api/cases", `{"title":"Inputs"}`, true)
	caseID := out["case"].(map[string]any)["id"].(string)
	_, out = do(t, ts, "POST", "/api/cases/"+caseID+"/tasks", `{"titles":["Collect logs"]}`, true)
	taskID := ""
	if c, ok := out["case"].(map[string]any); ok {
		if ts, ok := c["tasks"].([]any); ok && len(ts) > 0 {
			taskID, _ = ts[0].(map[string]any)["id"].(string)
		}
	}
	if taskID == "" {
		t.Fatalf("no task: %v", out)
	}
	_, out = do(t, ts, "GET", "/api/detections", "", true)
	det := out["detections"].([]any)[0].(map[string]any)["id"].(string)
	_, out = do(t, ts, "POST", "/api/dashboards", `{"title":"Inputs","panels":[{"title":"x","query":"user=bob | stats count","viz":"table"}]}`, true)
	dash := out["id"].(string)

	for _, c := range []struct {
		method, path, body string
		status             int
		want               string
	}{
		{"POST", "/api/ask", `{`, 400, "must be JSON"},
		{"POST", "/api/ask", `{"question":"` + strings.Repeat("q", 1001) + `"}`, 400, "under 1000"},
		{"POST", "/api/ask", `{"question":"failed logins","mode":"magic"}`, 400, "mode must be"},
		{"POST", "/api/cases/" + caseID + "/tasks", `{`, 400, "must be JSON"},
		{"PATCH", "/api/cases/" + caseID + "/tasks/" + taskID, `{`, 400, "must be JSON"},
		{"PUT", "/api/case-templates", `{`, 400, "must be JSON"},
		{"PUT", "/api/compliance/notes", `{`, 400, "must be JSON"},
		{"POST", "/api/detections/backtest", `{`, 400, "must be JSON"},
		{"POST", "/api/detections/" + det + "/exceptions", `{`, 400, "must be JSON"},
		{"POST", "/api/detections/exceptions", `{`, 400, "must be JSON"},
		{"PUT", "/api/me/finding-views", `{`, 400, "must be JSON"},
		{"POST", "/api/parse", `{`, 400, "must be JSON"},
		{"POST", "/api/users", `{`, 400, "must be JSON"},
		{"PUT", "/api/users/andy", `{`, 400, "must be JSON"},
		{"PUT", "/api/auth/directory", `{`, 400, "must be JSON"},
		{"POST", "/api/auth/directory/test", `{`, 400, "must be JSON"},
		{"POST", "/api/settings/restart", `{`, 400, "must be JSON"},
		{"GET", "/api/posture?range=120d", ``, 400, "at most 90d"},
		{"GET", "/api/posture?range=soon", ``, 400, "range"},
		{"POST", "/api/dashboards/" + dash + "/run", `{`, 400, "must be JSON"},
		{"POST", "/api/dashboards/" + dash + "/run", `{"range":"5s"}`, 400, "between 1m and 366d"},
		{"POST", "/api/panels/run", `{`, 400, "must be JSON"},
		{"POST", "/api/panels/run", `{"range":"400d","panel":{"title":"x","query":"* | stats count","viz":"table"}}`, 400, "between 1m and 366d"},
		{"POST", "/api/cases/reports/keys/nope/revoke", `{}`, 404, "no report key"},
		{"POST", "/api/cases/reports/keys/0123456789ab/revoke", `{`, 400, "must be JSON"},
		{"POST", "/api/cases/reports/keys/0123456789ab/revoke", `{"reason":"bell\u0007"}`, 400, "the reason must be"},
		{"POST", "/api/cases/reports/keys/0123456789ab/revoke", `{"reason":"leaked"}`, 404, "no report key"},
	} {
		code, out := do(t, ts, c.method, c.path, c.body, true)
		if msg, _ := out["error"].(string); code != c.status || !strings.Contains(msg, c.want) {
			t.Errorf("%s %s %.40q: %d %v", c.method, c.path, c.body, code, out)
		}
	}
	// None of it reached a store: the case has its one task and no new
	// entries, and the report keys list is empty.
	if code, out := do(t, ts, "GET", "/api/cases/reports/keys", "", true); code != http.StatusOK || len(out["keys"].([]any)) != 0 {
		t.Errorf("keys: %d %v", code, out)
	}
}
