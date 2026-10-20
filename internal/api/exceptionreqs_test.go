// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

// An analyst proposes an exception from a finding; only an admin's
// approval adds it to the detection, once.
func TestExceptionRequests(t *testing.T) {
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) { srv = s })
	now := time.Now()
	for _, f := range []*findings.Finding{
		{ID: "f-1", DetectionID: "auth-brute-force", Title: "Brute force", Severity: "medium", Status: findings.StatusNew,
			Result: map[string]any{"user": "svc-backup", "count": 40}, Created: now, Updated: now},
		{ID: "f-2", DetectionID: "auth-brute-force", Title: "Brute force", Severity: "medium", Status: findings.StatusNew,
			Result: map[string]any{"user": "scanner"}, Created: now, Updated: now},
		{ID: "f-manual", DetectionID: "manual", Title: "By hand", Severity: "low", Status: findings.StatusNew, Created: now, Updated: now},
	} {
		if err := srv.Findings.Create(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	const anaPass = "a-fine-pass-here"
	if code, _, _ := call(t, ts, "POST", "/api/users", `{"username":"ana","role":"analyst","password":"`+anaPass+`","must_change_password":false}`, "admin", adminPass, nil); code != 201 {
		t.Fatal("create analyst")
	}
	ana := func(method, path, body string) (int, map[string]any) {
		return doAs(t, ts, "ana", anaPass, method, path, body)
	}
	for _, c := range []struct {
		id, body string
		code     int
	}{
		{"f-1", `{"fields":["user"]}`, 400},                             // no reason
		{"f-1", `{"fields":["count"],"comment":"x","for":"soon"}`, 400}, // bad duration
		{"f-1", `{"fields":["nope"],"comment":"x"}`, 400},
		{"f-manual", `{"fields":["title"],"comment":"x"}`, 400}, // no detection
		{"f-none", `{"fields":["user"],"comment":"x"}`, 404},
	} {
		if code, out := ana("POST", "/api/findings/"+c.id+"/propose-exception", c.body); code != c.code {
			t.Errorf("%s %s: %d %v", c.id, c.body, code, out)
		}
	}
	code, out := ana("POST", "/api/findings/f-1/propose-exception", `{"fields":["user"],"for":"30d","comment":"the nightly backup job","update":{"status":"closed","disposition":"false_positive"}}`)
	if code != http.StatusOK {
		t.Fatalf("propose: %d %v", code, out)
	}
	id := out["request"].(map[string]any)["id"].(string)
	if f := out["finding"].(map[string]any); f["status"] != "closed" || !strings.Contains(f["comments"].([]any)[0].(map[string]any)["text"].(string), "Proposed an exception") {
		t.Errorf("finding after the proposal: %v", f["status"])
	}
	// The same ask again waits on the first.
	if code, out := ana("POST", "/api/findings/f-1/propose-exception", `{"fields":["user"],"comment":"again"}`); code != http.StatusConflict {
		t.Errorf("duplicate: %d %v", code, out)
	}
	// The detection has no exception yet; the analyst cannot approve.
	if d, _ := srv.Detections.Get("auth-brute-force"); len(d.Exceptions) != 0 {
		t.Errorf("exception added before approval: %v", d.Exceptions)
	}
	if code, _ := ana("POST", "/api/exception-requests/"+id+"/approve", `{}`); code != http.StatusForbidden {
		t.Errorf("analyst approves: %d", code)
	}
	code, out = ana("GET", "/api/exception-requests", "")
	if code != 200 || out["pending"] != float64(1) {
		t.Fatalf("list: %d %v", code, out)
	}

	if code, _ := do(t, ts, "POST", "/api/exception-requests/er-zz/approve", `{}`, true); code != http.StatusNotFound {
		t.Errorf("bad id: %d", code)
	}
	code, out = do(t, ts, "POST", "/api/exception-requests/"+id+"/approve", `{"note":"ok, ticket 42"}`, true)
	if code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, out)
	}
	d, _ := srv.Detections.Get("auth-brute-force")
	if len(d.Exceptions) != 1 || d.Exceptions[0].Match["user"] != "svc-backup" || d.Exceptions[0].ProposedBy != "ana" || d.Exceptions[0].By != "admin" ||
		d.Exceptions[0].Until == nil || d.Exceptions[0].Until.Before(now.Add(29*24*time.Hour)) {
		t.Errorf("exception %+v", d.Exceptions)
	}
	// Approving twice adds nothing.
	if code, _ := do(t, ts, "POST", "/api/exception-requests/"+id+"/approve", `{}`, true); code != http.StatusConflict {
		t.Errorf("second approval: %d", code)
	}
	if d, _ := srv.Detections.Get("auth-brute-force"); len(d.Exceptions) != 1 {
		t.Errorf("exceptions after a second approval: %d", len(d.Exceptions))
	}

	// A declined request adds nothing and says why on the finding.
	_, out = ana("POST", "/api/findings/f-2/propose-exception", `{"fields":["user"],"comment":"just a scanner"}`)
	id2 := out["request"].(map[string]any)["id"].(string)
	if code, out := do(t, ts, "POST", "/api/exception-requests/"+id2+"/decline", `{"note":"scanners should be allow-listed by IP"}`, true); code != 200 {
		t.Fatalf("decline: %d %v", code, out)
	}
	if d, _ := srv.Detections.Get("auth-brute-force"); len(d.Exceptions) != 1 {
		t.Errorf("exceptions after a decline: %d", len(d.Exceptions))
	}
	f, _ := srv.Findings.Get(context.Background(), "f-2")
	if last := f.Comments[len(f.Comments)-1]; !strings.Contains(last.Text, "Declined") || !strings.Contains(last.Text, "allow-listed") {
		t.Errorf("finding note %+v", last)
	}
	_, out = ana("GET", "/api/exception-requests", "")
	if out["pending"] != float64(0) || len(out["requests"].([]any)) != 2 {
		t.Errorf("list after: %v", out)
	}
}
