package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

func TestDetectionExceptionsAPI(t *testing.T) {
	var store findings.Store
	ts, _ := newTestServerWith(t, func(s *Server) { store = s.Findings })
	code, body := do(t, ts, "POST", "/api/detections/auth-brute-force/exceptions", `{"match":{"src":"203.0.113.*"},"for":"7d","comment":"our scanner"}`, true)
	if code != 200 {
		t.Fatalf("add = %d %v", code, body)
	}
	ex := body["exception"].(map[string]any)
	if ex["by"] != "admin" || ex["until"] == nil || ex["comment"] != "our scanner" {
		t.Errorf("exception = %v", ex)
	}
	d := body["detection"].(map[string]any)
	if d["source"] != "builtin" || len(d["exceptions"].([]any)) != 1 {
		t.Errorf("detection = %v", d)
	}
	for _, bad := range []string{`{"match":{}}`, `{"match":{"src":""}}`, `{"match":{"src":"x"},"for":"soon"}`, `{"match":{"src":"x"},"until":"2001-01-01T00:00:00Z"}`} {
		if code, body := do(t, ts, "POST", "/api/detections/auth-brute-force/exceptions", bad, true); code != 400 {
			t.Errorf("%s = %d %v", bad, code, body)
		}
	}
	if code, _ := do(t, ts, "POST", "/api/detections/no-such/exceptions", `{"match":{"src":"x"}}`, true); code != 404 {
		t.Errorf("unknown detection = %d", code)
	}
	id := ex["id"].(string)
	if code, _ := do(t, ts, "DELETE", "/api/detections/auth-brute-force/exceptions/ex-nope", "", true); code != 404 {
		t.Errorf("unknown exception = %d", code)
	}
	code, body = do(t, ts, "DELETE", "/api/detections/auth-brute-force/exceptions/"+id, "", true)
	if code != 200 || body["detection"].(map[string]any)["exceptions"] != nil {
		t.Errorf("delete = %d %v", code, body)
	}

	// "Don't alert on this host again" from a finding, closing it.
	f := &findings.Finding{ID: "f-1", DetectionID: "auth-brute-force", Title: "Brute force", Severity: "medium",
		Status: findings.StatusNew, Result: map[string]any{"dest": "web1", "src": "203.0.113.9", "count": 40},
		Created: time.Now(), Updated: time.Now()}
	if err := store.Create(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	code, body = do(t, ts, "POST", "/api/findings/f-1/suppress",
		`{"fields":["dest"],"for":"30d","comment":"test server","update":{"status":"closed","disposition":"benign_true_positive"}}`, true)
	if code != 200 {
		t.Fatalf("suppress = %d %v", code, body)
	}
	ex = body["exception"].(map[string]any)
	if m := ex["match"].(map[string]any); m["dest"] != "web1" || len(m) != 1 || ex["finding"] != "f-1" {
		t.Errorf("exception = %v", ex)
	}
	got := body["finding"].(map[string]any)
	comments := got["comments"].([]any)
	if got["status"] != "closed" || got["disposition"] != "benign_true_positive" || len(comments) != 1 ||
		!strings.Contains(comments[0].(map[string]any)["text"].(string), "Stopped alerting on dest=web1 until") {
		t.Errorf("finding = %v", got)
	}
	if code, _ := do(t, ts, "POST", "/api/findings/f-1/suppress", `{"fields":["user"]}`, true); code != 400 {
		t.Errorf("field the finding lacks = %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/findings/f-1/suppress", `{"fields":[]}`, true); code != 400 {
		t.Errorf("no fields = %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/findings/nope/suppress", `{"fields":["dest"]}`, true); code != 404 {
		t.Errorf("unknown finding = %d", code)
	}
}
