// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

func TestScopedExceptionsAPI(t *testing.T) {
	var store findings.Store
	ts, _ := newTestServerWith(t, func(s *Server) { store = s.Findings })
	code, body := do(t, ts, "GET", "/api/detections/exceptions", "", true)
	if code != 200 || len(body["exceptions"].([]any)) != 0 || body["etag"] == "" {
		t.Fatalf("list = %d %v", code, body)
	}
	etag := body["etag"].(string)
	code, body = doIf(t, ts, "POST", "/api/detections/exceptions", `{"scope":"all","match":{"host":"sccm*"},"comment":"SCCM server"}`, etag)
	if code != 200 {
		t.Fatalf("add = %d %v", code, body)
	}
	ex := body["exception"].(map[string]any)
	if ex["scope"] != "all" || ex["by"] != "admin" || ex["comment"] != "SCCM server" || len(body["exceptions"].([]any)) != 1 {
		t.Errorf("added = %v", body)
	}
	// The page's old version is refused.
	if code, _ := doIf(t, ts, "POST", "/api/detections/exceptions", `{"scope":"all","match":{"user":"ansible"}}`, etag); code != 412 {
		t.Errorf("stale add = %d", code)
	}
	for _, bad := range []string{
		`{"match":{"host":"x"}}`,                    // no scope
		`{"scope":"host:x","match":{"host":"x"}}`,   // not a scope
		`{"scope":"pack:","match":{"host":"x"}}`,    // no pack name
		`{"scope":"all","match":{}}`,                // every result, with no end
		`{"scope":"all","match":{"bad field":"x"}}`, // not a field
		`{"scope":"tag:windows","match":{"host":"x"},"for":"soon"}`,
	} {
		if code, body := do(t, ts, "POST", "/api/detections/exceptions", bad, true); code != 400 {
			t.Errorf("%s = %d %v", bad, code, body)
		}
	}
	// A maintenance window for every pack rule, with an end, is fine.
	if code, body := do(t, ts, "POST", "/api/detections/exceptions", `{"scope":"pack:sigmahq","match":{},"for":"4h"}`, true); code != 200 {
		t.Errorf("window = %d %v", code, body)
	}
	// Every detection lists its own exceptions only.
	if _, body := do(t, ts, "GET", "/api/detections/auth-brute-force", "", true); body["exceptions"] != nil {
		t.Errorf("detection = %v", body["exceptions"])
	}
	if code, _ := do(t, ts, "DELETE", "/api/detections/exceptions/ex-nope", "", true); code != 404 {
		t.Errorf("unknown = %d", code)
	}
	code, body = do(t, ts, "DELETE", "/api/detections/exceptions/"+ex["id"].(string), "", true)
	if code != 200 || len(body["exceptions"].([]any)) != 1 {
		t.Errorf("delete = %d %v", code, body)
	}

	// "Except this host from all rules" from a finding.
	f := &findings.Finding{ID: "f-1", DetectionID: "auth-brute-force", Title: "Brute force", Severity: "medium",
		Status: findings.StatusNew, Result: map[string]any{"dest": "sccm01", "src": "10.0.0.5", "count": 40},
		Created: time.Now(), Updated: time.Now()}
	if err := store.Create(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	code, body = do(t, ts, "POST", "/api/findings/f-1/suppress", `{"fields":["dest"],"scope":"all","comment":"SCCM","update":{"status":"closed","disposition":"false_positive"}}`, true)
	if code != 200 {
		t.Fatalf("suppress = %d %v", code, body)
	}
	ex = body["exception"].(map[string]any)
	if ex["scope"] != "all" || ex["finding"] != "f-1" || ex["match"].(map[string]any)["dest"] != "sccm01" {
		t.Errorf("exception = %v", ex)
	}
	if d := body["detection"].(map[string]any); d["exceptions"] != nil {
		t.Errorf("the detection got its own exception: %v", d["exceptions"])
	}
	got := body["finding"].(map[string]any)
	if c := got["comments"].([]any); got["status"] != "closed" || !strings.Contains(c[0].(map[string]any)["text"].(string), "Stopped alerting on dest=sccm01 in every detection") {
		t.Errorf("finding = %v", got)
	}
	if _, body = do(t, ts, "GET", "/api/detections/exceptions", "", true); len(body["exceptions"].([]any)) != 2 {
		t.Errorf("list = %v", body)
	}
	if code, _ := do(t, ts, "POST", "/api/findings/f-1/suppress", `{"fields":["dest"],"scope":"rules"}`, true); code != 400 {
		t.Errorf("bad scope from a finding = %d", code)
	}
}
