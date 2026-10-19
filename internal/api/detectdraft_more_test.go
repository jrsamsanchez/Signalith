// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/assistant"
)

// With an AI model the draft is the model's rule; a model that fails
// leaves the offline draft, with the error. "rules" never asks it.
func TestDraftDetectionWithAI(t *testing.T) {
	var calls atomic.Int32
	var fail atomic.Bool
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			http.Error(w, `{"error":{"message":"overloaded"}}`, http.StatusInternalServerError)
			return
		}
		reply := `{"title":"Many failed logins from one source","query":"action=failure | stats count by src | where count>20",` +
			`"schedule":"5m","lookback":"10m","severity":"high","guidance":"Check the source."}`
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": reply}}}})
	}))
	defer model.Close()
	ts, _ := newTestServerWith(t, func(s *Server) { s.Assistant = assistant.New(assistant.OpenAI, model.URL, "m", "") })
	desc := `"description":"Alert me when more than 20 failed logins come from the same source in 10 minutes"`

	code, out := do(t, ts, "POST", "/api/detections/draft", `{`+desc+`,"mode":"ai"}`, true)
	if code != http.StatusOK || out["ai_model"] == nil || out["ai_available"] != true {
		t.Fatalf("ai: %d %v", code, out)
	}
	d := out["draft"].(map[string]any)["detection"].(map[string]any)
	if d["severity"] != "high" || !strings.Contains(d["query"].(string), "count>20") {
		t.Errorf("the model's draft: %v", d)
	}

	n := calls.Load()
	if code, out := do(t, ts, "POST", "/api/detections/draft", `{`+desc+`,"mode":"rules"}`, true); code != http.StatusOK || out["ai_model"] != nil || calls.Load() != n {
		t.Errorf("rules only: %d %v", code, out)
	}

	fail.Store(true)
	code, out = do(t, ts, "POST", "/api/detections/draft", `{`+desc+`}`, true)
	if code != http.StatusOK || out["ai_error"] == nil || out["draft"].(map[string]any)["source"] != "rules" {
		t.Errorf("model fails: %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/detections/draft", `{`, true); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
}
