// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/nlq"
)

func TestAskWithoutAI(t *testing.T) {
	ts, _ := newTestServer(t)
	code, info := do(t, ts, "GET", "/api/ask", "", true)
	if code != 200 || info["ai_available"] != false || len(info["examples"].([]any)) == 0 {
		t.Fatalf("info %d %v", code, info)
	}
	// A name from the identity list is recognized as a user.
	if code, _ := do(t, ts, "PUT", "/api/lookups/identities", "identity,priority\ncarol,high\n", true); code != 200 {
		t.Fatalf("upload %d", code)
	}
	code, out := do(t, ts, "POST", "/api/ask", `{"question":"failed logins by carol in the last 4 hours"}`, true)
	if code != 200 || out["query"] != "datamodel=Authentication action=failure user=carol earliest=-4h" || out["source"] != "rules" {
		t.Fatalf("ask %d %v", code, out)
	}
	if len(out["steps"].([]any)) != 4 || len(out["explanation"].([]any)) == 0 {
		t.Errorf("steps %v explanation %v", out["steps"], out["explanation"])
	}
	if out["run"] != true {
		t.Errorf("a fully understood question is not run: %v", out)
	}
	// Half understood, with no AI model: shown, not run.
	if code, out := do(t, ts, "POST", "/api/ask", `{"question":"service account logins from workstations"}`, true); code != 200 || out["run"] != false {
		t.Errorf("half understood %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/ask", `{"question":"x","mode":"ai"}`, true); code != 400 || !strings.Contains(out["error"].(string), "Settings page") {
		t.Errorf("ai without model %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/ask", `{"question":"  "}`, true); code != 400 {
		t.Errorf("empty %d", code)
	}
}

func TestAskFallsBackToAI(t *testing.T) {
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "text",
			"text": "datamodel=Endpoint process_name=wmic.exe process=\"*process call create*\""}}})
	}))
	defer model.Close()
	ts, _ := newTestServerWith(t, func(s *Server) { s.Assistant = assistant.New(assistant.Anthropic, model.URL, "", "k") })

	// The built-in translator understands this one fully, so no AI call.
	code, out := do(t, ts, "POST", "/api/ask", `{"question":"failed logins today"}`, true)
	if code != 200 || out["source"] != "rules" || out["ai_available"] != true {
		t.Fatalf("rules %d %v", code, out)
	}
	// It does not understand this one, so auto mode asks the model.
	code, out = do(t, ts, "POST", "/api/ask", `{"question":"lateral movement via wmi remote process creation"}`, true)
	if code != 200 || out["source"] != "ai" || !strings.Contains(out["query"].(string), "wmic.exe") || out["ai_model"] != "claude-sonnet-5-5" || out["run"] != true {
		t.Fatalf("ai %d %v", code, out)
	}
	// Rules only, when asked.
	code, out = do(t, ts, "POST", "/api/ask", `{"question":"lateral movement via wmi remote process creation","mode":"rules"}`, true)
	if code != 200 || out["source"] != "rules" {
		t.Fatalf("rules mode %d %v", code, out)
	}
}

func TestAskReportsAIErrors(t *testing.T) {
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"overloaded"}}`, http.StatusServiceUnavailable)
	}))
	defer model.Close()
	ts, _ := newTestServerWith(t, func(s *Server) { s.Assistant = assistant.New(assistant.OpenAI, model.URL, "m", "") })
	code, out := do(t, ts, "POST", "/api/ask", `{"question":"something odd from 10.0.0.1","mode":"ai"}`, true)
	if code != 200 || out["source"] != "rules" || !strings.Contains(out["ai_error"].(string), "overloaded") || out["query"] != "src=10.0.0.1" {
		t.Fatalf("%d %v", code, out)
	}
}

// Every example under the Ask box is understood well enough to run.
func TestAskExamplesAreUnderstood(t *testing.T) {
	for _, q := range askExamples {
		r, err := nlq.Translate(q, nil)
		if err != nil || r.Confidence < aiThreshold {
			t.Errorf("%q: %v, confidence %.2f, unknown %v", q, err, r.Confidence, r.Unknown)
		}
	}
}
