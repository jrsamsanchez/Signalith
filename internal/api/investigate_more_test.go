// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

// A model that fails ends the stream with an error event; a findings
// store that fails is a 502 before anything is sent.
func TestInvestigateFailures(t *testing.T) {
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"the model is not loaded"}}`, http.StatusBadRequest)
	}))
	defer model.Close()
	store := &failFindings{}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Config.Assistant.Investigate = true
		s.Assistant = assistant.New(assistant.OpenAI, model.URL, "m", "")
		store.Store = s.Findings
		s.Findings = store
		s.Scheduler.Findings = store
	})
	f := &findings.Finding{ID: "f1", Title: "Odd logon", DetectionID: "manual", Severity: "low", Status: "new",
		Entities: map[string]any{"user": "carol"}, Created: time.Now().UTC()}
	if err := store.Create(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/findings/f1/investigate", strings.NewReader("{}"))
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var last map[string]any
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		last = nil
		if err := json.Unmarshal(sc.Bytes(), &last); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
	}
	if resp.StatusCode != http.StatusOK || last["type"] != "error" || !strings.Contains(last["text"].(string), "not loaded") {
		t.Errorf("model fails: %d %v", resp.StatusCode, last)
	}

	store.failing(errDown)
	for _, path := range []string{"/api/findings/f1/investigate", "/api/findings/f1/investigate/preview"} {
		if code, _ := do(t, ts, "POST", path, "{}", true); code != http.StatusBadGateway {
			t.Errorf("%s with the store failing: %d", path, code)
		}
	}
	store.failing(nil)
}
