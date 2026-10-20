// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

func TestInvestigateIsOffUntilTurnedOn(t *testing.T) {
	ts, _ := newTestServer(t)
	code, info := do(t, ts, "GET", "/api/investigate", "", true)
	if code != 200 || info["enabled"] != false || info["code"] != "no_model" {
		t.Fatalf("info %d %v", code, info)
	}
	if code, out := do(t, ts, "POST", "/api/findings/x/investigate", "{}", true); code != http.StatusConflict || out["code"] != "no_model" {
		t.Errorf("without a model %d %v", code, out)
	}
	ts, _ = newTestServerWith(t, func(s *Server) { s.Assistant = assistant.New(assistant.OpenAI, "http://127.0.0.1:1/v1", "m", "") })
	if code, out := do(t, ts, "POST", "/api/findings/x/investigate/preview", "{}", true); code != http.StatusConflict || out["code"] != "off" {
		t.Errorf("turned off %d %v", code, out)
	}
	if _, info := do(t, ts, "GET", "/api/investigate", "", true); info["local"] != true || info["model"] != "m" {
		t.Errorf("info %v", info)
	}
}

func TestInvestigateStreamsAResult(t *testing.T) {
	var sent []string
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []assistant.Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		sent = append(sent, body.Messages[len(body.Messages)-1].Content)
		reply := `{"verdict":"benign","confidence":"high","summary":"masked-user-1 ran a backup.","actions":[]}`
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": reply}}}})
	}))
	defer model.Close()
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Config.Assistant.Investigate = true
		s.Config.Assistant.MaskFields = []string{"user"}
		s.Assistant = assistant.New(assistant.OpenAI, model.URL, "m", "")
		srv = s
	})
	f := &findings.Finding{ID: "f1", Title: "Odd logon", DetectionID: "manual", Severity: "low", Status: "new",
		Entities: map[string]any{"user": "carol"}, Created: time.Now().UTC()}
	if err := srv.Findings.Create(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	code, out := do(t, ts, "POST", "/api/findings/f1/investigate/preview", "{}", true)
	p, _ := out["preview"].(map[string]any)
	if code != 200 || p == nil || !strings.Contains(p["message"].(string), "masked-user-1") || strings.Contains(p["message"].(string), "carol") {
		t.Fatalf("preview %d %v", code, out)
	}
	if len(sent) != 0 {
		t.Fatal("the preview sent something to the model")
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/findings/f1/investigate", strings.NewReader("{}"))
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-ndjson" {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var last map[string]any
	types := map[string]int{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		last = nil
		if err := json.Unmarshal(sc.Bytes(), &last); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		types[last["type"].(string)]++
	}
	res, _ := last["result"].(map[string]any)
	if last["type"] != "result" || res["verdict"] != "benign" || res["summary"] != "carol ran a backup." || types["step"] == 0 || types["status"] == 0 {
		t.Fatalf("last %v, events %v", last, types)
	}
	for _, s := range sent {
		if strings.Contains(s, "carol") {
			t.Errorf("a masked value was sent: %s", s)
		}
	}
	if code, _ := do(t, ts, "POST", "/api/findings/nope/investigate", "{}", true); code != 404 {
		t.Errorf("unknown finding %d", code)
	}
}

func TestShortDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		3 * time.Minute: "3m", 90 * time.Minute: "1h30m", time.Hour: "1h", 30 * time.Second: "30s", 2 * time.Hour: "2h",
	} {
		if got := shortDuration(d); got != want {
			t.Errorf("shortDuration(%s) = %q, want %q", d, got, want)
		}
	}
}

// TestExplainAssistantTimeout: a Test that runs out of time points at the
// answer time limit.
func TestExplainAssistantTimeout(t *testing.T) {
	err := errors.New(`could not reach the AI model at http://x/v1: Post "http://x/v1/chat/completions": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`)
	msg, field := explainAssistant(err, "qwen3:4b", 3*time.Minute)
	if field != "assistant.request_timeout" || !strings.Contains(msg, "(3m)") {
		t.Errorf("got %q, %q", msg, field)
	}
}
