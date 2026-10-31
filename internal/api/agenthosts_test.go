// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/agenttokens"
)

// ASI-102: a computer trades its line's token for a key of its own, and
// the line's token can then no longer report in its name.
func TestAgentHostKeys(t *testing.T) {
	ts, s := newSensorServer(t)
	_, line := makeToken(t, ts, "Web servers", "agent")
	_, linux := makeToken(t, ts, "Linux", "linux")
	st := `{"version":"0.4.0","os":"linux","arch":"amd64","components":[{"name":"fluentbit","state":"running"}]}`

	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteEnroll, linux, "web-01", "{}", nil); code != http.StatusForbidden {
		t.Errorf("linux token enrolls: %d %s", code, body)
	}
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteEnroll, line, "", "{}", nil); code != http.StatusBadRequest {
		t.Errorf("no name: %d %s", code, body)
	}
	code, h, body := agentDo(t, ts, "POST", agentproto.RouteEnroll, line, "Web-01", "{}", nil)
	var e agentproto.Enrolled
	if code != 200 || json.Unmarshal([]byte(body), &e) != nil || !agentproto.IsHostKey(e.Key) || e.Host != "web-01" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("enroll: %d %s", code, body)
	}
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteEnroll, line, "web-01", "{}", nil); code != http.StatusConflict || !strings.Contains(body, agenttokens.CodeHostEnrolled) {
		t.Errorf("second enroll: %d %s", code, body)
	}
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteEnroll, e.Key, "web-01", "{}", nil); code != http.StatusConflict {
		t.Errorf("enroll with the key: %d %s", code, body)
	}

	// The key works for its own computer only.
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteStatus, e.Key, "web-01", st, nil); code != http.StatusNoContent {
		t.Fatalf("status with key: %d %s", code, body)
	}
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteStatus, e.Key, "db-01", st, nil); code != http.StatusForbidden || !strings.Contains(body, agenttokens.CodeHostMismatch) {
		t.Errorf("key for another computer: %d %s", code, body)
	}
	if code, _, body := agentDo(t, ts, "GET", agentproto.RouteConfig+"?os=linux&arch=amd64&server=https://siem:7779", e.Key, "web-01", "", nil); code != 200 {
		t.Errorf("config with key: %d %s", code, body)
	}
	// The line's token can't report as the computer that has a key...
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteStatus, line, "WEB-01", st, nil); code != http.StatusConflict || !strings.Contains(body, agenttokens.CodeHostEnrolled) {
		t.Errorf("line token for an enrolled computer: %d %s", code, body)
	}
	// ...and its events in that name don't move the computer's row.
	list, _, _ := s.agents().List(t.Context())
	if len(list) != 1 {
		t.Fatalf("agents: %+v", list)
	}
	seen := list[0].LastSeen
	if code, _, body := agentDo(t, ts, "POST", "/api/ingest", line, "web-01", `[{"msg":"forged"}]`, nil); code != 200 {
		t.Fatalf("ingest: %d %s", code, body)
	}
	if list, _, _ = s.agents().List(t.Context()); len(list) != 1 || !list[0].LastSeen.Equal(seen) {
		t.Errorf("forged events moved the row: %+v", list)
	}
	// Computers without a key still report with the line's token.
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteStatus, line, "web-02", st, nil); code != http.StatusNoContent {
		t.Errorf("line token, no key: %d %s", code, body)
	}

	// Listed for analysts, never with a key.
	code, out, raw := call(t, ts, "GET", "/api/agent-hosts", "", "admin", adminPass, nil)
	if hosts, _ := out["hosts"].([]any); code != 200 || len(hosts) != 1 || strings.Contains(raw, e.Key[4:]) {
		t.Fatalf("list: %d %s", code, raw)
	}

	// Revoked: refused, and nothing enrolls in its name.
	if code, _, raw := call(t, ts, "POST", "/api/agent-hosts/web-01/revoke", "", "admin", adminPass, nil); code != 200 {
		t.Fatalf("revoke: %d %s", code, raw)
	}
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteStatus, e.Key, "web-01", st, nil); code != http.StatusUnauthorized || !strings.Contains(body, "token_revoked") {
		t.Errorf("revoked key: %d %s", code, body)
	}
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteEnroll, line, "web-01", "{}", nil); code != http.StatusConflict || !strings.Contains(body, agenttokens.CodeHostRevoked) {
		t.Errorf("enroll a revoked name: %d %s", code, body)
	}
	// Released: the key is unknown, and the computer enrolls again.
	if code, _, raw := call(t, ts, "POST", "/api/agent-hosts/web-01/release", "", "admin", adminPass, nil); code != 200 {
		t.Fatalf("release: %d %s", code, raw)
	}
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteStatus, e.Key, "web-01", st, nil); code != http.StatusUnauthorized || !strings.Contains(body, "token_unknown") {
		t.Errorf("released key: %d %s", code, body)
	}
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteEnroll, line, "web-01", "{}", nil); code != 200 {
		t.Errorf("enroll again: %d %s", code, body)
	}
	if code, _, raw := call(t, ts, "POST", "/api/agent-hosts/nobody/release", "", "admin", adminPass, nil); code != 404 {
		t.Errorf("release unknown: %d %s", code, raw)
	}
}
