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
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/ingest"
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
	// Not while a server of the cluster is older than computer keys.
	s.AgentHostKeys = func() bool { return false }
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteEnroll, line, "web-01", "{}", nil); code != http.StatusConflict || !strings.Contains(body, codeHostKeysWait) {
		t.Errorf("below the level: %d %s", code, body)
	}
	s.AgentHostKeys = nil
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

// ING-202, RT-201: a batch that names its computer in the events (an
// OpenTelemetry resource's host.name, an HEC event's host) and not in the
// X-Signalith-Agent header is held to the same rule: sent with a line's
// token, it does not move the row of a computer that has its own key.
func TestEnrolledRowNotMovedByBatchHostName(t *testing.T) {
	ts, s := newSensorServer(t)
	s.Config.Ingest.HEC = true
	_, line := makeToken(t, ts, "Web servers", "agent")
	_, other := makeToken(t, ts, "Linux", "linux")
	st := `{"version":"0.4.0","os":"linux","arch":"amd64","components":[{"name":"fluentbit","state":"running"}]}`
	code, _, body := agentDo(t, ts, "POST", agentproto.RouteEnroll, line, "web-01", "{}", nil)
	var e agentproto.Enrolled
	if code != 200 || json.Unmarshal([]byte(body), &e) != nil {
		t.Fatalf("enroll: %d %s", code, body)
	}
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteStatus, e.Key, "web-01", st, nil); code != http.StatusNoContent {
		t.Fatalf("status: %d %s", code, body)
	}
	list, _, _ := s.agents().List(t.Context())
	if len(list) != 1 || list[0].Name != "web-01" {
		t.Fatalf("agents: %+v", list)
	}
	before := list[0]
	unmoved := func(what string) {
		t.Helper()
		list, _, _ := s.agents().List(t.Context())
		if len(list) != 1 {
			t.Fatalf("%s: agents: %+v", what, list)
		}
		if a := list[0]; !a.LastSeen.Equal(before.LastSeen) || a.TokenID != before.TokenID || a.Intake != before.Intake {
			t.Errorf("%s moved the row of a computer with its own key: last seen %s (was %s), token %s (was %s), intake %s (was %s)",
				what, a.LastSeen, before.LastSeen, a.TokenID, before.TokenID, a.Intake, before.Intake)
		}
	}
	otlp := func(host string) string {
		return `{"resourceLogs":[{"resource":{"attributes":[{"key":"host.name","value":{"stringValue":"` + host + `"}}]},"scopeLogs":[{"logRecords":[{"body":{"stringValue":"forged"}}]}]}]}`
	}
	isJSON := map[string]string{"Content-Type": "application/json"}
	for name, tok := range map[string]string{"another line's token": other, "its line's token": line} {
		for _, host := range []string{"web-01", "WEB-01"} {
			// The events are kept; the row stays.
			if code, _, body := agentDo(t, ts, "POST", "/api/otlp/v1/logs", tok, "", otlp(host), isJSON); code != 200 {
				t.Fatalf("OTLP with %s: %d %s", name, code, body)
			}
			unmoved("an OTLP batch for " + host + " with " + name)
		}
		if code, _, body := agentDo(t, ts, "POST", "/services/collector/event", tok, "", `{"event":"forged","host":"web-01"}`, nil); code != 200 {
			t.Fatalf("HEC with %s: %d %s", name, code, body)
		}
		unmoved("an HEC event with " + name)
	}
	// A computer without a key is still listed by the name in its batch.
	if code, _, body := agentDo(t, ts, "POST", "/api/otlp/v1/logs", other, "", otlp("db-01"), isJSON); code != 200 {
		t.Fatalf("OTLP for db-01: %d %s", code, body)
	}
	list, _, _ = s.agents().List(t.Context())
	if len(list) != 2 {
		t.Fatalf("agents after db-01's batch: %+v", list)
	}
	// And the computer's own key moves its row, whatever name the batch
	// carries.
	if code, _, body := agentDo(t, ts, "POST", "/api/otlp/v1/logs", e.Key, "", otlp("db-01"), isJSON); code != 200 {
		t.Fatalf("OTLP with the key: %d %s", code, body)
	}
	list, _, _ = s.agents().List(t.Context())
	if len(list) != 2 {
		t.Fatalf("agents after the key's batch: %+v", list)
	}
	for _, a := range list {
		if a.Name == "web-01" && a.Intake != ingest.IntakeOTLP {
			t.Errorf("the key's own batch did not move its row: %+v", a)
		}
		if a.Name == "db-01" && a.TokenID == before.TokenID {
			t.Errorf("web-01's key moved db-01's row: %+v", a)
		}
	}
}

// RT-206: osquery enrollment follows the same rule. A line's token can't
// enroll a host in the name of a computer that has its own key, nor
// replace the record of a host enrolled with such a key.
func TestOsqueryEnrollRespectsHostKeys(t *testing.T) {
	ts, s := newSensorServer(t)
	nodes := endpoint.NewStore(endpoint.NewMemoryDocs(), "signalith")
	s.Endpoints = nodes
	_, line := makeToken(t, ts, "Web servers", "agent")
	code, _, body := agentDo(t, ts, "POST", agentproto.RouteEnroll, line, "web-01", "{}", nil)
	var e agentproto.Enrolled
	if code != 200 || json.Unmarshal([]byte(body), &e) != nil {
		t.Fatalf("enroll: %d %s", code, body)
	}
	enroll := func(secret, id, host string) (int, string) {
		t.Helper()
		req := `{"enroll_secret":"` + secret + `","host_identifier":"` + id + `","host_details":{"system_info":{"hostname":"` + host + `","uuid":"` + id + `"}}}`
		code, _, body := agentDo(t, ts, "POST", "/api/osquery/enroll", "", "", req, nil)
		return code, body
	}
	count := func() int {
		t.Helper()
		list, err := nodes.Nodes(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return len(list)
	}
	if code, body := enroll(e.Key, "UUID-1", "web-01"); code != 200 || !strings.Contains(body, "node_key") {
		t.Fatalf("with the computer's key: %d %s", code, body)
	}
	for _, name := range []string{"web-01", "WEB-01"} {
		if code, body := enroll(line, "UUID-9", name); code != http.StatusForbidden || !strings.Contains(body, `"node_invalid":true`) || !strings.Contains(body, "its own key") {
			t.Errorf("line token as %s: %d %s", name, code, body)
		}
	}
	if code, body := enroll(line, "UUID-1", "some-other-name"); code != http.StatusForbidden || !strings.Contains(body, `"node_invalid":true`) {
		t.Errorf("line token with the keyed host's identifier: %d %s", code, body)
	}
	if n := count(); n != 1 {
		t.Fatalf("%d osquery hosts after the refused enrollments, want 1", n)
	}
	// Another computer's key is no better than the line's token.
	code, _, body = agentDo(t, ts, "POST", agentproto.RouteEnroll, line, "web-02", "{}", nil)
	var e2 agentproto.Enrolled
	if code != 200 || json.Unmarshal([]byte(body), &e2) != nil {
		t.Fatalf("enroll web-02: %d %s", code, body)
	}
	if code, body := enroll(e2.Key, "UUID-2", "web-01"); code != http.StatusForbidden {
		t.Errorf("web-02's key as web-01: %d %s", code, body)
	}
	if code, body := enroll(e2.Key, "UUID-1", "web-02"); code != http.StatusForbidden {
		t.Errorf("web-02's key with web-01's identifier: %d %s", code, body)
	}
	// Computers without a key enroll with the line's token as before, and
	// a keyed one enrolls again with its key.
	if code, body := enroll(line, "UUID-3", "db-01"); code != 200 {
		t.Errorf("line token, no key: %d %s", code, body)
	}
	if code, body := enroll(line, "UUID-3", "db-01"); code != 200 {
		t.Errorf("line token again: %d %s", code, body)
	}
	if code, body := enroll(e.Key, "UUID-1", "web-01"); code != 200 {
		t.Errorf("the key again: %d %s", code, body)
	}
	if n := count(); n != 2 {
		t.Errorf("%d osquery hosts, want 2", n)
	}
}
