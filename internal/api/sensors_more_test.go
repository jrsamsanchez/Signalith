// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"slices"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
)

// The Sensors page flags a sensor that sends with a revoked token or one
// Signalith does not know, names a sensor without a name by its address,
// lists sensors needing attention first and leaves other agents out.
func TestSensorsPageFlagsTokens(t *testing.T) {
	ts, srv := newSensorServer(t)
	activeID, _ := makeToken(t, ts, "sensors", "sensor")
	revokedID, _ := makeToken(t, ts, "old sensors", "sensor")
	if code, _, raw := call(t, ts, "POST", "/api/agent-tokens/"+revokedID+"/revoke", "", "admin", adminPass, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, raw)
	}
	inv := srv.Agents
	inv.Note(agentinv.Contact{Tag: "zeek.conn", Address: "192.0.2.5", TokenID: revokedID, TokenName: "old sensors", Events: 3})
	inv.Note(agentinv.Contact{Name: "sensor-b", Tag: "suricata.eve", Address: "192.0.2.6", TokenID: "never-made", Events: 3})
	inv.Note(agentinv.Contact{Name: "sensor-a", Tag: "sensor", Address: "192.0.2.7", TokenID: activeID, TokenName: "sensors", Events: 3})
	inv.Note(agentinv.Contact{Name: "web1", Tag: "linux.syslog", Address: "192.0.2.8", TokenID: activeID, Events: 3})

	code, out := do(t, ts, "GET", "/api/sensors", "", true)
	if code != http.StatusOK {
		t.Fatalf("sensors: %d %v", code, out)
	}
	rows, _ := out["sensors"].([]any)
	byName := map[string]map[string]any{}
	var order []string
	for _, r := range rows {
		m := r.(map[string]any)
		byName[m["name"].(string)] = m
		order = append(order, m["name"].(string))
	}
	if len(rows) != 3 || byName["web1"] != nil {
		t.Fatalf("rows %v", order)
	}
	problems := func(name string) []string {
		var out []string
		for _, p := range byName[name]["problems"].([]any) {
			out = append(out, p.(string))
		}
		return out
	}
	if r := byName["192.0.2.5"]; r == nil || r["state"] != "attention" || !slices.Contains(problems("192.0.2.5"), "token") {
		t.Errorf("revoked token's sensor: %v", r)
	}
	if r := byName["sensor-b"]; r == nil || r["state"] != "attention" || !slices.Contains(problems("sensor-b"), "token") {
		t.Errorf("unknown token's sensor: %v", r)
	}
	if r := byName["sensor-a"]; r == nil || slices.Contains(problems("sensor-a"), "token") {
		t.Errorf("active token's sensor: %v", r)
	}
	rank := map[any]int{"silent": 0, "attention": 1, "healthy": 2}
	for i := 1; i < len(order); i++ {
		if rank[byName[order[i-1]]["state"]] > rank[byName[order[i]]["state"]] {
			t.Errorf("not listed worst first: %v", order)
		}
	}
	// The token list says which sensors use each sensor token.
	for _, tk := range out["tokens"].([]any) {
		m := tk.(map[string]any)
		if m["id"] == activeID {
			if used := m["used_by"].([]any); len(used) != 1 || used[0] != "sensor-a" {
				t.Errorf("used_by %v", used)
			}
		}
	}
	// tokenState: none, active, revoked, unknown.
	for id, want := range map[string]string{"": "unknown", activeID: "active", revokedID: "revoked", "never-made": "unknown"} {
		if got := srv.tokenState(id); got != want {
			t.Errorf("tokenState(%q) = %q, want %q", id, got, want)
		}
	}
}
