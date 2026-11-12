// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSharedRevs(t *testing.T) {
	sh := &Shared{Cluster: map[string]SharedValue{"search.max_events": {Rev: 4}}, Revs: map[string]int64{"search.summary_days": 2}}
	if sh.Rev("search.max_events") != 4 || sh.Rev("search.summary_days") != 2 || sh.Rev("nope") != 0 {
		t.Errorf("Rev = %d %d %d", sh.Rev("search.max_events"), sh.Rev("search.summary_days"), sh.Rev("nope"))
	}
	custom := &Shared{Hash: func(string, SharedValue) string { return "h" }}
	if custom.hash("x", SharedValue{}) != "h" {
		t.Error("Shared.Hash is not used")
	}
}

func TestKeptValues(t *testing.T) {
	v, err := keptValue("assistant.api_key", json.RawMessage(`{"secret": "s", "sent_to": "https://a:443"}`))
	if err != nil || v.Secret != "s" || v.SentTo != "https://a:443" {
		t.Errorf("a kept secret = %+v %v", v, err)
	}
	if _, err := keptValue("assistant.api_key", json.RawMessage(`[1]`)); err == nil {
		t.Error("a kept secret that is not one")
	}
	if v, err := keptValue("assistant.api_key", json.RawMessage(`null`)); err != nil || v.Secret != "" {
		t.Errorf("a kept null secret = %+v %v", v, err)
	}
	if v, err := keptValue("search.max_events", json.RawMessage(`600`)); err != nil || string(v.Value) != "600" {
		t.Errorf("a kept value = %+v %v", v, err)
	}
	c := Default()
	if r, ok := c.SharedKept("search.max_events"); ok || r.Reason != "" {
		t.Error("a config without layers keeps a value")
	}
	if got, err := c.KeptValue("assistant.api_key"); err != nil || got != nil {
		t.Errorf("KeptValue without layers = %s %v", got, err)
	}
	if got := c.SourceValues("search.max_events"); got != nil {
		t.Errorf("SourceValues without layers = %v", got)
	}
}

func TestCheckEditSharedEachScope(t *testing.T) {
	path := writeConfig(t, "")
	sh := &Shared{Self: "siem-a"}
	if _, err := CheckEditShared(path, sh, Scope("nowhere"), Edit{}); err == nil || !strings.Contains(err.Error(), "no settings have the scope") {
		t.Errorf("an unknown scope = %v", err)
	}
	// A secret without the cluster's key to seal it with.
	res, err := CheckEditShared(path, sh, ScopeCluster, Edit{Values: map[string]any{"assistant.url": "https://llm.example/v1", "assistant.api_key": "sk-x"}})
	if err == nil && res.OK() {
		t.Error("a secret was saved without the cluster's key")
	}
	// A setting of another scope is refused at its field.
	res, err = CheckEditShared(path, sh, ScopeServer, Edit{Values: map[string]any{"search.max_events": float64(700)}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Fields["search.max_events"], "This setting is one of") {
		t.Errorf("another scope's setting = %v", res.Fields)
	}
	// A server's own setting on its page.
	res, err = CheckEditShared(path, sh, ScopeServer, Edit{Values: map[string]any{"server.max_connections": float64(700)}, By: "sam"})
	if err != nil || !res.OK() {
		t.Fatalf("server setting = %v %v", err, res.Fields)
	}
	if e := res.Shared.Server["server.max_connections"]; e == nil || e.Value.Value != "700" {
		t.Errorf("server entry = %+v", e)
	}
	// Retry a shared value this server refused.
	sh.Refused = map[string]SharedRefusal{"search.max_events": {Reason: "no"}}
	res, err = CheckEditShared(path, sh, ScopeCluster, Edit{Retry: []string{"search.max_events", "search.summary_days"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Shared.Refused["search.max_events"]; ok {
		t.Error("a retried refusal is kept")
	}
	// Reset a shared value.
	sh.Cluster = map[string]SharedValue{"search.max_events": {Value: jsonOf(t, 600)}}
	res, err = CheckEditShared(path, sh, ScopeCluster, Edit{Reset: []string{"search.max_events"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Shared.Cluster["search.max_events"]; ok {
		t.Error("a reset shared value is kept")
	}
}

func TestEditServerRefusals(t *testing.T) {
	sh := &Shared{}
	res := EditServer(sh, Edit{Values: map[string]any{
		"no.such":                "x",
		"search.max_events":      float64(5),
		"server.max_connections": "lots",
		"server.listen":          "127.0.0.1:9443",
	}}, map[string]string{"server.listen": "SIGNALITH_LISTEN"})
	if res.Fields["no.such"] == "" || !strings.Contains(res.Fields["search.max_events"], "This setting is one of") ||
		res.Fields["server.max_connections"] == "" || res.Fields["server.listen"] == "" {
		t.Errorf("fields = %v", res.Fields)
	}
	if len(res.Shared.Server) != 0 {
		t.Errorf("refused values were saved: %v", res.Shared.Server)
	}
}
