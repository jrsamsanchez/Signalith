// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/url"
	"strings"
	"testing"
)

// Add data's Network sensor card asks for a config for the tools that
// run on the sensor and where they write; a bad path is shown under its
// input.
func TestAgentConfigSensor(t *testing.T) {
	ts, _ := newTestServer(t)
	get := func(q url.Values) (int, map[string]any) {
		q.Set("os", "linux")
		q.Set("source", "sensor")
		q.Set("server", "https://siem.example.com:8080")
		return do(t, ts, "GET", "/api/agents/config?"+q.Encode(), "", true)
	}
	code, body := get(url.Values{"zeek": {"true"}, "suricata": {"true"}, "zeek_dir": {"/nsm/zeek/logs/current"}})
	cfg, _ := body["config"].(string)
	if code != 200 || !strings.Contains(cfg, "Tag                  zeek.*\n") || !strings.Contains(cfg, "Path                 /nsm/zeek/logs/current/*.log\n") ||
		!strings.Contains(cfg, "Tag                  suricata.eve\n") || !strings.Contains(cfg, "event_type") {
		t.Fatalf("sensor config: %d %v", code, body)
	}
	if body["token_placeholder"] == nil || !strings.Contains(cfg, body["token_placeholder"].(string)) {
		t.Error("no token placeholder in the config")
	}
	// Both tools when the page names none; Suricata's protocol logs too
	// when asked.
	code, body = get(url.Values{"suricata_protocols": {"true"}})
	if cfg, _ := body["config"].(string); code != 200 || !strings.Contains(cfg, "zeek.*") || !strings.Contains(cfg, "suricata.eve") || strings.Contains(cfg, "grep") {
		t.Errorf("defaults: %d %v", code, body)
	}
	for _, c := range []struct {
		q     url.Values
		field string
	}{
		{url.Values{"zeek": {"true"}, "zeek_dir": {"bad path"}}, "zeek_dir"},
		{url.Values{"suricata": {"true"}, "zeek": {"false"}, "eve_path": {"/var/log/../shadow"}}, "eve_path"},
		{url.Values{"zeek": {"false"}, "suricata": {"false"}}, "tools"},
	} {
		code, body := get(c.q)
		if code != 400 || body["field"] != c.field || body["error"] == nil {
			t.Errorf("%v: %d %v", c.q, code, body)
		}
	}
}
