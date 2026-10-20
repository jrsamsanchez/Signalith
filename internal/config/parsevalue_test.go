// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func mustLookup(t *testing.T, key string) *Setting {
	t.Helper()
	s, ok := Lookup(key)
	if !ok {
		t.Fatalf("no setting %s", key)
	}
	return s
}

// The page's values are read as each setting's own type, or refused
// saying what to enter.
func TestParseValueRefusals(t *testing.T) {
	for _, c := range []struct {
		key  string
		raw  any
		want any
		err  string
	}{
		{"search.max_events", float64(500), 500, ""},
		{"search.max_events", json.Number("600"), 600, ""},
		{"search.max_events", " 700 ", 700, ""},
		{"search.max_events", json.Number("x"), nil, "enter a whole number"},
		{"search.max_events", "", nil, "enter a whole number"},
		{"search.max_events", 1.5, nil, "enter a whole number"},
		{"search.max_events", true, nil, "enter a whole number"},
		{"server.max_connections", float64(-1), nil, "enter a number from 0 to 1000000"},
		{"ingest.hec", true, true, ""},
		{"ingest.hec", "yes", nil, "choose on or off"},
		{"server.public_url", nil, "", ""},
		{"server.public_url", 5, nil, "enter text"},
		{"server.public_url", "https://a\tb", nil, "control character"},
		{"server.shared_addresses", "10.0.0.1, 10.0.0.2\n10.0.0.3", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, ""},
		{"server.shared_addresses", []string{" a ", ""}, []string{"a"}, ""},
		{"server.shared_addresses", nil, []string{}, ""},
		{"server.shared_addresses", []any{"a", 5}, nil, "enter a list of text values"},
		{"server.shared_addresses", 5, nil, "enter a list of text values"},
		{"server.shared_addresses", []any{"a\x00b"}, nil, "control character"},
		{"assistant.api_key", " spaced key ", " spaced key ", ""},
		{"assistant.api_key", "enc:v1:abc:def", nil, "cannot start with enc:v"},
		{"cluster.leader_eligible", false, false, ""},
	} {
		got, err := ParseValue(mustLookup(t, c.key), c.raw)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s %v: %v, want %q", c.key, c.raw, err, c.err)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %v = %#v, %v", c.key, c.raw, got, err)
		}
	}
	if _, err := ParseValue(&Setting{Key: "no.such"}, "x"); err == nil {
		t.Error("an unknown setting was parsed")
	}
}

// SetValue takes a value of the setting's type, and CopyValue copies one
// between configurations.
func TestSetAndCopyValue(t *testing.T) {
	c := validConfig(t)
	if err := c.SetValue("no.such", 1); err == nil {
		t.Error("set an unknown setting")
	}
	if err := c.SetValue("search.max_events", "many"); err == nil || !strings.Contains(err.Error(), "takes a int") {
		t.Errorf("a value of another type: %v", err)
	}
	if err := c.SetValue("cluster.leader_eligible", false); err != nil || c.Cluster.LeaderEligible == nil || *c.Cluster.LeaderEligible {
		t.Errorf("leader_eligible: %v %v", err, c.Cluster.LeaderEligible)
	}
	if err := c.SetValue("server.public_url", "https://siem.example.com"); err != nil || c.Server.PublicURL != "https://siem.example.com" {
		t.Errorf("public_url: %v %s", err, c.Server.PublicURL)
	}
	if err := c.SetValue("server.agent_listen", "0.0.0.0:9443"); err != nil {
		t.Error(err)
	}
	to := validConfig(t)
	for _, key := range []string{"server.public_url", "server.agent_listen", "cluster.leader_eligible", "server.tls.mode", "search.max_events"} {
		if err := to.CopyValue(key, c); err != nil {
			t.Errorf("CopyValue(%s): %v", key, err)
		}
		if !SameValue(to, c, key) {
			t.Errorf("%s: %v, want %v", key, to.Value(key), c.Value(key))
		}
	}
	if err := to.CopyValue("no.such", c); err == nil {
		t.Error("copied an unknown setting")
	}
	for key, v := range map[string]any{
		"server.public_url": "https://user:pw@siem.example.com", "assistant.url": "https://api.example.com/?api_key=x",
	} {
		if !AddressHasSecret(key, v) {
			t.Errorf("%s %v has no secret", key, v)
		}
	}
	for key, v := range map[string]any{
		"server.public_url": "https://siem.example.com", "search.max_events": 5, "assistant.url": "",
	} {
		if AddressHasSecret(key, v) {
			t.Errorf("%s %v has a secret", key, v)
		}
	}
}
