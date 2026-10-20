// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A settings file for signalith cluster apply lists the settings it sets
// at their deepest level, and refuses a file that is not YAML.
func TestReadSettingsFileKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apply.yaml")
	body := "search:\n  max_events: 500\nserver:\n  tls:\n    mode: auto\nintel:\n  feeds:\n    - name: a\n      url: https://feeds.example.com/a\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := ReadSettingsFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.FileKeys(); !slices.Equal(got, []string{"intel.feeds", "search.max_events", "server.tls.mode"}) {
		t.Errorf("file keys %v", got)
	}
	if c.Search.MaxEvents != 500 {
		t.Errorf("max_events %d", c.Search.MaxEvents)
	}
	if _, err := ReadSettingsFile(filepath.Join(dir, "missing.yaml"), nil); err == nil {
		t.Error("read a file that is not there")
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("search: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSettingsFile(bad, nil); err == nil {
		t.Error("read a file that is not YAML")
	}
	if (&Config{}).FileKeys() != nil {
		t.Error("a configuration with no layers has file keys")
	}
}

// A server that could not start with the shared settings starts with
// signalith.yaml alone and says why; one that could not start with its
// own saved settings keeps the shared ones.
func TestLoadWithoutSharedOrServerValues(t *testing.T) {
	path, sh := sharedFixture(t)
	c, err := LoadWithoutShared(path, "the shared settings fail their checks", []string{"server.public_url"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.SharedSkipped() || !strings.Contains(c.SettingsProblem(), "the shared settings fail their checks") ||
		!slices.Equal(c.SettingsProblemKeys(), []string{"server.public_url"}) {
		t.Errorf("skipped %v, problem %q, keys %v", c.SharedSkipped(), c.SettingsProblem(), c.SettingsProblemKeys())
	}
	if c.Server.PublicURL == "https://shared.example:8443" {
		t.Error("the shared value was used")
	}

	c, err = LoadWithoutServerValues(path, sh, "syslog.tcp did not start", []string{"syslog.tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if c.SharedSkipped() || !strings.Contains(c.SettingsProblem(), "syslog.tcp did not start") || c.Server.PublicURL != "https://shared.example:8443" {
		t.Errorf("problem %q, public url %s", c.SettingsProblem(), c.Server.PublicURL)
	}
	if c.Syslog.TCP == "0.0.0.0:6514" {
		t.Error("this server's own saved value was used")
	}
	if _, err := LoadWithoutShared(filepath.Join(t.TempDir(), "missing.yaml"), "x", nil); err == nil {
		t.Error("loaded a file that is not there")
	}
	if _, err := LoadWithoutServerValues(filepath.Join(t.TempDir(), "missing.yaml"), sh, "x", nil); err == nil {
		t.Error("loaded a file that is not there")
	}
}

// Setting aside a server's own value and a shared one marks both
// refused, and the server runs them at what it would without them.
func TestLoadSetAsideShared(t *testing.T) {
	path, sh := sharedFixture(t)
	c, err := LoadSetAsideShared(path, sh, []string{"syslog.tcp", "auth.session_timeout"}, "they did not start")
	if err != nil {
		t.Fatal(err)
	}
	if c.Syslog.TCP == "0.0.0.0:6514" {
		t.Error("the set-aside server value was used")
	}
	if c.Auth.SessionTimeout == "8h" {
		t.Error("the set-aside shared value was used")
	}
	if sh.Server["syslog.tcp"].Refused != "" {
		t.Error("the layer passed in was changed")
	}
	// KeptValue: a plain shared value it runs with, a secret's sealed
	// form, a default as nothing.
	full, err := LoadShared(path, sh)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := full.KeptValue("server.public_url"); err != nil || string(v) != `"https://shared.example:8443"` {
		t.Errorf("KeptValue(public_url) = %s, %v", v, err)
	}
	if v, err := full.KeptValue("search.max_events"); err != nil || v != nil {
		t.Errorf("KeptValue of a default = %s, %v", v, err)
	}
	if v, err := full.KeptValue("ingest.tokens"); err != nil || !strings.Contains(string(v), "enc:v1:") {
		t.Errorf("KeptValue(ingest.tokens) = %s, %v", v, err)
	}
	if v, err := full.KeptValue("assistant.api_key"); err != nil || v != nil {
		t.Errorf("KeptValue of an unset secret = %s, %v", v, err)
	}
}
