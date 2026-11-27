// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateDirProblemForms(t *testing.T) {
	dir := t.TempDir()
	if p := StateDirProblem(dir); p != "" {
		t.Errorf("a writable folder = %q", p)
	}
	// A folder not made yet is checked where it would be made.
	deep := filepath.Join(dir, "a", "b", "c")
	if p := StateDirProblem(deep); p != "" {
		t.Errorf("a folder to make = %q", p)
	}
	if got := NearestExisting(deep); got != dir {
		t.Errorf("NearestExisting = %q, want %q", got, dir)
	}
	// Under a file, the nearest thing that exists is not a folder.
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := StateDirProblem(filepath.Join(file, "sub")); !strings.Contains(p, "cannot write in") {
		t.Errorf("a folder under a file = %q", p)
	}
	for _, d := range StateDirFallbacks() {
		if d == "" {
			t.Error("an empty fallback state folder")
		}
	}
}

// A server's own settings are checked as the cluster's are: an address
// for other servers holds no password, and a list of addresses holds
// addresses.
func TestEditServerChecks(t *testing.T) {
	res := EditServer(&Shared{}, Edit{Values: map[string]any{
		"server.node_url":         "https://user:secret@siem-a.example:8443",
		"server.shared_addresses": []any{"not an address"},
		"syslog.udp":              ":5514",
	}, By: "ann"}, nil)
	for _, key := range []string{"server.node_url", "server.shared_addresses"} {
		if res.Fields[key] == "" {
			t.Errorf("%s was not refused: %v", key, res.Fields)
		}
	}
	if msg, refused := res.Fields["syslog.udp"]; refused {
		t.Errorf("syslog.udp refused: %q", msg)
	}
	if res.Shared.Server["syslog.udp"] == nil || res.Shared.Server["server.node_url"] != nil {
		t.Errorf("server settings = %v", res.Shared.Server)
	}
}
