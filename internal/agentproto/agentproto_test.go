// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentproto

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClean(t *testing.T) {
	long := strings.Repeat("é", MaxTextLen)
	in := Status{
		Version: "0.4.0", OS: "linux", Arch: "amd64", System: "Debian GNU/Linux 12 (bookworm)",
		Revision: "0123456789abcdef0123456789abcdef", Started: "2026-10-18T01:45:40Z", ConfigError: "bad\x00\x1b[31m " + long,
		Components: []Component{
			{Name: "fluentbit", Version: "4.0.3", State: StateRunning, Restarts: -3, Error: "line 1\nline 2"},
			{Name: "<script>", State: StateRunning},
			{Name: "osquery", State: "exploded"},
		},
	}
	for range MaxComponents + 2 {
		in.Components = append(in.Components, Component{Name: "x", State: StateOff})
	}
	out := in.Clean()
	if out.Version != "0.4.0" || out.System != in.System || out.Revision != in.Revision || out.Started != in.Started {
		t.Errorf("plain fields: %+v", out)
	}
	if len(out.ConfigError) > MaxTextLen || !utf8.ValidString(out.ConfigError) || strings.ContainsAny(out.ConfigError, "\x00\x1b") {
		t.Errorf("config error: %d bytes %q...", len(out.ConfigError), out.ConfigError[:20])
	}
	if len(out.Components) != MaxComponents || out.Components[0].Restarts != 0 || out.Components[0].Error != "line 1\nline 2" {
		t.Errorf("components: %+v", out.Components)
	}
	for _, c := range out.Components {
		if c.Name == "<script>" || c.Name == "osquery" {
			t.Errorf("kept %+v", c)
		}
	}
	bad := Status{Version: "1.0\n<b>", Revision: "not hex", System: strings.Repeat("a", 200)}.Clean()
	if bad.Version != "" || bad.Revision != "" || bad.System != "" || bad.Components == nil {
		t.Errorf("bad: %+v", bad)
	}
}

func TestRevisionOf(t *testing.T) {
	a := Config{PollSeconds: 300, FluentBit: &FluentBit{Config: "a"}}
	r := RevisionOf(a)
	if len(r) != 32 {
		t.Fatalf("revision %q", r)
	}
	a.Revision = "anything"
	if RevisionOf(a) != r {
		t.Error("the revision counts itself")
	}
	a.FluentBit.Config = "b"
	if RevisionOf(a) == r {
		t.Error("a new configuration has the same revision")
	}
}

func TestProgramName(t *testing.T) {
	if ProgramName("windows", "amd64") != "signalith-agent-windows-amd64.exe" || ProgramName("linux", "arm64") != "signalith-agent-linux-arm64" {
		t.Error(ProgramName("windows", "amd64"), ProgramName("linux", "arm64"))
	}
}

func TestOsqueryFlagAllowed(t *testing.T) {
	for line, want := range map[string]bool{
		"--tls_hostname=siem.example.com:7779": true,
		"--utc":                                true,
		"--enable_ntfs_event_publisher=true":   true,
		"--extensions_autoload=/tmp/x":         false,
		"--enroll_secret_path=/tmp/x":          false,
		"--database_path=/tmp/x":               false,
		"tls_hostname=x":                       false,
		"--tls_hostname=a\x00b":                false,
		"--utc=true --extensions_autoload=/x":  false,
		"--utc=true\t--x=/y":                   false,
		"--tls_hostname=[fd00::5]:7779":        true,
		"":                                     false,
	} {
		if got := OsqueryFlagAllowed(line); got != want {
			t.Errorf("OsqueryFlagAllowed(%q) = %v, want %v", line, got, want)
		}
	}
}
