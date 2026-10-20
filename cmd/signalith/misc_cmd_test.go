// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/upgradecheck"
)

func TestPrintUpgrade(t *testing.T) {
	print := func(v upgradeVerdict) string {
		var out bytes.Buffer
		printUpgrade(&clusterCLI{out: &out}, v)
		return out.String()
	}
	servers := []upgradecheck.Server{{Name: "siem-a", Version: "1.4.0", State: "ready", Jobs: true, CaughtUp: "yes"}, {Name: "siem-b", Version: "1.4.0", State: "ready", CaughtUp: "no"}}

	out := print(upgradeVerdict{Single: true, Servers: servers[:1], Next: "Only this server uses this OpenSearch: upgrade it."})
	if !strings.Contains(out, "siem-a") || !strings.Contains(out, "runs them") || !strings.HasSuffix(out, "Only this server uses this OpenSearch: upgrade it.\n") || strings.Contains(out, "Safe") {
		t.Errorf("single:\n%s", out)
	}
	out = print(upgradeVerdict{Safe: true, Current: "1.4.0", Servers: servers})
	if !strings.Contains(out, "Safe to start an upgrade.") || !strings.Contains(out, "Every server runs ") {
		t.Errorf("safe, one version:\n%s", out)
	}
	out = print(upgradeVerdict{Servers: servers, Blockers: []upgradecheck.Note{{Text: "siem-b has not caught up"}},
		Warnings: []upgradecheck.Note{{Text: "siem-c is offline"}}, Next: "Wait for siem-b."})
	for _, want := range []string{"Not safe yet:\n  - siem-b has not caught up\n", "\nWarnings:\n  - siem-c is offline\n", "\nWait for siem-b.\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("not safe lacks %q:\n%s", want, out)
		}
	}
}

func TestAgentProgramsCommandErrors(t *testing.T) {
	var out bytes.Buffer
	if err := runAgentPrograms(nil, &out); err == nil || !strings.Contains(out.String(), "agent-programs") {
		t.Errorf("no command: %v\n%s", err, out.String())
	}
	if err := runAgentPrograms([]string{"bogus"}, &out); err == nil || !strings.Contains(err.Error(), `unknown agent-programs command "bogus"`) {
		t.Errorf("bogus: %v", err)
	}
	if err := runAgentPrograms([]string{"status", "-nosuchflag"}, &out); err == nil {
		t.Error("an unknown flag was taken")
	}
	t.Setenv("SIGNALITH_AGENT_KEY", "")
	if err := runAgentPrograms([]string{"pubkey"}, &out); err == nil || !strings.Contains(err.Error(), "SIGNALITH_AGENT_KEY is not set") {
		t.Errorf("pubkey with no key: %v", err)
	}
	t.Setenv("SIGNALITH_AGENT_KEY", "not-a-key")
	if err := runAgentPrograms([]string{"sign", "-dir", t.TempDir()}, &out); err == nil {
		t.Error("sign with a bad key")
	}
	// A folder with no signed manifest.
	dir := t.TempDir()
	out.Reset()
	if err := runAgentPrograms([]string{"status", "-dir", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Agent programs in "+dir) || !strings.Contains(out.String(), "agents are offered no updates") {
		t.Errorf("status:\n%s", out.String())
	}
	// A manifest that cannot be used.
	writeTestFile(t, filepath.Join(dir, "manifest.json"), "{not json")
	writeTestFile(t, filepath.Join(dir, "manifest.json.sig"), "nope")
	out.Reset()
	if err := runAgentPrograms([]string{"status", "-dir", dir}, &out); err != nil || !strings.Contains(out.String(), "agents are offered no updates") {
		t.Errorf("status with a broken manifest: %v\n%s", err, out.String())
	}
}

func TestTCPForwardCommandErrors(t *testing.T) {
	if err := cmdTCPForward(nil); err == nil || !strings.Contains(err.Error(), "usage: signalith tcp-forward") {
		t.Errorf("no flags: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := cmdTCPForward([]string{"-listen", l.Addr().String(), "-to", "127.0.0.1:1"}); err == nil {
		t.Error("listened on a port already taken")
	}
}

func TestOpenSearchCommandOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the opensearch command installs OpenSearch on Windows")
	}
	stderr := os.Stderr
	devnull, _ := os.Open(os.DevNull)
	os.Stderr = devnull
	defer func() { os.Stderr = stderr; devnull.Close() }()
	if err := cmdOpenSearch(nil); err == nil || !strings.Contains(err.Error(), "an opensearch command is required") {
		t.Errorf("no command: %v", err)
	}
	if err := cmdOpenSearch([]string{"status"}); err == nil || !strings.Contains(err.Error(), "for Windows") {
		t.Errorf("status: %v", err)
	}
	if err := cmdService(nil); err == nil || !strings.Contains(err.Error(), "for Windows") {
		t.Errorf("service: %v", err)
	}
}
