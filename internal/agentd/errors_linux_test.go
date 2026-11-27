// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fakeSystemctl puts a systemctl first on PATH that prints out, or fails
// when out is "".
func fakeSystemctl(t *testing.T, out string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nexit 1\n"
	if out != "" {
		script = "#!/bin/sh\nprintf '" + out + "'\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestSystemdServiceWithSystemctl(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	fakeSystemctl(t, `LoadState=loaded\nActiveState=active\nSubState=running\nNRestarts=3\nnot a property\n`)
	svc := SystemdService{Unit: "signalith-agent.service"}
	running, restarts, err := svc.State(context.Background())
	if err != nil || !running || restarts != "3" {
		t.Fatalf("State = %v %q %v", running, restarts, err)
	}
	if err := svc.Restart(context.Background()); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	m, err := systemctlShow(context.Background(), "signalith-agent.service")
	if err != nil || m["SubState"] != "running" || len(m) != 4 {
		t.Fatalf("systemctlShow = %v %v", m, err)
	}

	fakeSystemctl(t, "")
	if _, _, err := svc.State(context.Background()); err == nil {
		t.Fatal("a failing systemctl gave a state")
	}
	if err := svc.Restart(context.Background()); err == nil {
		t.Fatal("a failing restart was no error")
	}
}

// launchctl is macOS's: elsewhere asking it fails.
func TestLaunchdServiceWithoutLaunchctl(t *testing.T) {
	if _, err := os.Stat("/bin/launchctl"); err == nil {
		t.Skip("launchctl is here")
	}
	svc := LaunchdService{Label: "io.signalith.agent"}
	if _, _, err := svc.State(context.Background()); err == nil {
		t.Fatal("a state without launchctl")
	}
	if err := svc.Restart(context.Background()); err == nil {
		t.Fatal("a restart without launchctl")
	}
}
