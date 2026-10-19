//go:build !windows

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agentd"
)

// On Windows CheckFolders wants folders owned by SYSTEM or
// Administrators, which a test's temporary folder is not.

func TestNewAgentNotSetUp(t *testing.T) {
	p := testPaths(t)
	if _, err := newAgent(p, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not set up") {
		t.Fatalf("no agent.conf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.Conf, "agent.conf"), []byte("SERVER=https://siem.example.test:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newAgent(p, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Fatalf("no token: %v", err)
	}
}

func TestNewAgent(t *testing.T) {
	p := testPaths(t)
	if err := os.WriteFile(filepath.Join(p.Conf, "agent.conf"), []byte("# set up\nSERVER='https://siem.example.test:8443'\nOSQUERY=yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Conf, "token"), []byte("made-up-agent-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	a, err := newAgent(p, &log)
	if err != nil {
		t.Fatal(err)
	}
	if a.Settings.Server != "https://siem.example.test:8443" || a.Settings.Token != "made-up-agent-token" || !a.Settings.Osquery {
		t.Errorf("settings %+v", a.Settings)
	}
	if a.Version != version || a.Out != &log || a.Paths != p {
		t.Errorf("agent %+v", a)
	}
	if !strings.Contains(log.String(), "Signalith Agent starting") || !strings.Contains(log.String(), "siem.example.test") {
		t.Errorf("log %q", log.String())
	}
}

func TestInstallUpdateNothingReady(t *testing.T) {
	p := testPaths(t)
	// No update folder: nothing to install.
	if err := installUpdate(p, &bytes.Buffer{}); err != nil {
		t.Fatalf("no update folder: %v", err)
	}
	// An update folder without the ready file: still nothing.
	upd := filepath.Join(p.State, "update")
	if err := os.Mkdir(upd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installUpdate(p, &bytes.Buffer{}); err != nil {
		t.Fatalf("nothing ready: %v", err)
	}
	// A folder others can write is refused.
	if err := os.Chmod(upd, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := installUpdate(p, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("writable update folder: %v", err)
	}
}

// TestInstallUpdateCommandNotInstalled: with no state folder there is no
// update, and the updater has nothing to do.
func TestInstallUpdateCommandNotInstalled(t *testing.T) {
	if _, err := os.Stat(agentd.DefaultPaths().State); err == nil {
		t.Skip("the agent is installed here")
	}
	if err := run([]string{"install-update"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}
