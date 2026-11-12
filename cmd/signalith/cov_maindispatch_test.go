// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// main hands each of these commands on, and returns when they succeed.
func TestMainDispatchesMoreCommands(t *testing.T) {
	sec := securityConfig(t, "")
	if out := runMain(t, "security", "-c", sec); !strings.Contains(out, "Summary: ") {
		t.Errorf("security:\n%s", out)
	}
	if out := runMain(t, "secrets", "help"); !strings.Contains(out, "rotate-master") {
		t.Errorf("secrets help:\n%s", out)
	}
	if out := runMain(t, "agent-programs", "keygen"); !strings.Contains(strings.ToLower(out), "key") {
		t.Errorf("agent-programs keygen:\n%s", out)
	}
	if out := runMain(t, "report", "keys", "-c", sec); !strings.Contains(out, "No case report was signed") {
		t.Errorf("report keys:\n%s", out)
	}
	pw := filepath.Join(filepath.Dir(sec), initialPasswordFile)
	if err := os.WriteFile(pw, []byte("first-pass-0123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", "")
	if out := runMain(t, "initial-password", "-c", sec); strings.TrimSpace(out) != "first-pass-0123" {
		t.Errorf("initial-password: %q", out)
	}

	src := backupInstall(t, map[string]string{"data/lookups/a.csv": "x\n"})
	zipFile := filepath.Join(t.TempDir(), "b.zip")
	if out := runMain(t, "backup", "-c", src, "-no-master-key", "-o", zipFile); !strings.Contains(out, "Wrote "+zipFile) {
		t.Errorf("backup:\n%s", out)
	}
	dst := backupInstall(t, map[string]string{})
	if out := runMain(t, "restore", "-c", dst, "-yes", zipFile); !strings.Contains(out, "Restored") {
		t.Errorf("restore:\n%s", out)
	}
}

// signalith security exits 0 when nothing is at risk, and fails on a
// config file it cannot read.
func TestSecurityCommandEntry(t *testing.T) {
	path := securityConfig(t, "cluster:\n  node_name: siem-sec\n")
	var err error
	out := captureStdout(t, func() { err = cmdSecurity([]string{"-c", path}) })
	if err != nil || !strings.Contains(out, "Summary: ") {
		t.Errorf("%v\n%s", err, out)
	}
	if err := cmdSecurity([]string{"-c", filepath.Join(t.TempDir(), "none.yaml")}); err == nil {
		t.Error("a missing config file was reported on")
	}
}

// serve stops at once on a config file it cannot read.
func TestServeCommandBadConfig(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "signalith.yaml")
	os.WriteFile(bad, []byte("server: [\n"), 0o600)
	if err := cmdServe([]string{"-c", bad}); err == nil {
		t.Error("serve ran with a broken config file")
	}
}

// A server started with SIGNALITH_JOIN joins only once.
func TestJoinFromEnvSkips(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	t.Setenv(joinTokenEnv, "")
	if err := joinFromEnv(path, log); err != nil || logs.Len() != 0 {
		t.Errorf("no token: %v %s", err, logs.String())
	}
	t.Setenv(joinTokenEnv, "sjt_some-token")
	t.Setenv(clusterKeyFileEnv, filepath.Join(t.TempDir(), "cluster.key"))
	if err := joinFromEnv(path, log); err != nil || !strings.Contains(logs.String(), "is ignored") {
		t.Errorf("joined: %v %s", err, logs.String())
	}
	// A config file that does not load: the server's start says why.
	t.Setenv(clusterKeyFileEnv, "")
	os.WriteFile(path, []byte("server: [\n"), 0o600)
	logs.Reset()
	if err := joinFromEnv(path, log); err != nil || logs.Len() != 0 {
		t.Errorf("broken config: %v %s", err, logs.String())
	}
}

func TestJoinFailedSaysWhy(t *testing.T) {
	for code, want := range map[int]string{
		2: "the join was refused", 3: "the join was refused", 4: "not ready to join",
		5: "could not save its files", 9: "exit code 9",
	} {
		if got := joinFailed(code); !strings.Contains(got, want) {
			t.Errorf("%d: %q", code, got)
		}
	}
}
