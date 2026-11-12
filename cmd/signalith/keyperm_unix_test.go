// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// The server does not start with a master key file other accounts can
// read, outside a container (CRYPTO-06).
func TestMasterKeyFileProblem(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	t.Setenv("SIGNALITH_MASTER_KEY", "")
	t.Setenv("SIGNALITH_MASTER_KEY_FILE", "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := config.Default().Keyring().Seal("x", "make the key"); err != nil {
		t.Fatal(err)
	}
	if err := masterKeyFileProblem(config.Default(), false); err != nil {
		t.Fatalf("a private key: %v", err)
	}
	p := filepath.Join(state, "keys", "master.key")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	err := masterKeyFileProblem(config.Default(), false)
	if err == nil || !strings.Contains(err.Error(), "chmod 600 "+p) || !strings.Contains(err.Error(), "does not start") {
		t.Errorf("a key others can read: %v", err)
	}
	// In a container, secrets are mounted 0644 by default: a warning only.
	if err := masterKeyFileProblem(config.Default(), true); err != nil {
		t.Errorf("in a container: %v", err)
	}
}
