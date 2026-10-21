// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/keytrust"
)

// Run as root, import-revocations refuses a state folder another user
// owns: that user could have linked keytrust to a system folder.
func TestContentImportRefusesRootOnServiceState(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	path, _ := contentConfig(t)
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	if err := os.Chown(state, 4321, 4321); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(state, "keytrust")); err != nil {
		t.Fatal(err)
	}
	list := filepath.Join(t.TempDir(), keytrust.ListFile)
	for _, f := range []string{list, list + ".sig"} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	name := "4321"
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	var out strings.Builder
	err := runContent([]string{"import-revocations", "-c", path, list}, &out)
	if err == nil || !strings.Contains(err.Error(), "sudo -u "+name+" signalith content import-revocations") {
		t.Fatalf("err = %v, want refused as root", err)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("written through the link: %v", entries)
	}
}
