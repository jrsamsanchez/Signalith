// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A program in a folder its user may change (a temp folder) is refused.
func TestCheckProgramFolderRefusesUserWritableFolder(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "signalith.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkProgramFolder(exe); err == nil {
		t.Fatal("a program in a user-writable folder was accepted")
	}
}

// Windows' own programs, owned by TrustedInstaller in a folder only
// administrators may change, are accepted.
func TestCheckProgramFolderAcceptsSystemFolder(t *testing.T) {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
	if _, err := os.Stat(exe); err != nil {
		t.Skip(err)
	}
	if err := checkProgramFolder(exe); err != nil {
		t.Fatal(err)
	}
}
