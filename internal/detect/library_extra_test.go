// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Files the library cannot read are reported, and the others still load.
func TestNewLibraryReportsUnreadableFiles(t *testing.T) {
	dir := t.TempDir()
	// A folder named like a detection, and like a state file.
	if err := os.MkdirAll(filepath.Join(dir, "folder.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, StateDir, "auth-brute-force.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	lib, problems, err := NewLibrary(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 2 {
		t.Fatalf("problems %v", problems)
	}
	joined := problems[0].Error() + problems[1].Error()
	if !strings.Contains(joined, "folder.yaml") || !strings.Contains(joined, "auth-brute-force.yaml") {
		t.Errorf("problems %v", problems)
	}
	if d, err := lib.Get("auth-brute-force"); err != nil || d.Source != "builtin" {
		t.Errorf("built-in after a bad state file: %+v %v", d, err)
	}
}

func TestSetEnabledCustomAndUnknown(t *testing.T) {
	lib := OnlyRules(t, &Detection{ID: "mine", Title: "Mine", Query: "src=1", Severity: "low", Schedule: "5m", Enabled: true})
	if err := lib.SetEnabled([]string{"nope"}, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
	if err := lib.SetEnabled([]string{"mine"}, false); err != nil {
		t.Fatal(err)
	}
	if d, err := lib.Get("mine"); err != nil || d.Enabled {
		t.Errorf("custom after SetEnabled: %+v %v", d, err)
	}
	// A hold that cannot be had stops the change.
	busy := errors.New("busy")
	lib.Hold = func() (func(), error) { return nil, busy }
	if err := lib.SetEnabled([]string{"mine"}, true); !errors.Is(err, busy) {
		t.Errorf("with the hold refused: %v", err)
	}
	held := 0
	lib.Hold = func() (func(), error) { held++; return func() {}, nil }
	if err := lib.SetEnabled([]string{"mine"}, true); err != nil || held != 1 {
		t.Errorf("with the hold: %v, held %d", err, held)
	}
}

// A library whose folder is a file cannot save anything, and says so.
func TestLibraryCannotWrite(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	lib, problems, err := NewLibrary(file)
	if err != nil || len(problems) != 0 {
		t.Fatal(err, problems)
	}
	if err := lib.Put(&Detection{ID: "mine", Title: "Mine", Query: "src=1", Severity: "low", Schedule: "5m"}); err == nil {
		t.Error("saved a custom detection under a file")
	}
	if err := lib.SetEnabled([]string{"auth-brute-force"}, false); err == nil {
		t.Error("saved a built-in's state under a file")
	}
	if err := writeFileAtomic(filepath.Join(file, "x.yaml"), []byte("x")); err == nil {
		t.Error("writeFileAtomic under a file")
	}
}
