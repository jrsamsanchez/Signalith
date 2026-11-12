// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package assets

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A list saved while something reads the old file for a moment (another
// request, an antivirus) is saved once the reader closes it, on Windows
// too, where an open file cannot be replaced.
func TestReplaceFileWhileTheOldOneIsOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.csv")
	if err := os.WriteFile(path, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() {
		time.Sleep(300 * time.Millisecond)
		f.Close()
		close(closed)
	}()
	defer func() { <-closed }()
	if err := replaceFile(path, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "new\n" {
		t.Fatalf("after the save: %q %v", b, err)
	}
}
