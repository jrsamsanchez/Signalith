// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package reportkeys

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The lock is the folder's: no lock file is made, so none can be left
// owned by root or be a link put there to make root create a file.
func TestLockMakesNoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report-keys.json")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), path+".lock"); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := (&File{Path: path}).Use(context.Background(), pub, FromMaster, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "elsewhere")); !os.IsNotExist(err) {
		t.Errorf("the link was followed: %v", err)
	}
}
