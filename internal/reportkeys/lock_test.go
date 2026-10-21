// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix || windows

package reportkeys

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A change held up by another one gives up after lockWait rather than
// waiting for good, and the list is still changed once the lock is free.
func TestLockGivesUp(t *testing.T) {
	old := lockWait
	lockWait = 200 * time.Millisecond
	t.Cleanup(func() { lockWait = old })
	path := filepath.Join(t.TempDir(), "report-keys.json")
	held, err := lockFile(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	f := &File{Path: path}
	if err := f.Use(context.Background(), pub, FromMaster, time.Now()); !errors.Is(err, errBusy) {
		t.Fatalf("while held: %v", err)
	}
	held()
	if err := f.Use(context.Background(), pub, FromMaster, time.Now()); err != nil {
		t.Fatalf("after: %v", err)
	}
}
