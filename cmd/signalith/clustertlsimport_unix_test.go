// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// openPlain follows no link, and doesn't wait on a FIFO with no writer;
// readPlainFile refuses both.
func TestOpenPlain(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openPlain(link); err == nil {
		f.Close()
		t.Error("opened through a link")
	}
	if _, err := readPlainFile(link); err == nil {
		t.Error("read through a link")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("no FIFO here:", err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := openPlain(fifo)
		if err == nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}
	if _, err := readPlainFile(fifo); err == nil {
		t.Error("read a FIFO")
	}
}
