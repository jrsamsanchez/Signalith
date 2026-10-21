// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package syslog

import (
	"syscall"
	"testing"
)

// makeFIFO makes a named pipe at path, and returns 1 (one file the spool
// skips).
func makeFIFO(t *testing.T, path string) int {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return 1
}
