// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"log/slog"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHardenProcess(t *testing.T) {
	hardenProcess(slog.New(slog.NewTextHandler(io.Discard, nil)))
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil || lim.Cur != 0 || lim.Max != 0 {
		t.Errorf("core file limit %+v, %v; want 0", lim, err)
	}
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || d != 0 {
		t.Errorf("dumpable = %d, %v; want 0", d, err)
	}
}
