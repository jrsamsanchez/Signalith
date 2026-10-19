// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log/slog"

	"golang.org/x/sys/unix"
)

// hardenProcess keeps the server's memory, which holds decrypted passwords
// and keys, out of core dumps and out of reach of other programs running
// as the same account: core files are turned off (RLIMIT_CORE 0), and the
// process is marked not dumpable (PR_SET_DUMPABLE 0), which also stops
// those programs from attaching a debugger or reading /proc/<pid>/mem.
// Root can still read the memory of any process; that needs the
// protections in docs/encryption.md ("In use").
func hardenProcess(log *slog.Logger) {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		log.Warn("could not turn off core dumps", "err", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Warn("could not stop other programs from reading this process's memory", "err", err)
	}
}
