// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package syslog

import (
	"os"
	"syscall"
)

// openNoFollow opens a spool file for reading without following a link
// at its name, and without waiting when it is a pipe.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
