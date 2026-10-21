// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"os"
	"syscall"
)

// openPlain opens path to read without following a link in its last
// part (O_NOFOLLOW), and without blocking on a FIFO or a device put in
// its place (O_NONBLOCK); readPlainFile checks what it opened.
func openPlain(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
