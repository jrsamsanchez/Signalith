// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

import "os"

// openPlain opens path to read. Windows has no O_NOFOLLOW: readPlainFile
// checks that what it opened is a regular file, and the one it looked at.
func openPlain(path string) (*os.File, error) {
	return os.Open(path)
}
