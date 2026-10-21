// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package syslog

import (
	"fmt"
	"os"
)

// openNoFollow opens a spool file for reading, refusing anything but a
// regular file at its name. Windows has no pipes in a folder, so opening never waits.
func openNoFollow(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return os.Open(path)
}
