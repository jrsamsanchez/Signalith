// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import "errors"

// giveTree changes nothing outside Linux: signalith join gives files to
// the service's account on Linux only (on Windows the folders' access
// lists do it).
func giveTree(string, int, int, func(int, string, int, int) error) error { return nil }

// chownFD is Linux's.
func chownFD(int, string, int, int) error {
	return errors.New("changing a file's owner by its descriptor is Linux's")
}
