// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package reportkeys

// lockFile has no file locks here: the in-process mutex still holds.
func lockFile(string) (func(), error) { return func() {}, nil }
