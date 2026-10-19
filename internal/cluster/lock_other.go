// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package cluster

// lockFile does nothing where files cannot be locked.
func lockFile(string) (func(), error) { return func() {}, nil }
