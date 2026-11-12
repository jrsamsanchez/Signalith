// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package assets

// inUse is for Windows: elsewhere a file that is open can be replaced.
func inUse(error) bool { return false }
