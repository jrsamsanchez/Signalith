// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build clustertest

package main

// The cluster tests join servers whose folders belong to the user that
// runs them (CI runs as an ordinary user): signalith join runs without
// root there. Release builds never have this tag.
func init() { joinAnyUser = true }
