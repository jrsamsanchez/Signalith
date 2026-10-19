// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package cluster

// machineID is unknown here.
func machineID() string { return "" }
