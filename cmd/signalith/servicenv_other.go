// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package main

import "time"

func platformServiceSettings() *serviceSettings { return nil }

// serviceStartedAfter is for systemd credentials, which exist only on
// Linux.
func serviceStartedAfter(time.Time) (bool, error) { return true, nil }

// serviceProcess: Signalith runs as a service only on Linux and Windows.
var serviceProcess = func() string { return "" }

// needAdmin is what to do when a file needs more rights than this
// account has.
const needAdmin = "Run it with sudo."
