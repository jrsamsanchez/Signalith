// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package cluster

import "time"

// bootTime is not read here: Go's monotonic clock already counts the time
// a suspended computer slept on Windows.
func bootTime() (time.Duration, bool) { return 0, false }
