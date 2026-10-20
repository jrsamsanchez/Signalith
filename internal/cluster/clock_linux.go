// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cluster

import (
	"time"

	"golang.org/x/sys/unix"
)

// bootTime is the time since the computer started, including time it was
// suspended, which Go's monotonic clock leaves out on Linux.
func bootTime() (time.Duration, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, false
	}
	return time.Duration(ts.Nano()), true
}
