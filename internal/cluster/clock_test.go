// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"strings"
	"testing"
)

// The real clock's wall time carries no monotonic reading, so the time
// between two of them is the wall clock's: a computer that slept shows a
// jump, which the lease's suspend check needs.
func TestRealClockWallTimeIsTheWallClock(t *testing.T) {
	c := NewRealClock()
	if s := c.Now().String(); strings.Contains(s, "m=") {
		t.Errorf("Now has a monotonic reading: %s", s)
	}
	a := c.Mono()
	b := c.Mono()
	if b < a {
		t.Errorf("monotonic time went back: %v then %v", a, b)
	}
}
