//go:build clustertest

package main

import (
	"os"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
)

// The cluster tests shorten how long a newer server must be ready before
// the server running the background jobs hands them to it, through
// SIGNALITH_TEST_YIELD_SETTLE. Release builds never have this tag.
func init() {
	nodeTiming = func() cluster.Timing {
		d, err := time.ParseDuration(os.Getenv("SIGNALITH_TEST_YIELD_SETTLE"))
		if err != nil || d <= 0 {
			return cluster.Timing{}
		}
		t := cluster.DefaultTiming
		t.YieldSettle = d
		return t
	}
}
