package main

import (
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/retention"
)

// jobsBusy names the step of the background jobs that a hand-over of the
// jobs to a newer version, and an upgrade, must wait for: a retention run
// or an archive restore. "" when none runs.
func jobsBusy(ret *retention.Manager) func() string {
	return func() string {
		if ret == nil {
			return ""
		}
		switch ret.Job() {
		case "run":
			return "retention run"
		case "restore":
			return "archive restore"
		case "":
			return ""
		default:
			return "retention " + ret.Job()
		}
	}
}

// nodeTiming is the timing of this server's node: the defaults (zero).
// The clustertest build lets the cluster tests shorten the hand-over to
// a newer version (yield_clustertest.go).
var nodeTiming = func() cluster.Timing { return cluster.Timing{} }
