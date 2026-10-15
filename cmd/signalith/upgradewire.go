package main

import (
	"context"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/upgradecheck"
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

// wireUpgrade gives the API the upgrade checklist of the Servers page
// (GET /api/cluster/upgrade): upgrade-check's judgement, read through this
// server's OpenSearch client cl and index prefix, with the shared
// configuration of rt (nil without shared settings).
func wireUpgrade(srv *api.Server, node *cluster.Node, rt *shared.Runtime, cl *store.Client, prefix string) {
	if node == nil || cl == nil {
		return
	}
	srv.Upgrade = func(ctx context.Context) (upgradecheck.Verdict, error) {
		in, err := upgradecheck.Read(ctx, cl, prefix, node.ID(), rt)
		if err != nil {
			return upgradecheck.Verdict{}, err
		}
		return upgradecheck.Judge(in), nil
	}
}
