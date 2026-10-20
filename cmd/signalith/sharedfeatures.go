// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// wireFeatures gives the API the features that come with a cluster
// level (GET /api/cluster/features), which pages grey out while servers
// run mixed versions; a server without shared settings has none.
func wireFeatures(srv *api.Server, rt *shared.Runtime) {
	if rt == nil {
		return
	}
	srv.Features = rt.FeatureStates
	srv.ClusterLevel = func() int { return rt.Status().Level }
}
