// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Each server sees itself and the others as the detection buckets'
// assignment does; the jobs move to the server named, and a server
// whose components could not start gives them up and is no longer live.
func TestDetectionServersAndMovingTheJobs(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	a := testNode(t, t.TempDir(), c, true)
	b := testNode(t, t.TempDir(), c, true)
	waitReady(t, a, 5*time.Second)
	waitReady(t, b, 5*time.Second)

	var list []DetectionServer
	until(t, 5*time.Second, "both servers live", func() bool {
		list = a.DetectionServers()
		return len(list) == 2 && list[0].Live && list[1].Live
	})
	if list[0].NodeID > list[1].NodeID {
		t.Errorf("not sorted: %s, %s", list[0].NodeID, list[1].NodeID)
	}
	for _, s := range list {
		if !s.Spread || !s.Eligible || (s.NodeID != a.ID() && s.NodeID != b.ID()) {
			t.Errorf("server %+v", s)
		}
	}

	var holder, other *Node
	until(t, 5*time.Second, "a server runs the jobs", func() bool {
		switch {
		case a.RunsJobs():
			holder, other = a, b
		case b.RunsJobs():
			holder, other = b, a
		}
		return holder != nil
	})
	// One that does not run them has none to move.
	other.MoveJobs(holder.ID())
	holder.MoveJobs(other.ID())
	until(t, 10*time.Second, "the jobs moved to the named server", func() bool { return other.RunsJobs() && !holder.RunsJobs() })

	other.Pause("its components could not start")
	until(t, 10*time.Second, "the jobs back on the server that runs", func() bool { return holder.RunsJobs() && !other.RunsJobs() })
	if other.HeartbeatFresh() {
		t.Error("a paused server counts as live")
	}
	until(t, 10*time.Second, "the paused server not live", func() bool {
		for _, s := range holder.DetectionServers() {
			if s.NodeID == other.ID() {
				return !s.Live
			}
		}
		return false
	})
}
