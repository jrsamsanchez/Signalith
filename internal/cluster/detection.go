package cluster

import "slices"

// DetectionServer is a server as the assignment of the detection buckets
// sees it (see detect.Assignment): the server running the background jobs
// gives a tenant's buckets to the live servers that may run them.
type DetectionServer struct {
	NodeID string
	// Spread is true when its version runs assigned buckets
	// (FeatureDetectionSpread), and Eligible when it may run background
	// work at all (cluster.leader_eligible).
	Spread, Eligible bool
	// Live is true while its heartbeat, written as ready, changed within
	// the takeover time.
	Live bool
	// Tenants is its tenants' detection fingerprints.
	Tenants map[string]string
	// ClockOffsetMS is OpenSearch's clock minus its own, nil when not
	// measured.
	ClockOffsetMS *int64
}

// DetectionServers returns this server and the others, as their last
// heartbeats show them.
func (n *Node) DetectionServers() []DetectionServer {
	self := n.heartbeatDoc(StateReady)
	fresh := n.HeartbeatFresh()
	n.mu.Lock()
	defer n.mu.Unlock()
	out := []DetectionServer{{NodeID: n.ID(), Spread: true, Eligible: self.LeaderEligible, Live: fresh,
		Tenants: self.DetTenants, ClockOffsetMS: self.ClockOffsetMS}}
	now := n.clock.Mono()
	for id, m := range n.members {
		if id == n.ID() {
			continue
		}
		out = append(out, DetectionServer{NodeID: id, Spread: slices.Contains(m.hb.Features, FeatureDetectionSpread),
			Eligible: m.hb.LeaderEligible, Live: m.hb.State == StateReady && now-m.since < n.timing.Takeover,
			Tenants: m.hb.DetTenants, ClockOffsetMS: m.hb.ClockOffsetMS})
	}
	slices.SortFunc(out, func(a, b DetectionServer) int {
		switch {
		case a.NodeID < b.NodeID:
			return -1
		case a.NodeID > b.NodeID:
			return 1
		}
		return 0
	})
	return out
}

// HeartbeatFresh reports whether this server wrote its heartbeat, as
// ready, within the fence time: a server that cannot is cut off from the
// others' view and stops running assigned detection buckets by itself,
// as the job lease's holder stops its jobs.
func (n *Node) HeartbeatFresh() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.hb.checked && n.conflict == "" && !n.stopping && n.paused == "" && n.drained == "" &&
		n.hb.goodState == StateReady && n.clock.Mono()-n.hb.good < n.timing.Fence
}
