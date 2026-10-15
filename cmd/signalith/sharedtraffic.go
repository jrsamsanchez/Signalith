package main

import (
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/syslog"
)

// trafficOf counts what this instance receives from agents and syslog, for
// its heartbeat: the Health page totals the servers from it, and says when
// one behind a load balancer gets no agent traffic.
func trafficOf(agents *agentinv.Inventory, receiver *syslog.Receiver) func() cluster.Traffic {
	since := time.Now().UTC()
	return func() cluster.Traffic {
		t := cluster.Traffic{Since: since}
		var last time.Time
		t.Agents.Batches, t.Agents.Events, last = agents.Traffic()
		if !last.IsZero() {
			t.Agents.LastAt = &last
		}
		var lm time.Time
		t.Syslog.Messages, lm = receiver.Traffic()
		if !lm.IsZero() {
			t.Syslog.LastAt = &lm
		}
		return t
	}
}
