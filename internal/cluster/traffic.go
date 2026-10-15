package cluster

import "time"

// Traffic is what one server received from agents and syslog since Since
// (when it started counting: its start, or its last in-process restart).
// Heartbeats carry it, so any server can show totals for all of them and
// tell when one behind a load balancer gets no agent traffic.
type Traffic struct {
	Since  time.Time     `json:"since"`
	Agents AgentTraffic  `json:"agents"`
	Syslog SyslogTraffic `json:"syslog"`
}

// AgentTraffic counts the batches agents sent (Fluent Bit, OpenTelemetry)
// and the events in them; LastAt is the latest batch, nil before one.
type AgentTraffic struct {
	Batches int64      `json:"batches"`
	Events  int64      `json:"events"`
	LastAt  *time.Time `json:"last_at,omitempty"`
}

// SyslogTraffic counts the syslog messages received; LastAt is the latest,
// nil before one.
type SyslogTraffic struct {
	Messages int64      `json:"messages"`
	LastAt   *time.Time `json:"last_at,omitempty"`
}
