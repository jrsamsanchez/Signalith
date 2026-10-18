//go:build !windows

package main

import (
	"io"

	"github.com/jrsamsanchez/signalith/internal/agentd"
)

// runService is false: on Linux, systemd runs "signalith-agent run".
func runService() bool { return false }

// agentService is the agent's systemd service.
func agentService(p agentd.Paths) agentd.ServiceControl {
	return agentd.SystemdService{Unit: p.Service}
}

// updateLog is w: the updater's service logs to the journal.
func updateLog(_ agentd.Paths, w io.Writer) io.Writer { return w }
