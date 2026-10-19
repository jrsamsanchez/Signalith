// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"path/filepath"

	"github.com/jrsamsanchez/signalith/internal/agentd"
	"github.com/jrsamsanchez/signalith/internal/safelog"
)

// runService is false: on macOS, launchd runs "signalith-agent run".
func runService() bool { return false }

// agentService is the agent's launchd service.
func agentService(p agentd.Paths) agentd.ServiceControl {
	return agentd.LaunchdService{Label: p.Service}
}

// agentLog is agent.log in the agent's state folder as well as w: launchd
// keeps no log of its own for the service, and the file rotates by size
// so it cannot fill the disk.
func agentLog(p agentd.Paths, w io.Writer) io.Writer {
	return rotating(filepath.Join(p.State, "agent.log"), w)
}

// updateLog is updater.log in the agent's state folder as well as w.
func updateLog(p agentd.Paths, w io.Writer) io.Writer {
	return rotating(filepath.Join(p.State, "updater.log"), w)
}

func rotating(path string, w io.Writer) io.Writer {
	f, err := safelog.OpenRotating(path, safelog.DefaultMaxSize, safelog.DefaultBackups)
	if err != nil {
		return w
	}
	return io.MultiWriter(f, w)
}
