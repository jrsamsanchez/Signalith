// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"context"
	"time"
)

// MetricsView is what GET /metrics says about retention on this server.
type MetricsView struct {
	// LastRun is when the last run ended and how many errors it had;
	// zero when none is known (no run yet, or the history can't be read).
	LastRun       time.Time
	LastRunErrors int
	// Running is set while a run or a restore is in progress, and
	// Automatic while this server runs retention on its schedule.
	Running, Automatic bool
	// GuardState is the disk guard now: GuardOff, GuardOK, GuardOver
	// (the fullest data disk is above the limit), GuardUnknown (the disk
	// can't be read) or GuardPaused (the settings have errors).
	// GuardPausedRun is set while the guard waits for the next scheduled
	// run, after one that could not get the disk under its limit.
	GuardState     string
	GuardPausedRun bool
	GuardLimit     int
	// DiskPercent is how full the fullest OpenSearch data disk is; -1
	// when unknown.
	DiskPercent float64
}

// Metrics reads what GET /metrics says about retention. It asks
// OpenSearch for the disk once, and the history only when this server
// has made no run since it started.
func (m *Manager) Metrics(ctx context.Context) MetricsView {
	m.init()
	v := MetricsView{DiskPercent: -1, GuardState: GuardUnknown}
	m.mu.Lock()
	run := m.lastRun
	v.Running, v.Automatic = m.current != "", m.automatic
	m.mu.Unlock()
	if run == nil {
		if r, _, err := m.hist.Recent(ctx); err == nil {
			run = r
		}
	}
	if run != nil {
		v.LastRun, v.LastRunErrors = run.Finished, len(run.Errors)
	}
	_, v.GuardPausedRun = m.guardPause()
	if m.Cluster != nil {
		if d, err := m.Cluster.Disk(ctx); err == nil && d != nil {
			v.DiskPercent = d.Percent()
		}
	}
	s, err := m.Settings()
	switch {
	case err != nil:
		v.GuardState = GuardPaused
	case !s.Guard.IsEnabled():
		v.GuardState = GuardOff
	default:
		v.GuardLimit = s.Guard.MaxDiskPercent
		switch {
		case v.DiskPercent < 0:
			v.GuardState = GuardUnknown
		case v.DiskPercent > float64(s.Guard.MaxDiskPercent):
			v.GuardState = GuardOver
		default:
			v.GuardState = GuardOK
		}
	}
	return v
}
