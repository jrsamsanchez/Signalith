// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package cluster lets several Signalith servers share one OpenSearch.
// Each server keeps an identity in its state folder, writes a heartbeat
// document into <prefix>_runtime every 10 seconds, and the servers that
// may run the background jobs (detections, threat intel downloads,
// retention) take turns through one lease document, lease:jobs, so they
// never run on two servers at once. A single server is a cluster of one.
//
// Servers coordinate only through OpenSearch, never with each other, and
// every timeout is measured on each server's own monotonic clock, so a
// wrong or changed wall clock cannot hand the jobs over.
package cluster

import "time"

// Clock tells the time. Tests use a fake one (ostest.Clock).
type Clock interface {
	// Now is the wall-clock time, written into documents for people to
	// read; it never decides anything.
	Now() time.Time
	// Mono is the time since an arbitrary start on a clock that only moves
	// forward. Every timeout is measured with it.
	Mono() time.Duration
	// After receives once d has passed.
	After(d time.Duration) <-chan time.Time
	// Until receives once Mono reaches at, or at once if it has. A wait
	// for a deadline worked out from an earlier Mono reading uses it, so
	// that time passing between the reading and the wait is not added.
	Until(at time.Duration) <-chan time.Time
}

// realClock is the computer's clock.
type realClock struct {
	start time.Time
	// boot is the time since the computer started when this clock was
	// made, where that can be read (Linux); Mono then counts from it.
	boot   time.Duration
	booted bool
}

// NewRealClock returns the computer's clock.
func NewRealClock() Clock {
	c := realClock{start: time.Now()}
	c.boot, c.booted = bootTime()
	return c
}

// Now is the wall-clock time without Go's monotonic reading, so that
// subtracting two of them gives the wall time that passed: a computer that
// was suspended shows the time it slept (see Lease.validLocked).
func (realClock) Now() time.Time { return time.Now().Round(0) }

// Mono counts the time a suspended computer slept, where the system can
// tell (Linux's boot time clock; Go's own monotonic clock does on Windows),
// so a holder that wakes up after the fence time knows its lease ran out.
func (c realClock) Mono() time.Duration {
	if c.booted {
		if now, ok := bootTime(); ok {
			return now - c.boot
		}
	}
	return time.Since(c.start)
}

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

func (c realClock) Until(at time.Duration) <-chan time.Time { return time.After(at - c.Mono()) }

// Timing holds the intervals the cluster uses. The defaults are the ones
// in the multi-server design; tests shorten them.
type Timing struct {
	// Heartbeat is how often a server writes its heartbeat, and Offline
	// how long a heartbeat may stay unchanged before its server counts as
	// offline.
	Heartbeat, Offline time.Duration
	// IdentityWatch is how long a starting server watches a heartbeat of
	// its own identity written by another process, to see whether that
	// process is alive.
	IdentityWatch time.Duration
	// Renew is how often the job lease is renewed, Retry how soon a failed
	// renewal is tried again, Fence how long after the last good renewal
	// was sent the holder stops its jobs, and Takeover how long another
	// server must see the lease unchanged before it takes it.
	Renew, Retry, Fence, Takeover time.Duration
	// Watch is how often a server that does not hold the lease reads it.
	Watch time.Duration
	// ReleaseWait is how long a graceful release waits for jobs to finish.
	ReleaseWait time.Duration
	// PreferWait is how long a server waits after a release that names
	// another server before it takes the lease itself.
	PreferWait time.Duration
	// ClockCheck is how often the clock offset to OpenSearch is measured,
	// and FilesCheck how often the files fingerprints are worked out.
	ClockCheck, FilesCheck time.Duration
	// FilesWait is how long a server waits for its files fingerprints when
	// it needs them now; reading the archive folder on a network share
	// that does not answer must not hold it up.
	FilesWait time.Duration
	// YieldEvery is how often at most the server running the background
	// jobs hands them to a server that runs a newer version, and
	// YieldSettle how long that server must have been ready first (and
	// how long the holder must have held them).
	YieldEvery, YieldSettle time.Duration
}

// DefaultTiming is the timing servers run with.
var DefaultTiming = Timing{
	Heartbeat: 10 * time.Second, Offline: 30 * time.Second, IdentityWatch: 12 * time.Second,
	Renew: 10 * time.Second, Retry: 2 * time.Second, Fence: 20 * time.Second, Takeover: 30 * time.Second,
	Watch: 2 * time.Second, ReleaseWait: 60 * time.Second, PreferWait: 10 * time.Second,
	ClockCheck: time.Minute, FilesCheck: 15 * time.Second, FilesWait: 5 * time.Second,
	YieldEvery: 10 * time.Minute, YieldSettle: 60 * time.Second,
}

// MaxClockOffset is how far a server's clock may be off OpenSearch's
// before it leaves the background jobs to another server whose clock is
// right: detections are scheduled by wall-clock time. A server alone keeps
// running them whatever its clock says.
const MaxClockOffset = 30 * time.Second
