// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// A server that runs the background jobs hands them to a server that runs
// a newer version, once that one has been ready a while, so during a
// rolling upgrade the jobs move to the new code once, with a graceful
// release rather than a takeover after a pause (design 4.3.1, Preference).
// Only to a strictly newer version, at most once per Timing.YieldEvery:
// the new holder is the newest, so the jobs never move back and forth.

// yieldCandidate is another server as the holder last saw it.
type yieldCandidate struct {
	hb Heartbeat
	// readySince is when its heartbeat turned ready, on the holder's
	// monotonic clock; gone is true when it is offline or stopped.
	readySince time.Duration
	gone       bool
}

// yieldTarget picks the server the holder self should hand the jobs to at
// now (its monotonic clock), if any: one ready for at least
// t.YieldSettle, that may run the jobs and would take them (its files
// match, its clock is right), reads at least the stored formats self
// reads, has applied at least the shared settings self has, and runs a
// newer version. Of several, the newest, then the first by name.
func yieldTarget(self Heartbeat, members []yieldCandidate, now time.Duration, t Timing) (Heartbeat, bool) {
	var best *Heartbeat
	for i := range members {
		m := &members[i]
		hb := &m.hb
		switch {
		case m.gone, hb.NodeID == self.NodeID, hb.State != StateReady, now-m.readySince < t.YieldSettle,
			!hb.LeaderEligible, hb.NotEligible != "", hb.CannotTakeOver != "":
			continue
		case hb.ClockOffsetMS == nil || (time.Duration(*hb.ClockOffsetMS)*time.Millisecond).Abs() > MaxClockOffset:
			continue
		case hb.LevelMax < self.LevelMax:
			continue
		case hb.MaxRev > 0 && self.MaxRev > 0 && hb.MaxRev < self.MaxRev:
			continue
		case !NewerVersion(hb.Version, self.Version, hb.LevelMax, self.LevelMax):
			continue
		}
		if best == nil || NewerVersion(hb.Version, best.Version, hb.LevelMax, best.LevelMax) ||
			(!NewerVersion(best.Version, hb.Version, best.LevelMax, hb.LevelMax) && strings.Compare(hb.Name, best.Name) < 0) {
			best = hb
		}
	}
	if best == nil {
		return Heartbeat{}, false
	}
	return *best, true
}

// maybeYield hands the background jobs to a server that runs a newer
// version (see yieldTarget), when this server holds them and nothing it
// does must not be cut short. The heartbeat loop calls it after reading
// the other servers.
func (n *Node) maybeYield() {
	if !n.lease.Holding() || n.lease.Frozen() {
		return
	}
	view := n.lease.View()
	now := n.clock.Mono()
	n.mu.Lock()
	// The time this server took the lease, as near as the loop saw it: a
	// just-started newer server is not handed the jobs while the old
	// leader itself is restarting.
	if !n.heldSet || n.heldEpoch != view.Doc.Epoch {
		n.heldSet, n.heldEpoch, n.heldSince = true, view.Doc.Epoch, now
	}
	if n.releasing || n.drained != "" || n.probation || n.stopping || n.paused != "" || n.conflict != "" ||
		now-n.heldSince < n.timing.YieldSettle || (n.yielded && now-n.lastYield < n.timing.YieldEvery) {
		n.mu.Unlock()
		return
	}
	busyFn, sharedFn := n.settings.Busy, n.settings.Shared
	cands := make([]yieldCandidate, 0, len(n.members))
	for _, m := range n.members {
		cands = append(cands, yieldCandidate{hb: m.hb, readySince: m.readySince, gone: n.goneLocked(m)})
	}
	n.mu.Unlock()
	if busyFn != nil && busyFn() != "" {
		return
	}
	self := Heartbeat{NodeID: n.ID(), Name: n.Name(), Version: n.opts.Version}
	if sharedFn != nil {
		sh := sharedFn()
		self.LevelMax, self.MaxRev = sh.LevelMax, sh.MaxRev
	}
	slices.SortFunc(cands, func(a, b yieldCandidate) int { return strings.Compare(a.hb.NodeID, b.hb.NodeID) })
	target, ok := yieldTarget(self, cands, now, n.timing)
	if !ok {
		return
	}
	n.mu.Lock()
	if n.releasing || !n.lease.Holding() {
		n.mu.Unlock()
		return
	}
	n.releasing, n.yielded, n.lastYield = true, true, now
	at := n.clock.Now().UTC()
	n.yieldedTo, n.yieldedAt = target.Name, &at
	n.mu.Unlock()
	reason := fmt.Sprintf("handing the background jobs to %s, which runs a newer version (%s)", target.Name, target.Version)
	n.log.Info(reason, "audit", true, "to", target.NodeID, "version", target.Version)
	go func() {
		n.lease.ReleaseTo(reason, target.NodeID)
		n.mu.Lock()
		n.releasing = false
		n.mu.Unlock()
	}()
}

// upgradeStatusLocked is what the heartbeat says of upgrades: what this
// server is doing that a rolling upgrade must wait for, and whom it
// handed the jobs to last. nil when there is nothing to say. The caller
// holds n.mu; busy was asked before.
func (n *Node) upgradeStatusLocked(busy string) *UpgradeStatus {
	if busy == "" && n.yieldedTo == "" {
		return nil
	}
	return &UpgradeStatus{Busy: busy, YieldedTo: n.yieldedTo, YieldedAt: n.yieldedAt}
}
