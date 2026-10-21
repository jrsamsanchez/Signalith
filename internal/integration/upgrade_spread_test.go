// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package integration

import (
	"net/http"
	"testing"
	"time"
)

// Two servers of the previous release are upgraded one at a time to this
// commit's, with detections.spread turned on halfway: while a server of a
// version that cannot spread is running, the server running the jobs runs
// every rule itself; once both run this commit, the buckets spread over
// the two, and no rule falls behind on the way.
func TestUpgradeDetectionSpread(t *testing.T) {
	b := upgradeEnv(t)
	t.Parallel()
	h := newClusterHarness(t)
	a := h.add("siem-a", serverOptions{})
	startBin(a, b.prev)
	waitUntil(t, 45*time.Second, "siem-a runs the jobs", func() bool {
		v, ok := a.view()
		return ok && v.Lease.Mine
	})
	sb := h.add("siem-b", serverOptions{})
	startBin(sb, b.prev)
	waitStandby(t, a, sb)
	caps := detectCaps(t, b, a)
	if caps.level == 0 {
		t.Skipf("prev %s: no shared settings, so no detections.spread to turn on", b.prevVersion)
	}

	stopGraceful(sb)
	startBin(sb, b.next)
	if caps.yieldNewer {
		waitUntil(t, 3*time.Minute, "siem-a hands the jobs to the upgraded siem-b", func() bool { return h.leaseHolder() == "siem-b" })
	} else {
		waitStandby(t, a, sb)
	}
	code, _, body := sb.request(http.MethodPut, "/api/settings", map[string]any{"values": map[string]any{"detections.spread": true}}, nil)
	if code != http.StatusOK {
		t.Fatalf("turning detections.spread on next to %s: %d %s", b.prevVersion, code, body)
	}

	// For longer than a server waits to join the spread, an old siem-a
	// that can't spread keeps it from starting: no bucket has an owner.
	// A previous release that spreads too just joins in.
	deadline := time.Now().Add(90 * time.Second)
	for !caps.spread && time.Now().Before(deadline) {
		if v, ok := sb.spread(); ok && len(v.Servers) > 0 {
			t.Fatalf("detections spread while siem-a runs %s: %+v", b.prevVersion, v.Servers)
		}
		time.Sleep(3 * time.Second)
	}

	stopGraceful(a)
	waitUntil(t, 90*time.Second, "siem-b runs the jobs", func() bool { return h.leaseHolder() == "siem-b" })
	startBin(a, b.next)
	waitStandby(t, sb, a)
	ids := []string{h.nodeIDOf("siem-a"), h.nodeIDOf("siem-b")}
	var v spreadView
	waitUntil(t, 5*time.Minute, "the buckets spread over both upgraded servers", func() bool {
		var ok bool
		v, ok = a.spread()
		return ok && v.spreadOver(ids...)
	})
	t.Logf("spread after the upgrade: %v", v.running())
	if late := v.behind(); len(late) > 0 {
		t.Errorf("servers fall behind after the upgrade: %v", late)
	}
}
