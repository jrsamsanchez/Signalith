// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/detect"
)

// Two servers of the previous release are upgraded one at a time to this
// commit's, with detections.spread turned on halfway: while a server of a
// version that cannot spread is running, the server running the jobs runs
// every rule itself; once both run this commit, the buckets spread over
// the two, no slot is skipped on the way, and every rule keeps up.
//
// Runs that started late while one server ran every rule (each restart
// leaves one) are logged, not failed: on a shared 2-core CI runner a lone
// server can rightly be late then, and the Servers page says so for an
// hour. What must hold is that no slot is skipped, and that once the
// buckets are spread over both upgraded servers every rule catches up
// within upgradeSettle and no run starts late after that.
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
	dumpLogsOnFailure(t, a, sb)
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
	settled := time.Now()

	// Every rule catches up on the two servers: none is half a schedule
	// interval or more past its next slot.
	var behind []string
	deadline = time.Now().Add(upgradeSettle)
	for {
		states, ok := h.detStates()
		behind = rulesBehind(states, time.Now(), 2)
		if ok && len(behind) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("rules still behind %s after the buckets spread: %v", upgradeSettle, behind)
			break
		}
		time.Sleep(5 * time.Second)
	}
	caughtUp := time.Now()
	t.Logf("every rule caught up %s after the buckets spread", caughtUp.Sub(settled).Round(time.Second))

	// One more minute on the settled layout: no rule falls a whole
	// interval behind, and none starts a run late (a rule half an interval
	// behind at most cannot start a run a whole interval late within a
	// minute unless the servers do not keep up).
	time.Sleep(time.Minute)
	states, _ := h.detStates()
	if late := rulesBehind(states, time.Now(), 1); len(late) > 0 {
		t.Errorf("rules fall behind again after catching up: %v", late)
	}
	var before []string
	for _, st := range states {
		switch {
		case st.LastLate.IsZero():
		case st.LastLate.After(caughtUp):
			t.Errorf("rule %s started a run late at %s on %s, after every rule had caught up", st.DetectionID, st.LastLate.Format(time.RFC3339), st.LateNode)
		default:
			before = append(before, fmt.Sprintf("%s on %q at %s", st.DetectionID, st.LateNode, st.LastLate.Format(time.TimeOnly)))
		}
	}
	slices.Sort(before)
	if len(before) > 0 {
		t.Logf("runs that started late before the rules caught up (tolerated): %v", before)
	}
	// Skipped slots are never tolerated: they are events no rule looked at.
	if v, ok := a.spread(); ok {
		for id, hl := range v.Health {
			if hl.SkippedHour > 0 {
				t.Errorf("server %s skipped %d slots in the last hour: %s", id, hl.SkippedHour, hl.Why)
			} else if hl.Behind {
				t.Logf("server %s: %s (tolerated: late runs while one server ran every rule)", id, hl.Why)
			}
		}
	}
}

// upgradeSettle is how long after the buckets spread every rule must have
// caught up.
const upgradeSettle = 3 * time.Minute

// detStates reads the default tenant's run state of every rule from
// OpenSearch.
func (h *clusterHarness) detStates() ([]detect.DetState, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	docs, err := h.os.SearchDocs(ctx, cluster.RuntimeIndex(h.prefix), map[string]any{"term": map[string]any{"kind": "detstate"}})
	if err != nil {
		return nil, false
	}
	var out []detect.DetState
	for _, d := range docs {
		var st detect.DetState
		if json.Unmarshal(d.Source, &st) == nil && st.DetectionID != "" {
			out = append(out, st)
		}
	}
	return out, true
}

// rulesBehind lists the enabled rules whose next slot ended more than
// 1/part of a schedule interval before now; part 1 is how the Detections
// page counts a rule behind.
func rulesBehind(states []detect.DetState, now time.Time, part int) []string {
	var out []string
	for _, st := range states {
		sched, err := detect.ParseDuration(st.Schedule)
		if err != nil || !st.Enabled || !st.GoneSince.IsZero() || st.NextSlot.IsZero() {
			continue
		}
		if over := now.Sub(st.NextSlot); over > sched/time.Duration(part) {
			out = append(out, fmt.Sprintf("%s (%s, %s behind)", st.DetectionID, st.Schedule, over.Round(time.Second)))
		}
	}
	slices.Sort(out)
	return out
}
