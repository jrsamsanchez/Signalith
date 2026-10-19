//go:build integration && linux

package integration

// Detections spread over servers (detections.spread), with real `signalith
// serve` processes: once the setting is on, every server runs a share of
// each tenant's buckets, and a server killed without warning has its
// buckets moved to the others, with no rule falling behind.

import (
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

// spreadView is a tenant's entry of the detections block of GET
// /api/cluster.
type spreadView struct {
	Tenant  string `json:"tenant"`
	Buckets int    `json:"buckets"`
	Servers map[string]struct {
		Run    int `json:"run"`
		Moving int `json:"moving"`
	} `json:"servers"`
	Health map[string]struct {
		Rules       int    `json:"rules"`
		Skipped     int    `json:"skipped"`
		SkippedHour int    `json:"skipped_hour"`
		Behind      bool   `json:"behind"`
		Why         string `json:"why"`
	} `json:"health"`
}

// spread reads the default tenant's spread from the server's GET
// /api/cluster; ok is false when it did not answer. A cluster whose
// detections are not spread has no servers in it.
func (s *testServer) spread() (v spreadView, ok bool) {
	var out struct {
		Detections []spreadView `json:"detections"`
	}
	if s.api == nil || s.call(http.MethodGet, "/api/cluster", nil, &out) != http.StatusOK {
		return v, false
	}
	for _, d := range out.Detections {
		if d.Tenant == "" || d.Tenant == "default" {
			return d, true
		}
	}
	return v, true
}

// running sums the buckets each server runs (not moving), by node ID.
func (v spreadView) running() map[string]int {
	out := map[string]int{}
	for id, c := range v.Servers {
		if c.Run > 0 {
			out[id] = c.Run
		}
	}
	return out
}

// spreadOver reports whether every bucket runs and each of ids runs some,
// and no other server does.
func (v spreadView) spreadOver(ids ...string) bool {
	run := v.running()
	total := 0
	for id, n := range run {
		if !slices.Contains(ids, id) {
			return false
		}
		total += n
	}
	for _, c := range v.Servers {
		if c.Moving > 0 {
			return false
		}
	}
	return len(run) == len(ids) && total == detect.Buckets
}

// behind lists the servers the page says fall behind, with why.
func (v spreadView) behind() []string {
	var out []string
	for id, h := range v.Health {
		if h.Behind || h.SkippedHour > 0 {
			out = append(out, fmt.Sprintf("%s: %s (skipped %d)", id, h.Why, h.SkippedHour))
		}
	}
	slices.Sort(out)
	return out
}

// nodeIDOf waits for the server's heartbeat and returns its node ID.
func (h *clusterHarness) nodeIDOf(name string) string {
	h.t.Helper()
	var id string
	waitUntil(h.t, 30*time.Second, name+"'s heartbeat", func() bool {
		hb, ok := h.heartbeat(name)
		id = hb.NodeID
		return ok && id != ""
	})
	return id
}

// Three servers share the buckets (detections.spread is on by default); one killed
// has its buckets moved to the other two, and none falls behind.
func TestClusterDetectionSpread(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	c := h.start("siem-c", serverOptions{})
	waitSettingsShared(t, a, b, c)
	ids := []string{h.nodeIDOf("siem-a"), h.nodeIDOf("siem-b"), h.nodeIDOf("siem-c")}

	// detections.spread is on unless turned off. A server joins the
	// spread once it has been able to for a minute (detect.DefaultJoinDelay).
	var v spreadView
	waitUntil(t, 4*time.Minute, "the buckets spread over the three servers", func() bool {
		var ok bool
		v, ok = b.spread()
		return ok && v.spreadOver(ids...)
	})
	t.Logf("spread: %v", v.running())
	for id, n := range v.running() {
		// Rendezvous hashing of 64 buckets over 3 servers: far from even
		// only when something is wrong.
		if n < 8 {
			t.Errorf("server %s runs only %d of %d buckets: %v", id, n, detect.Buckets, v.running())
		}
	}

	// Each server runs the rules of its buckets: the run state says so
	// once each rule's next slot came (the built-in rules run every 5
	// minutes).
	waitUntil(t, 7*time.Minute, "each server runs rules of its buckets", func() bool {
		v, ok := a.spread()
		if !ok {
			return false
		}
		for _, id := range ids {
			if v.Health[id].Rules == 0 {
				return false
			}
		}
		return true
	})

	// siem-c dies without handing its buckets over: after the takeover
	// time the leader gives them to the other two.
	c.kill9()
	waitUntil(t, 3*time.Minute, "siem-c's buckets move to siem-a and siem-b", func() bool {
		var ok bool
		v, ok = a.spread()
		return ok && v.spreadOver(ids[0], ids[1])
	})
	t.Logf("after siem-c died: %v", v.running())

	// The rules siem-c ran catch up on their new servers from the run
	// state: none is skipped.
	time.Sleep(30 * time.Second)
	if v, ok := a.spread(); !ok || len(v.behind()) > 0 {
		t.Errorf("servers fall behind after siem-c died: %v", v.behind())
	}

	// With the setting off again, the leader runs every rule itself.
	a.saveSettings("", map[string]any{"detections.spread": false})
	waitUntil(t, 3*time.Minute, "the leader runs every rule again", func() bool {
		v, ok := b.spread()
		return ok && len(v.Servers) == 0
	})
}
