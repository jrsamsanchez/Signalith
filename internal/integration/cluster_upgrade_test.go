// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package integration

// A rolling upgrade's hand-over: the server running the background jobs
// hands them to a server of a newer version once that one has been ready
// a while, and they stay there. Both binaries are this commit, built with
// different versions; the clustertest build shortens the wait through
// SIGNALITH_TEST_YIELD_SETTLE.

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var (
	versionedMu   sync.Mutex
	versionedBins = map[string]string{}
)

// versionedBinary builds this commit with the clustertest tag as version
// v, once per test run, next to signalithBinary's build.
func versionedBinary(t *testing.T, v string) string {
	t.Helper()
	signalithBinary(t)
	versionedMu.Lock()
	defer versionedMu.Unlock()
	if bin, ok := versionedBins[v]; ok {
		return bin
	}
	bin := filepath.Join(buildDir, "signalith-"+v)
	cmd := exec.Command("go", "build", "-tags", "clustertest", "-ldflags", "-X main.version="+v, "-o", bin, "../../cmd/signalith")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(fmt.Errorf("go build %s: %v\n%s", v, err, out))
	}
	versionedBins[v] = bin
	return bin
}

func TestClusterJobsMoveToNewer(t *testing.T) {
	const settle = 5 * time.Second
	t.Setenv("SIGNALITH_TEST_YIELD_SETTLE", settle.String())
	older, newer := versionedBinary(t, "9.9.0"), versionedBinary(t, "9.9.1")
	h := newClusterHarness(t)
	a := h.add("siem-a", serverOptions{})
	startBin(a, older)
	waitUntil(t, 45*time.Second, "siem-a runs the jobs", func() bool {
		v, ok := a.view()
		return ok && v.Lease.Mine
	})
	b := h.add("siem-b", serverOptions{})
	startBin(b, newer)
	// siem-a sees siem-b ready at its next heartbeat (10 s), waits the
	// settle time, and hands the jobs over at the heartbeat after.
	waitUntil(t, settle+40*time.Second, "the jobs move to siem-b, which runs 9.9.1", func() bool { return h.leaseHolder() == "siem-b" })
	l, ok := h.lease()
	if !ok || l.HolderVersion != "9.9.1" {
		t.Errorf("lease %+v", l)
	}
	if hb, ok := h.heartbeat("siem-a"); !ok || hb.Upgrade == nil || hb.Upgrade.YieldedTo != "siem-b" {
		waitUntil(t, 15*time.Second, "siem-a's heartbeat says it handed the jobs to siem-b", func() bool {
			hb, ok := h.heartbeat("siem-a")
			return ok && hb.Upgrade != nil && hb.Upgrade.YieldedTo == "siem-b"
		})
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if holder := h.leaseHolder(); holder != "siem-b" {
			t.Fatalf("the jobs moved back to %q", holder)
		}
		time.Sleep(time.Second)
	}
}
