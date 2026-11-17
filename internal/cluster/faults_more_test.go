// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// InUse says whether another open file holds the state folder's lock.
func TestInUse(t *testing.T) {
	dir := t.TempDir()
	if used, err := InUse(dir); err != nil || used {
		t.Fatalf("a folder never used: %v %v", used, err)
	}
	l, err := OpenLocal(dir, testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	used, err := InUse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !used {
		// Where files cannot be locked, nothing is in use.
		t.Log("this file system does not lock files")
	}
	l.Close()
	if used, err := InUse(dir); err != nil || used {
		t.Fatalf("a folder no longer used: %v %v", used, err)
	}
}

// unstartedNode is a node that has not written to any OpenSearch yet.
func unstartedNode(t *testing.T) *Node {
	t.Helper()
	l, err := OpenLocal(t.TempDir(), testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return New(Options{Local: l, Version: "1.0.0", Timing: fast})
}

// The first heartbeat on an OpenSearch whose disk is full claims nothing
// and writes nothing, and says writes are refused.
func TestFirstHeartbeatOnAFullDisk(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	n := unstartedNode(t)
	fos.SetFault(func(method, path string) *ostest.Fault {
		if method == http.MethodPut && strings.Contains(path, "/_create/") {
			return &ostest.Fault{Status: http.StatusForbidden, Type: "cluster_block_exception"}
		}
		return nil
	})
	if err := n.firstHeartbeat(context.Background(), c, "s"); err != nil {
		t.Fatal(err)
	}
	if !n.WritesRefused() {
		t.Fatal("writes are not said to be refused")
	}
}

// A heartbeat that keeps changing between the read and the write is
// another process's.
func TestFirstHeartbeatKeepsConflicting(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	n := unstartedNode(t)
	fos.FailN(3, http.MethodPut, "/_create/", http.StatusConflict, "version_conflict_engine_exception")
	err := n.firstHeartbeat(context.Background(), c, "s")
	if _, ok := err.(*identityConflictError); !ok {
		t.Fatalf("a heartbeat that kept changing: %v", err)
	}
}

// A start cancelled while it watches a heartbeat of its identity that
// another process wrote stops there.
func TestFirstHeartbeatCancelledWhileWatching(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	n := unstartedNode(t)
	if err := ensureRuntime(context.Background(), c, "s"); err != nil {
		t.Fatal(err)
	}
	fos.Put(RuntimeIndex("s"), nodeDocID(n.ID()), map[string]any{"kind": "node", "node_id": n.ID(), "boot_id": "another-process", "name": "copy"})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := n.firstHeartbeat(ctx, c, "s"); err == nil {
		t.Fatal("a start cancelled while watching was no error")
	}
}

// A frozen lease (OpenSearch refuses writes) that another server changed
// meanwhile is given up: at once when a read shows it, or when the next
// renewal once writes work again conflicts.
func TestFrozenLeaseChangedElsewhereIsLost(t *testing.T) {
	for _, unblock := range []bool{false, true} {
		s := newSim(t)
		a := s.add("n_a", nil)
		job := &probe{}
		a.l.SetJobs([]Job{job.job("detections", false)})
		s.run(time.Second)
		s.os.Block(true)
		s.run(15 * time.Second)
		if !a.l.Frozen() {
			t.Fatalf("not frozen: %+v", a.l.View())
		}
		other := s.lease()
		other.Holder, other.Epoch = "n_b", other.Epoch+1
		raw, _ := json.Marshal(other)
		var src map[string]any
		_ = json.Unmarshal(raw, &src)
		s.os.Put(testIndex, leaseID, src)
		if unblock {
			s.os.Block(false)
		}
		s.run(10 * time.Second)
		if a.l.Frozen() || a.l.Holding() {
			t.Fatalf("unblocked %v: still holds a lease another server changed: %+v", unblock, a.l.View())
		}
	}
}

// The heartbeat carries what the server's hooks report.
func TestHeartbeatDocHooks(t *testing.T) {
	n := unstartedNode(t)
	since := time.Now().UTC()
	n.settings.Traffic = func() Traffic { return Traffic{Since: since} }
	n.settings.DetTenants = func() map[string]string { return map[string]string{"acme": "fp1"} }
	n.settings.DetReleased = func() map[string]map[int]int64 { return map[string]map[int]int64{"acme": {3: 7}} }
	hb := n.heartbeatDoc(StateReady)
	if hb.Traffic == nil || !hb.Traffic.Since.Equal(since) {
		t.Errorf("traffic %+v", hb.Traffic)
	}
	if hb.DetTenants["acme"] != "fp1" || hb.DetReleased["acme"][3] != 7 {
		t.Errorf("detections %v %v", hb.DetTenants, hb.DetReleased)
	}
}

// A conflict names the other process's address, and says how to give
// a server a new identity the way it is deployed.
func TestIdentityConflictMessage(t *testing.T) {
	for _, dep := range []string{"", "docker"} {
		n := unstartedNode(t)
		n.opts.Deployment = dep
		err := n.identityConflict(&Heartbeat{Name: "copy", NodeURL: "https://copy.example.com:8443"})
		if err == nil || !strings.Contains(err.Error(), "copy, https://copy.example.com:8443") {
			t.Fatalf("%q: %v", dep, err)
		}
		if got := strings.Contains(err.Error(), "docker compose"); got != (dep == "docker") {
			t.Errorf("%q: %v", dep, err)
		}
	}
}

// A lease on standby has no epoch, and one with no fingerprints hook
// reports none.
func TestStandbyLease(t *testing.T) {
	l := &Lease{}
	if l.Epoch() != 0 {
		t.Errorf("epoch on standby %d", l.Epoch())
	}
	if fp := l.fingerprints(true); fp != (Fingerprints{}) {
		t.Errorf("fingerprints %+v", fp)
	}
}

// A file is never written under a file.
func TestWriteFileAtomicUnderAFile(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-folder")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(filepath.Join(blocker, "identity.json"), []byte("{}")); err == nil {
		t.Error("written under a file")
	}
}

// A node made with no timing uses the default one.
func TestNodeDefaultTiming(t *testing.T) {
	l, err := OpenLocal(t.TempDir(), testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	n := New(Options{Local: l, Version: "1.0.0"})
	if n.timing != DefaultTiming {
		t.Errorf("timing %+v", n.timing)
	}
	partial := fast
	partial.FilesWait = 0
	n = New(Options{Local: l, Version: "1.0.0", Timing: partial})
	if n.timing.FilesWait != DefaultTiming.FilesWait || n.timing.Watch != fast.Watch {
		t.Errorf("timing %+v", n.timing)
	}
}

// leaderElsewhere finds another server's heartbeat that says it runs the
// jobs; it and maxEpoch fail when OpenSearch cannot be searched.
func TestLeaderElsewhereAndMaxEpoch(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	ctx := context.Background()
	if err := ensureRuntime(ctx, c, "s"); err != nil {
		t.Fatal(err)
	}
	index := RuntimeIndex("s")
	fos.Put(index, nodeDocID("n_self"), map[string]any{"kind": "node", "node_id": "n_self", "leader": true})
	if found, err := leaderElsewhere(ctx, c, index, "n_self"); err != nil || found {
		t.Fatalf("only this server leads: %v %v", found, err)
	}
	fos.Put(index, nodeDocID("n_other"), map[string]any{"kind": "node", "node_id": "n_other", "leader": true})
	if found, err := leaderElsewhere(ctx, c, index, "n_self"); err != nil || !found {
		t.Fatalf("another server leads: %v %v", found, err)
	}
	fos.SetFault(func(method, path string) *ostest.Fault {
		if strings.Contains(path, "_search") {
			return &ostest.Fault{Status: http.StatusBadRequest, Type: "search_phase_execution_exception"}
		}
		return nil
	})
	if _, err := leaderElsewhere(ctx, c, index, "n_self"); err == nil {
		t.Error("leaderElsewhere without a search")
	}
	if _, err := maxEpoch(ctx, c, index); err == nil || !strings.Contains(err.Error(), "highest job lease epoch") {
		t.Errorf("maxEpoch without a search: %v", err)
	}
}

func TestFirstHeartbeatCannotRead(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	n := unstartedNode(t)
	fos.SetFault(func(method, path string) *ostest.Fault {
		if method == http.MethodGet && strings.Contains(path, "/_doc/") {
			return &ostest.Fault{Status: http.StatusBadRequest, Type: "illegal_argument_exception"}
		}
		return nil
	})
	if err := n.firstHeartbeat(context.Background(), c, "s"); err == nil {
		t.Fatal("a heartbeat that cannot be read was no error")
	}
	fos.SetFault(func(method, path string) *ostest.Fault {
		if method == http.MethodPut && strings.Contains(path, "/_create/") {
			return &ostest.Fault{Status: http.StatusBadRequest, Type: "mapper_parsing_exception"}
		}
		return nil
	})
	if err := n.firstHeartbeat(context.Background(), c, "s"); err == nil {
		t.Fatal("a heartbeat that cannot be written was no error")
	}
}
