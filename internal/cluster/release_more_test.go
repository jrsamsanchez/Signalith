// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

// A server that does not hold the lease has nothing to give up.
func TestReleaseByAStandbyChangesNothing(t *testing.T) {
	s := newSim(t)
	a, b := s.add("n_a", nil), s.add("n_b", nil)
	s.run(time.Second)
	before := s.lease()
	b.l.ReleaseTo("an admin moved the background jobs", "n_b")
	if d := s.lease(); d.Holder != "n_a" || d.Epoch != before.Epoch || d.Prefer != "" || !a.l.Holding() {
		t.Fatalf("lease %+v after a standby's release", d)
	}
}

// A frozen lease cannot be written: its release stops the jobs and lets
// it run out, and the lease is taken again once writes work.
func TestReleaseOfAFrozenLease(t *testing.T) {
	s := newSim(t)
	a := s.add("n_a", nil)
	s.run(time.Second)
	s.os.Block(true)
	s.run(15 * time.Second)
	if !a.l.Frozen() {
		t.Fatalf("not frozen: %+v", a.l.View())
	}
	a.l.Release("this server stops")
	if a.l.Holding() || a.l.Frozen() {
		t.Fatalf("still holding after the release: %+v", a.l.View())
	}
	if d := s.lease(); d.Holder != "n_a" || d.ReleasedBy != "" {
		t.Fatalf("a frozen lease was written: %+v", d)
	}
	s.os.Block(false)
	s.run(2 * time.Minute)
	if !a.l.Holding() {
		t.Fatalf("the lease was not taken again: %+v", s.lease())
	}
}

// A release OpenSearch refuses leaves the lease to run out, and another
// server takes it then.
func TestReleaseNotWritten(t *testing.T) {
	s := newSim(t)
	a, b := s.add("n_a", nil), s.add("n_b", nil)
	s.run(time.Second)
	s.os.SetFault(func(method, path string) *ostest.Fault {
		if method == http.MethodPut && strings.Contains(path, leaseID) {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
	a.l.ReleaseTo("an admin moved the background jobs", "n_b")
	s.os.SetFault(nil)
	if d := s.lease(); d.Holder != "n_a" || d.Prefer != "" {
		t.Fatalf("lease %+v after a refused release", d)
	}
	if a.l.Holding() {
		t.Fatal("a still holds the lease it gave up")
	}
	a.paused = true
	s.run(2 * time.Minute)
	if !b.l.Holding() {
		t.Fatalf("b did not take over: %+v", s.lease())
	}
}
