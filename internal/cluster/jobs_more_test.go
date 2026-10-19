// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The node address applies from the next heartbeat, and the jobs set run
// while this server holds the lease, until they are replaced.
func TestNodeURLAndJobs(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	a := testNode(t, t.TempDir(), c, true)
	waitReady(t, a, 5*time.Second)
	const url = "https://siem-a.internal.example:8443"
	a.SetNodeURL(url)
	until(t, 5*time.Second, "the new address in the heartbeat", func() bool { return heartbeatOf(t, fos, a.ID()).NodeURL == url })

	var running atomic.Int32
	a.SetJobs([]Job{{Name: "probe", Run: func(ctx context.Context) {
		running.Add(1)
		<-ctx.Done()
		running.Add(-1)
	}}})
	until(t, 5*time.Second, "the job runs", func() bool { return running.Load() == 1 })
	if err := a.Check(context.Background()); err != nil {
		t.Errorf("the holder's check: %v", err)
	}
	a.SetJobs(nil)
	if n := running.Load(); n != 0 {
		t.Errorf("%d jobs still run after SetJobs(nil)", n)
	}
}

// The fence before a change confirms the lease in OpenSearch: it refuses
// a standby, a lease another server took and a lease it cannot read.
func TestLeaseCheck(t *testing.T) {
	s := newSim(t)
	a, b := s.add("n_a", nil), s.add("n_b", nil)
	s.run(time.Second)
	ctx := context.Background()
	if err := a.l.Check(ctx); err != nil {
		t.Fatalf("the holder: %v", err)
	}
	if err := b.l.Check(ctx); !errors.Is(err, ErrNotHolder) {
		t.Errorf("a standby: %v", err)
	}
	s.os.SetFault(func(method, path string) *ostest.Fault {
		if method == http.MethodGet && strings.Contains(path, leaseID) {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
	if err := a.l.Check(ctx); err == nil || !strings.Contains(err.Error(), "could not confirm") {
		t.Errorf("an unreadable lease: %v", err)
	}
	s.os.SetFault(nil)
	src := s.os.Source(testIndex, leaseID)
	src["holder"], src["holder_boot"] = "n_b", "b_n_b"
	s.os.Put(testIndex, leaseID, src)
	if d := s.lease(); d.Holder != "n_b" || d.HolderBoot != "b_n_b" {
		t.Fatalf("the lease was not changed: %+v", d)
	}
	if err := a.l.Check(ctx); !errors.Is(err, ErrNotHolder) {
		t.Errorf("a lease taken by another: %v", err)
	}
}
