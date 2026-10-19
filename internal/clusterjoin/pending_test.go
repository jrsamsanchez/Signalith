// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterjoin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

var fastTiming = shared.Timing{Poll: 10 * time.Millisecond, Resync: time.Minute, Wait: 100 * time.Millisecond, CacheEvery: time.Second}

// runtime starts a server's shared-settings runtime on the fake, with its
// own state folder; lease says whether it holds the job lease.
func (e *env) runtime(name string, lease bool) (*shared.Runtime, string) {
	e.t.Helper()
	return e.runtimeWith(name, lease, nil)
}

// runtimeWith is runtime with content, which makes the shared documents
// on each hub the runtime builds.
func (e *env) runtimeWith(name string, lease bool, content func(*shared.Hub)) (*shared.Runtime, string) {
	e.t.Helper()
	dir := e.t.TempDir()
	rt := shared.NewRuntime(shared.RuntimeOptions{StateDir: dir, Self: shared.Self{NodeID: "n_" + name, Name: name}, Content: content,
		HoldsLease: func() bool { return lease },
		LeaseCheck: func(context.Context) error {
			if !lease {
				return errors.New("no lease")
			}
			return nil
		},
		LeaseEpoch: func() int64 { return 1 }, Timing: fastTiming})
	rt.Use(e.cl, prefix, secrets.NewKeyring(dir))
	ctx, cancel := context.WithCancel(context.Background())
	rt.Start(ctx)
	e.t.Cleanup(func() {
		cancel()
		rt.Wait()
	})
	return rt, dir
}

func waitMode(t *testing.T, rt *shared.Runtime, want shared.Mode) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m, _ := rt.Mode(); m == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	m, why := rt.Mode()
	t.Fatalf("mode %s (%s), want %s", m, why, want)
}

func waitPending(t *testing.T, ap *Approver, n int) []shared.PendingDoc {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		list, err := ap.Pending(context.Background())
		if err == nil && len(list) == n {
			return list
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("not %d pending", n)
	return nil
}

func TestApprove(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.runtime("siem-a", true)
	waitMode(t, a, shared.ModeMember)
	b, bdir := e.runtime("siem-b", false)
	waitMode(t, b, shared.ModeLegacyB)

	ap := &Approver{RT: a}
	list := waitPending(t, ap, 1)
	fp := b.Status().Fingerprint
	if list[0].NodeID != "n_siem-b" || list[0].Fingerprint != fp {
		t.Fatalf("pending %+v, fingerprint %s", list[0], fp)
	}

	// A fingerprint that does not match is refused, and nothing changes.
	other, _ := shared.NewNodeKey()
	if _, err := ap.Approve(ctx, "n_siem-b", other.Fingerprint(), "sam"); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("wrong fingerprint: %v", err)
	}
	if kr, _ := a.Keyring().Get(); kr.Members["n_siem-b"].NodePub != "" {
		t.Fatal("a refused approval listed the server")
	}
	if _, err := ap.Approve(ctx, "n_nobody", fp, "sam"); !errors.Is(err, ErrNoPending) {
		t.Errorf("unknown server: %v", err)
	}
	// The secured-OpenSearch requirement.
	ap.Secured = func() error { return ErrNotSecured }
	if _, err := ap.Approve(ctx, "n_siem-b", fp, "sam"); !errors.Is(err, ErrNotSecured) {
		t.Errorf("not secured: %v", err)
	}
	ap.Secured = nil
	// Only a member approves.
	bp := &Approver{RT: b}
	if _, err := bp.Approve(ctx, "n_siem-b", fp, "sam"); err == nil {
		t.Error("a server outside the cluster approved")
	}

	// A server removed before is readmitted to OpenSearch's
	// certificates on approval; when that fails no approval is written.
	ap.Readmit = func(context.Context, string) error { return errors.New("down") }
	if _, err := ap.Approve(ctx, "n_siem-b", fp, "sam"); err == nil || !strings.Contains(err.Error(), "readmitted") {
		t.Fatalf("readmit failed: %v", err)
	}
	if ok, _ := a.Approved(ctx); ok["n_siem-b"] {
		t.Fatal("approved although the readmit failed")
	}
	var readmitted []string
	ap.Readmit = func(_ context.Context, id string) error { readmitted = append(readmitted, id); return nil }

	// Fingerprints are compared without case or dashes.
	p, err := ap.Approve(ctx, "n_siem-b", " "+lowerNoDash(fp)+" ", "sam")
	if err != nil {
		t.Fatal(err)
	}
	if len(readmitted) != 1 || readmitted[0] != "n_siem-b" {
		t.Errorf("readmitted %v", readmitted)
	}
	if p.Name != "siem-b" {
		t.Errorf("approved %+v", p)
	}
	waitMode(t, b, shared.ModeMember)
	if b.Hub().Keys().Active().ID() != e.keyOf(a).ID() {
		t.Error("joined with another key")
	}
	if len(shared.ClusterKeyFiles(bdir)) != 1 {
		t.Error("the approved server keeps no cluster key")
	}
	kr, _ := a.Keyring().Get()
	if m := kr.Members["n_siem-b"]; m.AddedBy != shared.AddedByApproval || m.Fingerprint != fp {
		t.Errorf("member = %+v", m)
	}
	if l, _ := ap.Pending(ctx); len(l) != 0 {
		t.Errorf("still pending: %+v", l)
	}
}

func (e *env) keyOf(rt *shared.Runtime) *shared.ClusterKey { return rt.Hub().Keys().Active() }

func lowerNoDash(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

func TestSameFingerprint(t *testing.T) {
	if !SameFingerprint("4F2A-91C0", "4f2a91c0") || !SameFingerprint("4F2A 91C0", "4F2A-91C0") {
		t.Error("the same fingerprint differs")
	}
	if SameFingerprint("", "") || SameFingerprint("4F2A", "4F2B") {
		t.Error("different fingerprints match")
	}
}
