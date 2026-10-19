// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

// A live member that does not pick up the new key stops the rotation
// after MemberWait, naming it; asked again, the rotation goes on from
// where it stopped once the member runs again.
func TestKeyRotationWaitsForALiveMember(t *testing.T) {
	rc := newRotationCluster(t)
	old := rc.a.key().ID()
	done := make(chan error, 1)
	go func() {
		_, err := rc.a.rt.RotateKey(context.Background(), RotateOptions{By: "admin", Reason: "rotate-key", Poll: time.Second, MemberWait: 5 * time.Second})
		done <- err
	}()
	var err error
wait:
	for range 500 {
		rc.b.step()
		rc.heartbeats()
		select {
		case err = <-done:
			break wait
		case <-time.After(5 * time.Millisecond):
		}
		if rc.e.clock.Waiting() > 0 {
			rc.e.clock.Advance(time.Second)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "siem-c did not pick up the new cluster key in time") {
		t.Fatalf("RotateKey = %v", err)
	}
	kr, _ := rc.a.rt.Keyring().Get()
	n, _ := kr.Rotation()
	if n == nil || n.Phase != PhaseDistribute || kr.Active != old {
		t.Fatalf("rotation %+v, active %s", n, kr.Active)
	}
	if st := rc.a.rt.Rotation(); st.InProgress == nil || st.InProgress.KID != n.KID {
		t.Errorf("status = %+v", st)
	}

	res, err := rc.rotate(RotateOptions{By: "admin", Reason: "rotate-key"})
	if err != nil {
		t.Fatal(err)
	}
	if res.KID != n.KID || len(res.Skipped) != 0 {
		t.Errorf("result %+v, want the rotation to %s", res, n.KID)
	}
	mustContain(t, "log", rc.c.logs.String(), "picked up the new cluster key")
}

// Only the member that runs the background jobs rotates.
func TestKeyRotationRefusals(t *testing.T) {
	rc := newRotationCluster(t)
	ctx := context.Background()
	if _, err := rc.b.rt.RotateKey(ctx, RotateOptions{By: "admin"}); err == nil || !strings.Contains(err.Error(), "lost the job lease") {
		t.Errorf("a rotation without the lease = %v", err)
	}
	ro := rc.e.server("siem-r", func(o *RuntimeOptions) {
		o.ReadOnly = true
		o.KeyFile = writeKeyFile(t, rc.a.key())
		o.Peers = rc.peers.get
	})
	ro.step()
	if m := ro.mode(); m == ModeMember {
		if _, err := ro.rt.RotateKey(ctx, RotateOptions{By: "admin"}); err == nil || !strings.Contains(err.Error(), "runs on the server that runs the background jobs") {
			t.Errorf("a rotation on a read-only server = %v", err)
		}
	}
	e := newEnv(t)
	lone := e.server("siem-z", nil)
	var paused *PausedError
	if _, err := lone.rt.RotateKey(ctx, RotateOptions{By: "admin"}); !errors.As(err, &paused) {
		t.Errorf("a rotation on a server not in a cluster = %v", err)
	}
}

// A rotation the old job holder left in progress is taken on by the new
// one, which first picks up its own copy of the new key.
func TestKeyRotationTakenOverByTheNextHolder(t *testing.T) {
	rc := newRotationCluster(t)
	done := make(chan error, 1)
	go func() {
		_, err := rc.a.rt.RotateKey(context.Background(), RotateOptions{By: "admin", Reason: "rotate-key", Poll: time.Second, MemberWait: 3 * time.Second})
		done <- err
	}()
	var err error
wait:
	for range 500 {
		rc.heartbeats()
		select {
		case err = <-done:
			break wait
		case <-time.After(5 * time.Millisecond):
		}
		if rc.e.clock.Waiting() > 0 {
			rc.e.clock.Advance(time.Second)
		}
	}
	if err == nil {
		t.Fatal("the rotation did not stop for the members that did not pick up the key")
	}
	kr, _ := rc.a.rt.Keyring().Get()
	n, _ := kr.Rotation()
	if n == nil {
		t.Fatal("no rotation in progress")
	}
	rc.a.holds.Store(false)
	rc.b.holds.Store(true)
	// It reads the keyring, but its loop has not run to pick up its copy.
	cycle(t, rc.b.rt.Hub())
	if rc.b.rt.Hub().Keys().Get(n.KID) != nil {
		t.Fatal("siem-b has the new key before taking over")
	}
	done2 := make(chan error, 1)
	go func() {
		_, err := rc.b.rt.RotateKey(context.Background(), RotateOptions{By: "admin", Reason: "rotate-key", Poll: time.Second, MemberWait: time.Minute})
		done2 <- err
	}()
	for range 500 {
		rc.a.step()
		rc.c.step()
		rc.heartbeats()
		select {
		case err = <-done2:
			if err != nil {
				t.Fatal(err)
			}
			kr, _ := rc.b.rt.Keyring().Get()
			if kr.Active != n.KID {
				t.Errorf("active %s, want %s", kr.Active, n.KID)
			}
			mustContain(t, "log", rc.b.logs.String(), "picked up the new cluster key")
			return
		case <-time.After(5 * time.Millisecond):
		}
		if rc.e.clock.Waiting() > 0 {
			rc.e.clock.Advance(time.Second)
		}
	}
	t.Fatal("the rotation did not end")
}

// A rotation whose server loses the job lease part way stops at the next
// step, and a resealer that fails on its second run stops it before the
// old key is retired.
func TestKeyRotationStops(t *testing.T) {
	for _, at := range []int{1, 2, 3} {
		t.Run("lease lost after step "+rotationSteps[at], func(t *testing.T) {
			rc := newRotationCluster(t)
			_, err := rc.rotate(RotateOptions{By: "admin", Progress: func(_ string, done, _ int) {
				if done == at {
					rc.a.holds.Store(false)
				}
			}})
			if err == nil || !strings.Contains(err.Error(), "lost the job lease") {
				t.Fatalf("RotateKey = %v", err)
			}
			kr, _ := rc.a.rt.Keyring().Get()
			if n, _ := kr.Rotation(); n == nil {
				t.Error("the rotation is not in progress any more")
			}
		})
	}
	t.Run("second reseal fails", func(t *testing.T) {
		rc := newRotationCluster(t)
		var runs atomic.Int32
		rs := func(context.Context) error {
			if runs.Add(1) == 2 {
				return errors.New("cannot reach OpenSearch")
			}
			return nil
		}
		old := rc.a.key().ID()
		_, err := rc.rotate(RotateOptions{By: "admin", Resealers: []Resealer{rs}})
		if err == nil || !strings.Contains(err.Error(), "sealing the shared secrets again") {
			t.Fatalf("RotateKey = %v", err)
		}
		kr, _ := rc.a.rt.Keyring().Get()
		if !slices.Contains(kr.KIDs(), old) {
			t.Error("the old key was retired although the second reseal failed")
		}
	})
}

// A member catches up only from a keyring it can read that offers it a
// copy: anything else keeps nothing.
func TestCatchUpNeedsAnOffer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	good := e.os.Source(testIndex, KeyringDocID)
	for name, put := range map[string]func(){
		"no rotation":   func() {},
		"gone":          func() { e.os.Delete(testIndex, KeyringDocID) },
		"not envelope":  func() { e.os.Put(testIndex, KeyringDocID, map[string]any{"body": 5}) },
		"body not json": func() { e.putSigned(a.key(), KeyringDocID, "keyring", 1, 99, "not json", nil) },
		"deleted": func() {
			e.os.Put(testIndex, KeyringDocID, map[string]any{"kind": "keyring", "id": KeyringDocID, "deleted": true, "body": "{}"})
		},
	} {
		put()
		if a.rt.catchUp(ctx) {
			t.Errorf("%s: caught up", name)
		}
		e.os.Put(testIndex, KeyringDocID, good)
	}
	if n := len(ClusterKeyFiles(a.dir)); n != 1 {
		t.Errorf("%d keys kept", n)
	}
	lone := e.server("siem-z", nil)
	if lone.rt.catchUp(ctx) {
		t.Error("a server with no key caught up")
	}
}

// A server whose keyring copy is behind does not start a second rotation
// over one in progress.
func TestKeyRotationStartedElsewhere(t *testing.T) {
	rc := newRotationCluster(t)
	done := make(chan error, 1)
	go func() {
		_, err := rc.a.rt.RotateKey(context.Background(), RotateOptions{By: "admin", Poll: time.Second, MemberWait: 2 * time.Second})
		done <- err
	}()
	for stopped := false; !stopped; {
		rc.heartbeats()
		select {
		case <-done:
			stopped = true
		case <-time.After(5 * time.Millisecond):
			if rc.e.clock.Waiting() > 0 {
				rc.e.clock.Advance(time.Second)
			}
		}
	}
	kr, _ := rc.a.rt.Keyring().Get()
	n, _ := kr.Rotation()
	if n == nil {
		t.Fatal("no rotation in progress")
	}
	rc.a.holds.Store(false)
	rc.b.holds.Store(true)
	if _, err := rc.b.rt.RotateKey(context.Background(), RotateOptions{By: "admin"}); err == nil || !strings.Contains(err.Error(), "another rotation of the cluster key started meanwhile") {
		t.Errorf("RotateKey over a rotation in progress = %v", err)
	}
	kr, _ = rc.e.server("siem-q", func(o *RuntimeOptions) { o.KeyFile = writeKeyFile(t, rc.a.key()) }).rt.Keyring().Get()
	if cur, _ := kr.Rotation(); cur == nil || cur.KID != n.KID {
		t.Errorf("the rotation in progress is now %+v, want %s", cur, n.KID)
	}
}

func TestJoinNames(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, ""}, {[]string{"a"}, "a"}, {[]string{"a", "b"}, "a and b"}, {[]string{"a", "b", "c"}, "a, b and c"},
	} {
		if got := joinNames(c.in); got != c.want {
			t.Errorf("joinNames(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Signing again stops at a write OpenSearch refuses, naming the document,
// and leaves a document no key signed as it is.
func TestResignOldFaults(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	d := NewDoc[testBody](a, "users", "users", 1)
	if _, err := d.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "jlee"; return nil }); err != nil {
		t.Fatal(err)
	}
	stranger, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	e.putSigned(stranger, "forged", "settings", 1, 1, `{"x":1}`, nil)
	k, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if method == http.MethodPut && strings.Contains(path, "/_doc/users") {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
	_, _, err = resignOld(ctx, e.c, testPrefix, k, NewKeySet(e.key), "siem-a")
	if err == nil || !strings.Contains(err.Error(), "users") {
		t.Errorf("resignOld = %v", err)
	}
	// A document that changes once while it is signed is read again; one
	// that keeps changing stops the pass.
	var conflicts atomic.Int32
	conflict := func(limit int32) {
		conflicts.Store(0)
		e.os.SetFault(func(method, path string) *ostest.Fault {
			if method == http.MethodPut && strings.Contains(path, "/_doc/users") && (limit < 0 || conflicts.Load() < limit) {
				conflicts.Add(1)
				return &ostest.Fault{Status: http.StatusConflict, Type: "version_conflict_engine_exception"}
			}
			return nil
		})
	}
	conflict(-1)
	if _, _, err := resignOld(ctx, e.c, testPrefix, k, NewKeySet(e.key), "siem-a"); err == nil || !strings.Contains(err.Error(), "kept changing") {
		t.Errorf("resignOld with a document that keeps changing = %v", err)
	}
	conflict(1)
	n, refused, err := resignOld(ctx, e.c, testPrefix, k, NewKeySet(e.key), "siem-a")
	if err != nil || n == 0 || len(refused) != 1 || refused[0] != "forged" {
		t.Errorf("resignOld = %d, %v, %v", n, refused, err)
	}
	// Signed already: nothing to do.
	if n, _, err := resignOld(ctx, e.c, testPrefix, k, NewKeySet(k, e.key), "siem-a"); err != nil || n != 0 {
		t.Errorf("again = %d, %v", n, err)
	}
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if strings.Contains(path, "_search") {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
	if _, _, err := resignOld(ctx, e.c, testPrefix, k, NewKeySet(e.key), "siem-a"); err == nil {
		t.Error("resignOld with the search failing")
	}
}
