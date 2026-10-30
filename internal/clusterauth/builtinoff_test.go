// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Turning the cluster's built-in admin off marks its document disabled
// and ends its sessions on every server; it needs another local admin,
// and turning it on again (signalith passwd) needs none.
func TestBuiltinTurnedOff(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	cookie := a.signIn("admin", false)
	if _, err := a.store.SetBuiltinDisabled(ctx, true); !errors.Is(err, users.ErrBuiltinLastAdmin) {
		t.Fatalf("turned off with no other admin: %v", err)
	}
	a.addUser("kim", users.Admin)
	if changed, err := a.store.SetBuiltinDisabled(ctx, true); err != nil || !changed {
		t.Fatalf("turn off = %v, %v", changed, err)
	}
	b.cycle()
	if !b.store.BuiltinDisabled() || !b.ub.BuiltinDisabled() {
		t.Error("B does not see the built-in admin turned off")
	}
	a.sessions.Cache = NewSessionCache()
	if a.valid(cookie) {
		t.Error("the built-in admin's session outlived turning it off")
	}
	if err := b.sessions.MayDegrade("admin", users.SourceBuiltin); !errors.Is(err, ErrDegraded) {
		t.Errorf("a turned-off built-in admin may sign in while OpenSearch is down: %v", err)
	}
	// kim is the last admin now.
	off := true
	if _, err := b.store.Update(ctx, "kim", users.Change{Disabled: &off}); !errors.Is(err, users.ErrLastAdmin) {
		t.Errorf("disable the last admin: %v", err)
	}
	// As signalith passwd does.
	if on, err := b.ub.ChangeBuiltinDisabled(ctx, "root", false, nil); err != nil || !on {
		t.Fatalf("turn on = %v, %v", on, err)
	}
	a.cycle()
	if a.store.BuiltinDisabled() {
		t.Error("A still has the built-in admin turned off")
	}
	if on, err := b.ub.ChangeBuiltinDisabled(ctx, "root", false, nil); err != nil || on {
		t.Errorf("turn on again = %v, %v; want no change", on, err)
	}
}

// Two servers each make a change the other's copy does not show yet: A
// turns the built-in admin off while B disables kim, the only other
// admin. Once the copies show both, the built-in admin is on again.
func TestBuiltinOnAgainAfterChangesAtOnce(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	a.addUser("kim", users.Admin)
	b.cycle()
	// B's change, as its copy allowed it: the built-in admin was on there.
	if _, err := b.ub.Change(ctx, "ann", "kim", "", func(r *users.Record) error { r.Disabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := a.store.SetBuiltinDisabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		a.cycle()
		b.cycle()
		if !a.ub.BuiltinDisabled() && !b.ub.BuiltinDisabled() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the built-in admin stayed off with no other admin")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Below shared.LevelBuiltinOff the backend refuses to turn it off, whoever
// asks.
func TestBuiltinOffNeedsTheLevel(t *testing.T) {
	_, a, _, _ := pair(t)
	ctx := context.Background()
	if _, err := a.rt.Cluster().Mutate(ctx, "test", func(c *shared.ClusterBody) error { c.Level = shared.LevelBuiltinOff - 1; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ub.ChangeBuiltinDisabled(ctx, "test", true, nil); !errors.Is(err, ErrBuiltinOffLevel) {
		t.Errorf("below the level: %v", err)
	}
}
