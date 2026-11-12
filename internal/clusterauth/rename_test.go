// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// W23: signalith cluster apply renames the built-in admin. A crash after
// any step leaves a rename the same call finishes; the old name's
// sessions end on every server, its password carries over, and a user
// who has the new name already refuses it.
func TestRenameBuiltin(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	old := a.signIn("admin", false)
	if !b.valid(old) {
		t.Fatal("the built-in admin's session does not work on B")
	}
	a.addUser("ops", users.Analyst)
	b.cycle()
	if _, err := b.docs.RenameBuiltin(ctx, "test", "ops"); err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Fatalf("a rename to a user's name: %v", err)
	}

	crash := errors.New("crash")
	for stop := 1; stop <= 4; stop++ {
		renameStep = func(n int) error {
			if n == stop {
				return crash
			}
			return nil
		}
		if _, err := a.docs.RenameBuiltin(ctx, "test", "root"); !errors.Is(err, crash) {
			t.Fatalf("stop after step %d: %v", stop, err)
		}
		b.cycle()
		// The built-in admin signs in throughout, under one of its names.
		name, hash, ok := b.docs.Builtin()
		if !ok || hash != builtinHash() || name != "admin" && name != "root" {
			t.Fatalf("after step %d B sees the built-in admin %q %v", stop, name, ok)
		}
	}
	renameStep = nil
	t.Cleanup(func() { renameStep = nil })
	prev, err := a.docs.RenameBuiltin(ctx, "test", "root")
	if err != nil || prev != "admin" {
		t.Fatalf("resumed rename: %q %v", prev, err)
	}
	b.cycle()
	c, _ := b.docs.clusterBody()
	if c.Builtin != "root" || c.BuiltinPrev != "" {
		t.Fatalf("cluster document: builtin %q prev %q", c.Builtin, c.BuiltinPrev)
	}
	if _, _, ok := b.docs.Users().Get("admin"); ok {
		t.Error("the old name's document is still there")
	}
	name, hash, ok := b.docs.Builtin()
	if !ok || name != "root" || hash != builtinHash() {
		t.Fatalf("B's built-in admin %q %v", name, ok)
	}
	if b.valid(old) || a.valid(old) {
		t.Error("the old name's session still works")
	}
	if prev, err := a.docs.RenameBuiltin(ctx, "test", "root"); err != nil || prev != "" {
		t.Errorf("a rename to the same name: %q %v", prev, err)
	}
}

// AUTHRT-10: the built-in admin turned off under its old name after the
// copy and before the delete stays off under the new one.
func TestRenameBuiltinKeepsATurnOffDuringTheRename(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	a.addUser("kim", users.Admin)
	b.cycle()
	t.Cleanup(func() { renameStep = nil })
	renameStep = func(n int) error {
		if n != 3 {
			return nil
		}
		// Another server, still reading the old name's document, turns
		// the built-in admin off there.
		_, err := b.docs.Users().Mutate(ctx, "other", "admin", func(v *UserBody) error {
			v.Disabled = true
			v.SessionEpoch++
			return nil
		})
		return err
	}
	if _, err := a.docs.RenameBuiltin(ctx, "test", "root"); err != nil {
		t.Fatal(err)
	}
	renameStep = nil
	for _, s := range []*server{a, b} {
		s.cycle()
		after, _, ok := s.docs.BuiltinUser()
		if !ok || after.Username != "root" || !after.Disabled {
			t.Errorf("%s: built-in admin after the rename %+v %v, want root turned off", s.name, after, ok)
		}
		if _, _, ok := s.docs.Users().Get("admin"); ok {
			t.Errorf("%s: the old name's document is still there", s.name)
		}
	}
}

// AUTHRT-10: carrying over a change made to the old name's document
// during a rename takes only what changed there; a password set on the
// new name meanwhile is not put back to the old one.
func TestRenameBuiltinMergesOnlyTheOldDocumentsChanges(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	a.addUser("kim", users.Admin)
	b.cycle()
	t.Cleanup(func() { renameStep = nil })
	renameStep = func(n int) error {
		if n != 3 {
			return nil
		}
		// The new name's password changes on this server...
		if _, err := a.docs.Users().Mutate(ctx, "test", "root", func(v *UserBody) error {
			v.PasswordHash = "new-name-hash"
			v.MFA = &users.StoredMFA{}
			v.SessionEpoch++
			return nil
		}); err != nil {
			return err
		}
		// ...while another server turns the old name off and renames
		// its display name.
		_, err := b.docs.Users().Mutate(ctx, "other", "admin", func(v *UserBody) error {
			v.Disabled = true
			v.Name = "Old Admin"
			v.SessionEpoch++
			return nil
		})
		return err
	}
	if _, err := a.docs.RenameBuiltin(ctx, "test", "root"); err != nil {
		t.Fatal(err)
	}
	renameStep = nil
	for _, s := range []*server{a, b} {
		s.cycle()
		after, _, ok := s.docs.BuiltinUser()
		if !ok || after.Username != "root" {
			t.Fatalf("%s: built-in admin after the rename %+v %v", s.name, after, ok)
		}
		if after.PasswordHash != "new-name-hash" || after.MFA == nil {
			t.Errorf("%s: the new name's password or two-step sign-in was reverted: %q %v", s.name, after.PasswordHash, after.MFA)
		}
		if !after.Disabled || after.Name != "Old Admin" {
			t.Errorf("%s: the old name's changes were not carried over: disabled %v name %q", s.name, after.Disabled, after.Name)
		}
	}
}

func TestMergeChangedTakesOnlyChangedFields(t *testing.T) {
	base := UserBody{PasswordHash: "h0", Name: "A", SessionEpoch: 1}
	prev := base
	v := base
	v.PasswordHash, v.SessionEpoch = "h-new", 2
	if mergeChanged(&v, &base, &prev) {
		t.Error("an unchanged old document changed the new one")
	}
	prev.PasswordHash, prev.SessionEpoch = "h-old", 2
	if !mergeChanged(&v, &base, &prev) || v.PasswordHash != "h-old" || v.SessionEpoch <= 2 {
		t.Errorf("a password changed on the old name did not carry over: %+v", v)
	}
}

// A rename keeps everything that guards the built-in admin's sign-in: a
// built-in admin turned off stays off under the new name, and its
// two-step sign-in and passkeys go with it. A server watching sees the
// rename, and no password change or turning on.
func TestRenameBuiltinKeepsOffAndTwoStep(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	a.addUser("kim", users.Admin)
	const secret = "JBSWY3DPEHPK3PXP"
	if err := a.ub.ChangeBuiltinMFA(ctx, "admin", func(*users.MFA) (*users.MFA, bool, error) {
		return &users.MFA{Secret: secret, Recovery: []string{"r1", "r2"}, Since: time.Now().UTC(),
			Handle: []byte("handle"), Passkeys: []users.Passkey{{Name: "key one"}}}, false, nil
	}); err != nil {
		t.Fatal(err)
	}
	if changed, err := a.store.SetBuiltinDisabled(ctx, true); err != nil || !changed {
		t.Fatalf("turn off = %v, %v", changed, err)
	}
	if _, err := a.docs.Users().Mutate(ctx, "test", "admin", func(v *UserBody) error {
		v.MustChangePassword = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	before, _, _ := b.docs.BuiltinUser()
	var seen []BuiltinChange
	w := &BuiltinWatch{Docs: b.docs, Report: func(c BuiltinChange) { seen = append(seen, c) }}
	w.Check()

	if prev, err := a.docs.RenameBuiltin(ctx, "cli:root", "siemroot"); err != nil || prev != "admin" {
		t.Fatalf("rename: %q %v", prev, err)
	}
	a.cycle()
	b.cycle()
	w.Check()
	for _, s := range []*server{a, b} {
		after, _, ok := s.docs.BuiltinUser()
		if !ok || after.Username != "siemroot" {
			t.Fatalf("%s: built-in admin %+v %v", s.name, after, ok)
		}
		if !after.Disabled || !s.store.BuiltinDisabled() {
			t.Errorf("%s: the rename turned the built-in admin on again", s.name)
		}
		if after.PasswordHash != before.PasswordHash || !after.MustChangePassword {
			t.Errorf("%s: password hash or must-change flag not carried over", s.name)
		}
		if after.SessionEpoch <= before.SessionEpoch {
			t.Errorf("%s: session epoch %d, was %d", s.name, after.SessionEpoch, before.SessionEpoch)
		}
		m := s.ub.BuiltinMFA()
		if m == nil || m.Problem != "" || m.Secret != secret || len(m.Recovery) != 2 ||
			string(m.Handle) != "handle" || len(m.Passkeys) != 1 || m.Passkeys[0].Name != "key one" {
			t.Errorf("%s: two-step sign-in after the rename = %+v", s.name, m)
		}
	}
	if len(seen) != 1 || seen[0].What != BuiltinRenamed || seen[0].User != "siemroot" || seen[0].From != "admin" ||
		seen[0].By.User != "cli:root" || seen[0].By.Node != "siem-a" {
		t.Errorf("the watching server saw %+v, want one rename by cli:root on siem-a", seen)
	}
}

// A server watching the built-in admin sees a password set and the
// built-in admin turned on from another server's command line, with who
// did it.
func TestBuiltinWatchSeesPasswordAndOnAgain(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	a.addUser("kim", users.Admin)
	if changed, err := a.store.SetBuiltinDisabled(ctx, true); err != nil || !changed {
		t.Fatalf("turn off = %v, %v", changed, err)
	}
	b.cycle()
	var seen []BuiltinChange
	w := &BuiltinWatch{Docs: b.docs, Report: func(c BuiltinChange) { seen = append(seen, c) }}
	w.Check()
	w.Check()
	if len(seen) != 0 {
		t.Fatalf("nothing changed, saw %+v", seen)
	}
	if err := a.docs.SetBuiltinHash(ctx, "cli:root", "$2a$04$another"); err != nil {
		t.Fatal(err)
	}
	if on, err := a.ub.ChangeBuiltinDisabled(ctx, "cli:root", false, nil); err != nil || !on {
		t.Fatalf("turn on = %v, %v", on, err)
	}
	b.cycle()
	w.Check()
	if len(seen) != 2 || seen[0].What != BuiltinPassword || seen[1].What != BuiltinEnabled {
		t.Fatalf("saw %+v, want a password change and turned on", seen)
	}
	for _, c := range seen {
		if c.User != "admin" || c.By.User != "cli:root" || c.By.Node != "siem-a" {
			t.Errorf("%+v, want admin by cli:root on siem-a", c)
		}
	}
}
