// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// The built-in admin is turned off only while another enabled local admin
// of the provider exists, stays off in the file, and then no longer
// counts as the admin who is always there.
func TestBuiltinDisabled(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.BuiltinAdmin = "admin"
	if s.BuiltinDisabled() {
		t.Fatal("a new store has the built-in admin turned off")
	}
	if _, err := s.SetBuiltinDisabled(ctx, true); !errors.Is(err, ErrBuiltinLastAdmin) {
		t.Fatalf("turned off with no other admin: %v", err)
	}
	// Admins who cannot take over don't count: a tenant's, a disabled one,
	// and a directory admin, whose role the directory may change.
	ta := newUser("tad", Admin)
	ta.Tenant = "acme"
	if _, err := s.Create(ctx, ta); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, newUser("ann", Admin)); err != nil {
		t.Fatal(err)
	}
	off := true
	if _, err := s.Update(ctx, "ann", Change{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SeeDirectoryUser(ctx, DirectoryUser{Username: "dora", Role: Admin}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetBuiltinDisabled(ctx, true); !errors.Is(err, ErrBuiltinLastAdmin) {
		t.Fatalf("turned off with no admin to take over: %v", err)
	}

	if _, err := s.Create(ctx, newUser("kim", Admin)); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.SetBuiltinDisabled(ctx, true); err != nil || !changed {
		t.Fatalf("turn off = %v, %v", changed, err)
	}
	if changed, err := s.SetBuiltinDisabled(ctx, true); err != nil || changed {
		t.Errorf("turn off again = %v, %v; want no change", changed, err)
	}
	if !s.BuiltinDisabled() {
		t.Fatal("not turned off")
	}
	// The last enabled admin is now kim, who cannot be disabled, demoted
	// or deleted.
	viewer := Viewer
	if _, err := s.Update(ctx, "kim", Change{Disabled: &off}); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disable the last admin: %v", err)
	}
	if _, err := s.Update(ctx, "kim", Change{Role: &viewer}); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demote the last admin: %v", err)
	}
	if _, err := s.Delete(ctx, "kim"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("delete the last admin: %v", err)
	}

	// It stays off in the file, for this server and others.
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	again.BuiltinAdmin = "admin"
	if !again.BuiltinDisabled() {
		t.Error("turned off is not kept in the file")
	}
	if off, err := ReadFileBuiltinDisabled(path); err != nil || !off {
		t.Errorf("ReadFileBuiltinDisabled = %v, %v", off, err)
	}

	// signalith passwd turns it on in the file; the store sees it.
	if changed, err := SetFileBuiltinDisabled(path, false); err != nil || !changed {
		t.Fatalf("SetFileBuiltinDisabled = %v, %v", changed, err)
	}
	s.recheck = 0
	if s.BuiltinDisabled() {
		t.Error("turned on in the file, but the store still has it off")
	}
	// Turning it on needs no other admin.
	if _, err := s.Update(ctx, "kim", Change{Disabled: &off}); err != nil {
		t.Errorf("disable kim with the built-in admin on: %v", err)
	}
	if _, err := s.SetBuiltinDisabled(ctx, false); err != nil {
		t.Errorf("turn on: %v", err)
	}
}

// A store without a built-in admin has nothing to turn off.
func TestBuiltinDisabledNoBuiltin(t *testing.T) {
	s := NewMemory()
	if _, err := s.SetBuiltinDisabled(context.Background(), true); !errors.Is(err, ErrNoBuiltinOff) {
		t.Errorf("SetBuiltinDisabled = %v, want ErrNoBuiltinOff", err)
	}
}
