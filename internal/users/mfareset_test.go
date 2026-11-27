// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// signalith passwd -reset-mfa asks for the built-in admin's two-step
// sign-in to go at the next start; until then it stays, and the next
// server to start removes it, once.
func TestBuiltinMFAResetAtStart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.BuiltinAdmin = "admin"
	if _, err := s.Create(ctx, newUser("kim", Viewer)); err != nil {
		t.Fatal(err)
	}
	// Nothing to reset yet.
	if had, err := SetFileBuiltinMFAResetAtStart(path); err != nil || had {
		t.Fatalf("SetFileBuiltinMFAResetAtStart with none = %v, %v", had, err)
	}
	if err := s.changeMFA(ctx, "admin", func(*MFA) (*MFA, bool, error) {
		return &MFA{Secret: NewMFASecret(), Since: time.Now().UTC()}, false, nil
	}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if had, err := SetFileBuiltinMFAResetAtStart(path); err != nil || !had {
			t.Fatalf("SetFileBuiltinMFAResetAtStart = %v, %v", had, err)
		}
	}
	// The running server keeps it until a server starts.
	if !s.MFAOn("admin") {
		t.Error("two-step sign-in went before the start")
	}
	next, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	next.BuiltinAdmin = "admin"
	reset, err := next.StartBuiltinMFA(ctx)
	if err != nil || !reset {
		t.Fatalf("StartBuiltinMFA = %v, %v", reset, err)
	}
	if _, ok := next.MFA("admin"); ok {
		t.Error("two-step sign-in is still there after the start")
	}
	if _, ok := next.Get("kim"); !ok {
		t.Error("the other users were lost")
	}
	// A second start has nothing to reset.
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	again.BuiltinAdmin = "admin"
	if reset, err := again.StartBuiltinMFA(ctx); err != nil || reset {
		t.Errorf("second StartBuiltinMFA = %v, %v", reset, err)
	}
	// A store without a users file has nothing to do.
	if reset, err := NewMemory().StartBuiltinMFA(ctx); err != nil || reset {
		t.Errorf("StartBuiltinMFA in memory = %v, %v", reset, err)
	}
}
