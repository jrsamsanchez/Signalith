// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

// With SignIns set, sign-ins go there instead of into the users.
func TestRecordSignInThroughSignIns(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	s.BuiltinAdmin = "admin"
	if _, err := s.Create(ctx, newUser("ann", Analyst)); err != nil {
		t.Fatal(err)
	}
	var got []string
	s.SignIns = func(_ context.Context, name string, builtin bool) {
		got = append(got, fmt.Sprintf("%s %v", name, builtin))
	}
	s.RecordSignIn(ctx, "ANN")
	s.RecordBuiltinSignIn(ctx)
	if len(got) != 2 || got[0] != "ann false" || got[1] != "admin true" {
		t.Errorf("sign-ins %v", got)
	}
	if u, ok := s.Get("ann"); !ok || u.LastSignIn != nil {
		t.Errorf("the user was written: %+v", u)
	}
}

func TestChangeBuiltinMFAInFile(t *testing.T) {
	ctx := context.Background()
	f := newFileBackend(filepath.Join(t.TempDir(), "users.json"))
	// No change: nothing written.
	if err := f.ChangeBuiltinMFA(ctx, "admin", func(cur *MFA) (*MFA, bool, error) { return cur, false, ErrNoChange }); err != nil {
		t.Errorf("no change: %v", err)
	}
	refused := errors.New("refused")
	if err := f.ChangeBuiltinMFA(ctx, "admin", func(cur *MFA) (*MFA, bool, error) { return nil, false, refused }); !errors.Is(err, refused) {
		t.Errorf("refused: %v", err)
	}
	if err := f.ChangeBuiltinMFA(ctx, "admin", func(*MFA) (*MFA, bool, error) {
		return &MFA{Secret: "JBSWY3DPEHPK3PXP"}, false, nil
	}); err != nil {
		t.Fatal(err)
	}
	// Another backend of the same file reads it back.
	again := newFileBackend(f.path)
	if _, err := again.reloadLocked(); err != nil {
		t.Fatal(err)
	}
	if again.builtinMFA == nil || again.builtinMFA.Secret == "" {
		t.Errorf("the built-in admin's two-step sign-in was not kept: %+v", again.builtinMFA)
	}
}
