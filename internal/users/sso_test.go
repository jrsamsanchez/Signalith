// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A user whose name or email the Users page would not take (as a provider
// or an older version recorded it) can still be disabled.
func TestDisableUserWithUncheckedNameAndEmail(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	now := time.Now()
	if _, err := s.b.Create(ctx, "", Record{User: User{Username: "odd", Source: SourceSSO, Name: strings.Repeat("x", 150),
		Email: "Odd <odd@example.com>", Role: Analyst, Subject: SSOSubject("https://idp.example.com", "1"), Created: now, Updated: now}, Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	off := true
	if u, err := s.Update(ctx, "odd", Change{Disabled: &off}); err != nil || !u.Disabled {
		t.Fatalf("disable = %+v, %v", u, err)
	}
}

func TestSSOValuesAreCleaned(t *testing.T) {
	s := NewMemory()
	u, err := s.SeeSSOUser(context.Background(), SSOUser{Username: "odd", Name: strings.Repeat("Ö", 120) + "\n", Email: "not an address",
		Role: Viewer, Subject: SSOSubject("https://idp.example.com", "1")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(u.Name)) != 100 || u.Email != "" {
		t.Errorf("name %d characters, email %q", len([]rune(u.Name)), u.Email)
	}
}
