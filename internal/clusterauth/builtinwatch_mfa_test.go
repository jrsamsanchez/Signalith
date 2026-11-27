// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterauth

import (
	"context"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// signalith passwd -reset-mfa removes the built-in admin's two-step
// sign-in from the shared settings; the watch reports it, for the audit
// log.
func TestBuiltinWatchSeesMFAReset(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	if err := a.ub.ChangeBuiltinMFA(ctx, "admin", func(*users.MFA) (*users.MFA, bool, error) {
		return &users.MFA{Secret: users.NewMFASecret(), Since: time.Now().UTC()}, false, nil
	}); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	var seen []BuiltinChange
	w := &BuiltinWatch{Docs: b.docs, Report: func(c BuiltinChange) { seen = append(seen, c) }}
	w.Check()
	if err := a.ub.ChangeBuiltinMFA(ctx, "cli:root", func(*users.MFA) (*users.MFA, bool, error) { return nil, false, nil }); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	w.Check()
	if len(seen) != 1 || seen[0].What != BuiltinMFAReset || seen[0].User != "admin" || seen[0].By.User != "cli:root" {
		t.Fatalf("saw %+v, want the two-step sign-in reset by cli:root", seen)
	}
	if b.ub.BuiltinMFA() != nil {
		t.Error("the other server still sees two-step sign-in")
	}
}
