// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

const goodPassword = "Plum-Orbit-Lantern-47"

func TestCreateAndUpdateChecks(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	if s.Path() != "" {
		t.Errorf("memory path = %q", s.Path())
	}
	if _, err := s.Create(ctx, NewUser{Username: "boss", Role: Admin, Password: goodPassword}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, NewUser{Username: "ann", Role: Analyst, Password: goodPassword}); err != nil {
		t.Fatal(err)
	}
	field := func(err error) string {
		var fe *FieldError
		if errors.As(err, &fe) {
			return fe.Field
		}
		return ""
	}
	for want, in := range map[string]NewUser{
		"tenant": {Username: "t1", Role: Viewer, Password: goodPassword, Tenant: "Not A Tenant!"},
		"name":   {Username: "longname", Role: Viewer, Password: goodPassword, Name: strings.Repeat("n", 101)},
		"role":   {Username: "norole", Role: "overlord", Password: goodPassword},
	} {
		if _, err := s.Create(ctx, in); field(err) != want {
			t.Errorf("%s: %v", want, err)
		}
	}
	if _, err := s.Create(ctx, NewUser{Username: "ctl", Role: Viewer, Password: goodPassword, Name: "a\x01b"}); field(err) != "name" ||
		!strings.Contains(err.Error(), "control characters") {
		t.Errorf("control name = %v", err)
	}
	if _, err := s.Create(ctx, NewUser{Username: "ANN", Role: Viewer, Password: goodPassword}); !errors.Is(err, ErrExists) || field(err) != "username" {
		t.Errorf("taken = %v", err)
	}

	bad, email, role := "a\nb", "not an email", Role("overlord")
	for want, ch := range map[string]Change{
		"name":  {Name: &bad},
		"email": {Email: &email},
		"role":  {Role: &role},
	} {
		if _, err := s.Update(ctx, "ann", ch); field(err) != want {
			t.Errorf("update %s: %v", want, err)
		}
	}

	if _, err := s.SetPassword(ctx, "nobody", goodPassword, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing user = %v", err)
	}
	if _, err := s.SetPassword(ctx, "ann", "short", false); field(err) != "password" {
		t.Errorf("weak password = %v", err)
	}
	before := s.PasswordVersion("ANN")
	if before == "" {
		t.Fatal("no password version")
	}
	if _, err := s.SetPassword(ctx, "ann", "Velvet-Harbor-Quartz-82", true); err != nil {
		t.Fatal(err)
	}
	if after := s.PasswordVersion("ann"); after == before || after == "" {
		t.Errorf("password version did not change: %q", after)
	}
	if u, _ := s.Get("ann"); !u.MustChangePassword {
		t.Errorf("must change not kept: %+v", u)
	}
}

func TestOpenedStorePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Path() != path {
		t.Errorf("path = %q", s.Path())
	}
}
