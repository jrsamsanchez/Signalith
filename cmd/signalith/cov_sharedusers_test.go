// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Only the sessions of users this server has as they are are carried
// into the shared users.
func TestCarriedSessions(t *testing.T) {
	ctx := context.Background()
	people, err := users.Open(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := people.Create(ctx, users.NewUser{Username: "ann", Role: users.Analyst, Password: "a-long-password-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := people.Create(ctx, users.NewUser{Username: "bob", Role: users.Analyst, Password: "a-long-password-2"}); err != nil {
		t.Fatal(err)
	}
	off := true
	if _, err := people.Update(ctx, "bob", users.Change{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	c := &config.Config{}
	c.Auth.AdminUser = "admin"
	c.Auth.AdminPasswordHash = "$2a$10$adminhash"
	stamp := api.PasswordStamp(people.PasswordVersion("ann"))
	held := func(user, method, version string) auth.Held {
		return auth.Held{Session: auth.Session{User: user, Method: method, Version: version}}
	}
	in := []auth.Held{
		held("ADMIN", users.SourceBuiltin, ""),        // kept: the built-in admin
		held("root", users.SourceBuiltin, ""),         // another name: dropped
		held("ann", users.SourceLocal, stamp),         // kept
		held("ann", users.SourceLocal, "old-version"), // an older password: dropped
		held("ann", users.SourceDirectory, ""),        // another source: dropped
		held("bob", users.SourceLocal, ""),            // disabled: dropped
		held("carl", users.SourceLocal, ""),           // unknown: dropped
	}
	got := carried(in, people, c)
	if len(got) != 2 || got[0].Role != users.Admin || got[0].PasswordHash != c.Auth.AdminPasswordHash || got[1].User != "ann" || got[1].Role != users.Analyst {
		t.Errorf("carried %+v", got)
	}
	// Without a users file only the built-in admin is carried.
	if got := carried(in, nil, c); len(got) != 1 {
		t.Errorf("without users: %+v", got)
	}
}

// isFirstPassword knows the first password from the file the packages
// keep it in.
func TestIsFirstPasswordFromFile(t *testing.T) {
	path := sampleConfig(t, "http://127.0.0.1:1")
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", "")
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := config.HashPassword("the-first-password")
	if isFirstPassword(c, h) {
		t.Error("no file, yet first")
	}
	file := filepath.Join(filepath.Dir(path), initialPasswordFile)
	if err := os.WriteFile(file, []byte("the-first-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", file)
	if !isFirstPassword(c, h) {
		t.Error("the first password was not known")
	}
	other, _ := config.HashPassword("another-password")
	if isFirstPassword(c, other) {
		t.Error("another password taken for the first")
	}
}

// signalith passwd changes only this server's files when the shared users
// cannot be used, and says why.
func TestPasswdSharedFallsBack(t *testing.T) {
	path := sampleConfig(t, "http://"+freeAddr(t))
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	// Never a member: nothing is said.
	var ok bool
	var err error
	out := captureStdout(t, func() { ok, err = passwdShared(path, state, "$2a$10$x") })
	if ok || err != nil || out != "" {
		t.Errorf("never a member: %v %v %q", ok, err, out)
	}
	cache := shared.CachePath(state)
	os.MkdirAll(filepath.Dir(cache), 0o700)
	if err := os.WriteFile(cache, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, path, want string
	}{
		{"no config", filepath.Join(t.TempDir(), "none.yaml"), "The configuration could not be read"},
		{"no identity", path, "This server has no identity yet"},
	} {
		out := captureStdout(t, func() { ok, err = passwdShared(c.path, state, "$2a$10$x") })
		if ok || err != nil || !strings.Contains(out, c.want) || !strings.Contains(out, "in this server's files only") {
			t.Errorf("%s: %v %v %q", c.name, ok, err, out)
		}
	}
}
