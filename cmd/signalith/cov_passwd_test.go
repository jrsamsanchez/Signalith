// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// markMember gives the state folder of the config at path a copy of
// shared settings, as a server that was a member of a cluster has.
func markMember(t *testing.T, path string) string {
	t.Helper()
	state := config.StateDirFor(path)
	cache := shared.CachePath(state)
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	return state
}

// On a server that was a member of a cluster, passwd says which password
// it changed: the break-glass one with -local, else the file's, used
// until the server shares the cluster's users again.
func TestPasswdOnAFormerMember(t *testing.T) {
	passwdEnv(t)
	path := initForPasswd(t)
	state := markMember(t, path)

	t.Setenv("SIGNALITH_NEW_PASSWORD", "member-password-1")
	out, err := capture(t, func() error { return cmdPasswd([]string{"-local", "-c", path}) })
	if err != nil || !strings.Contains(out, "on this server only.") || !strings.Contains(out, "While this server shares the users of its cluster") {
		t.Errorf("-local: %v\n%s", err, out)
	}
	if _, err := os.Stat(config.AdminLocalHashFileIn(state)); err != nil {
		t.Errorf("no break-glass hash: %v", err)
	}

	t.Setenv("SIGNALITH_NEW_PASSWORD", "member-password-2")
	out, err = capture(t, func() error { return cmdPasswd([]string{"-c", path}) })
	if err != nil || !strings.Contains(out, "in this server's files only") || !strings.Contains(out, "auth.admin_password_hash in signalith.yaml changed") {
		t.Errorf("in the file: %v\n%s", err, out)
	}
	c, err := config.Load(path)
	if err != nil || !c.CheckPassword(config.DefaultAdminUser, "member-password-2") {
		t.Errorf("the new password does not work: %v", err)
	}

	// With a hash file in the state folder, that file is changed.
	if err := writeAdminHash(config.AdminHashFileIn(state), c.Auth.AdminPasswordHash); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_NEW_PASSWORD", "member-password-3")
	out, err = capture(t, func() error { return cmdPasswd([]string{"-c", path}) })
	if err != nil || !strings.Contains(out, "replaces the first password") || !strings.Contains(out, "the password is used only while it keeps its users in its own files") {
		t.Errorf("hash file: %v\n%s", err, out)
	}
}
