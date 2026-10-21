// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"

	"github.com/jrsamsanchez/signalith/internal/security"
)

// SEC-01: on a cluster member (every server is one, the Docker quick
// start's too) the built-in admin's first password, changed from the
// account menu, no longer shows on the Security page.
func TestSecurityBuiltinPasswordChangedOnPage(t *testing.T) {
	file := filepath.Join(t.TempDir(), "admin-password")
	if err := os.WriteFile(file, []byte("s3cret-pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", file)
	dir := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "state"))
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte("ingest:\n  tokens: [tok-0123456789abcdef]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The server's config as the quick start's: the password from the file.
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c := newMemberCluster(t, func(s *Server) { s.Config = cfg })
	check := func() *security.Check {
		t.Helper()
		ch := c.a.srv.gatherSecurity(context.Background()).Find("accounts.builtin_password")
		if ch == nil {
			t.Fatal("no accounts.builtin_password")
		}
		return ch
	}
	if ch := check(); ch.State != security.Attention || !strings.Contains(ch.Line, "SIGNALITH_ADMIN_PASSWORD_FILE") {
		t.Fatalf("first password: %s %q", ch.State, ch.Line)
	}
	admin, _ := c.a.signIn("admin", "s3cret-pass")
	if code, out, _ := c.a.call("POST", "/api/me/password", `{"current_password":"s3cret-pass","new_password":"another-boss-pass"}`, admin, nil); code != http.StatusOK {
		t.Fatalf("change: %d %v", code, out)
	}
	// Tests hash with the lowest bcrypt cost, so the new password is
	// only "weaker hash" here; it is Good with the real cost.
	if ch := check(); strings.Contains(ch.Line, "SIGNALITH_ADMIN_PASSWORD_FILE") || !strings.Contains(ch.Line, "weaker hash") {
		t.Errorf("after the change: %s %q", ch.State, ch.Line)
	}
}
