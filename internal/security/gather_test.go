// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// The old example token is still accepted over plain HTTP only on a
// Docker quick start upgraded from a version whose agents send it, in a
// container, with HTTPS on and agents on plain HTTP allowed (see
// config.Config.OldToken and api.retiredTokenAccepted).
func TestPublicTokenAccepted(t *testing.T) {
	https := "server:\n  listen: 0.0.0.0:8080\n  tls:\n    mode: auto\n"
	allow := "server:\n  listen: 0.0.0.0:8080\n  tls:\n    mode: auto\n    plaintext_ingest: allow\n"
	off := "server:\n  listen: 0.0.0.0:8080\n  tls:\n    mode: off\n"
	upgraded := &config.DockerUpgrade{Upgraded: true, Decided: now}
	ended := &config.DockerUpgrade{Upgraded: true, Decided: now, Ended: now}
	started := &config.DockerUpgrade{Decided: now}
	for _, tc := range []struct {
		name      string
		config    string
		decision  *config.DockerUpgrade
		decided   bool
		container bool
		want      bool
	}{
		{"upgraded quick start", https, upgraded, true, true, true},
		{"upgraded, plain allowed", allow, upgraded, true, true, true},
		{"upgraded, plain refused", httpsAuto, upgraded, true, true, false},
		{"upgraded, ended", allow, ended, true, true, false},
		{"upgraded, HTTPS off", off, upgraded, true, true, false},
		{"quick start installed new, plain allowed", allow, started, true, true, false},
		{"quick start not decided yet", allow, nil, true, true, false},
		{"other container, plain allowed", allow, nil, false, true, false},
		{"upgraded, no container", allow, upgraded, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := loadConfig(t, tc.config)
			if tc.decided {
				c = c.WithDockerUpgrade(tc.decision)
			}
			f := NewFacts(Host{Config: c, GOOS: "linux", InContainer: tc.container, Docker: tc.container}, now, ServerInfo{})
			if f.PublicTokenAccepted != tc.want || f.Docker != tc.container {
				t.Errorf("%+v", f)
			}
		})
	}
}

// SIGNALITH_ADMIN_PASSWORD_FILE is the Docker quick start's first
// password in its volume; elsewhere it is a file someone made.
func TestAdminFactsFromFile(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	file := map[string]string{"SIGNALITH_ADMIN_PASSWORD_FILE": "/run/secrets/admin"}
	c := loadConfig(t, "")
	if a := adminFacts(Host{Config: c, Docker: true, InContainer: true, Getenv: env(file)}); !a.DockerFirst || a.FromFile {
		t.Errorf("docker: %+v", a)
	}
	if a := adminFacts(Host{Config: c, InContainer: true, Getenv: env(file)}); a.DockerFirst || !a.FromFile {
		t.Errorf("other container: %+v", a)
	}
	if a := adminFacts(Host{Config: c, Getenv: env(file)}); a.DockerFirst || !a.FromFile {
		t.Errorf("service: %+v", a)
	}
	// SIGNALITH_ADMIN_PASSWORD wins over the file.
	both := map[string]string{"SIGNALITH_ADMIN_PASSWORD_FILE": "/run/secrets/admin", "SIGNALITH_ADMIN_PASSWORD": "x"}
	if a := adminFacts(Host{Config: c, Getenv: env(both)}); !a.FromEnv || a.FromFile {
		t.Errorf("both: %+v", a)
	}
}

// Commands that change this server's own files name its signalith.yaml
// when it isn't where the command looks by itself, and only for its own
// system.
func TestConfigArg(t *testing.T) {
	f := goodFacts(t, "")
	p := f.Config.Path()
	want := " -c " + sh(p)
	if filepath.Separator != '/' {
		want = "" // a Windows path on a Linux server
	}
	if got := configArg(f, "linux"); got != want {
		t.Errorf("linux: %q", got)
	}
	if got := configArg(f, "windows"); got != "" {
		t.Errorf("windows command on a Linux server: %q", got)
	}
	f.InContainer = true
	if got := configArg(f, "linux"); got != "" {
		t.Errorf("container: %q", got)
	}
	f.InContainer = false
	f.Server.OS = "windows"
	if got := configArg(f, "linux"); got != "" {
		t.Errorf("linux command on a Windows server: %q", got)
	}
	for path, want := range map[string]string{
		"/etc/signalith/signalith.yaml":           "",
		"/srv/it's/signalith.yaml":                ` -c '/srv/it'\''s/signalith.yaml'`,
		`C:\ProgramData\Signalith\signalith.yaml`: "",
		`D:\Signalith\signalith.yaml`:             ` -c 'D:\Signalith\signalith.yaml'`,
	} {
		fam := "linux"
		f.Server.OS = "linux"
		if path[0] != '/' {
			fam, f.Server.OS = "windows", "windows"
		}
		if got := configArgFor(f, fam, path); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}

// Names a strict certificate authority wouldn't cover are this server's
// when they are private or lead to one of its addresses; others can't be
// told apart from a name someone made up.
func TestMarkOwn(t *testing.T) {
	own := []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7")}
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "siem.example.com":
			return []netip.Addr{netip.MustParseAddr("2001:db8::7")}, nil
		case "paypal.com":
			return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
		}
		return nil, errors.New("no such host")
	}
	names := []SeenName{
		{Name: "siem-1", CoveredStrict: true},
		{Name: "siem.example.com"},
		{Name: "nas.corp.local"},
		{Name: "192.168.1.20"},
		{Name: "203.0.113.7"},
		{Name: "[2001:db8::7]"},
		{Name: "paypal.com"},
		{Name: "made-up.example"},
		{Name: "198.51.100.9"},
	}
	markOwn(context.Background(), names, own, lookup)
	want := map[string]bool{"siem.example.com": true, "nas.corp.local": true, "192.168.1.20": true, "203.0.113.7": true, "[2001:db8::7]": true}
	for _, n := range names {
		if n.Own != want[n.Name] {
			t.Errorf("%s: own %v", n.Name, n.Own)
		}
	}
}

// SEC-01: on a server whose users are the cluster's, a change on the
// page goes to the shared user document and never to this server's
// files; the check reads the password in use there.
func TestAdminFactsSharedPassword(t *testing.T) {
	c0 := loadConfig(t, "")
	file := filepath.Join(t.TempDir(), "admin-password")
	if err := os.WriteFile(file, []byte("first-docker-pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", file)
	env := func(k string) string {
		if k == "SIGNALITH_ADMIN_PASSWORD_FILE" {
			return file
		}
		return ""
	}
	c, err := config.Load(c0.Path())
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.HashPassword("first-docker-pass")
	if err != nil {
		t.Fatal(err)
	}
	set := time.Date(2026, 10, 20, 15, 50, 0, 0, time.UTC)
	live := func(h string) func() (string, time.Time, bool) {
		return func() (string, time.Time, bool) { return h, set, true }
	}
	// Still the first password: hashed with another salt than this
	// process's, as at every start.
	a := adminFacts(Host{Config: c, Docker: true, InContainer: true, Getenv: env, Builtin: live(first)})
	if !a.DockerFirst || !a.Shared || a.SetAt != nil {
		t.Errorf("first password: %+v", a)
	}
	changed, err := config.HashPassword("a-password-of-its-own")
	if err != nil {
		t.Fatal(err)
	}
	a = adminFacts(Host{Config: c, Docker: true, InContainer: true, Getenv: env, Builtin: live(changed)})
	if a.DockerFirst || a.FromFile || a.FromEnv || a.Public || !a.Shared || a.SetAt == nil || !a.SetAt.Equal(set) {
		t.Errorf("changed on the page: %+v", a)
	}
	f := &Facts{Config: c, Admin: a, Users: UserFacts{BuiltinName: "signalithadmin"}}
	if ch := checkBuiltinPassword(f); ch.State != Good {
		t.Errorf("check after the change: %+v", ch)
	}
	// The file changed on disk since the start: the password this process
	// loaded still counts, so the first password still shows.
	if err := os.WriteFile(file, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if a := adminFacts(Host{Config: c, Docker: true, InContainer: true, Getenv: env, Builtin: live(first)}); !a.DockerFirst {
		t.Errorf("file rotated: %+v", a)
	}
	// A signalith.yaml hash that differs from the cluster's cannot tell.
	if a := adminFacts(Host{Config: c0, Builtin: live(changed)}); a.SetAt != nil || !a.Shared {
		t.Errorf("yaml: %+v", a)
	}
	// Not read yet (the shared settings cannot be used): as before.
	none := func() (string, time.Time, bool) { return "", time.Time{}, false }
	if a := adminFacts(Host{Config: c, Docker: true, InContainer: true, Getenv: env, Builtin: none}); !a.DockerFirst || a.Shared {
		t.Errorf("unread: %+v", a)
	}
	// The fix for the first password points at the page, with no restart.
	f.Admin = adminFacts(Host{Config: c, Docker: true, InContainer: true, Getenv: env, Builtin: live(first)})
	ch := checkBuiltinPassword(f)
	if ch.State != Attention || ch.Fix == nil || ch.Fix.Page == nil || ch.Fix.Page.ID != "change-password" {
		t.Fatalf("fix: %+v", ch)
	}
	for k, cmd := range ch.Fix.Commands {
		if strings.Contains(strings.ToLower(cmd), "restart") {
			t.Errorf("%s command restarts: %q", k, cmd)
		}
	}
}

// Where the shared password cannot be read (the CLI), the state
// folder's note that the Docker first password was replaced tells.
func TestAdminFactsFirstPasswordNoted(t *testing.T) {
	file := "/run/signalith/" + config.InitialPasswordFileName
	env := func(k string) string {
		if k == "SIGNALITH_ADMIN_PASSWORD_FILE" {
			return file
		}
		return ""
	}
	c := loadConfig(t, "")
	if a := adminFacts(Host{Config: c, Docker: true, InContainer: true, Getenv: env}); !a.DockerFirst {
		t.Fatalf("before: %+v", a)
	}
	at := time.Date(2026, 10, 20, 15, 50, 0, 0, time.UTC)
	if err := config.NoteFirstPasswordChanged(c.StateDir(), at); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(c.Path())
	if err != nil {
		t.Fatal(err)
	}
	a := adminFacts(Host{Config: c, Docker: true, InContainer: true, Getenv: env})
	if a.DockerFirst || a.FromFile || a.SetAt == nil || !a.SetAt.Equal(at) {
		t.Errorf("after: %+v", a)
	}
}
