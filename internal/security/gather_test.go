package security

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

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
