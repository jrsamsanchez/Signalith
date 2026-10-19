package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agentd"
	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

func testPaths(t *testing.T) agentd.Paths {
	t.Helper()
	dir := t.TempDir()
	p := agentd.Paths{Conf: filepath.Join(dir, "conf"), State: filepath.Join(dir, "state"), Service: "signalith-agent-test"}
	for _, d := range []string{p.Conf, p.State} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func writeStatus(t *testing.T, p agentd.Paths, st agentproto.Status) {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.StatusFile(), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStatusNotReported(t *testing.T) {
	p := testPaths(t)
	var out bytes.Buffer
	err := status(p, &out)
	if err == nil || !strings.Contains(err.Error(), "has not reported yet") {
		t.Fatalf("status with no file: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("printed %q", out.String())
	}
}

func TestStatusBadJSON(t *testing.T) {
	p := testPaths(t)
	if err := os.WriteFile(p.StatusFile(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := status(p, io.Discard); err == nil {
		t.Fatal("bad status accepted")
	}
}

func TestStatusPrints(t *testing.T) {
	cases := []struct {
		name   string
		st     agentproto.Status
		health string
		want   []string
		absent []string
	}{
		{
			name:   "no configuration",
			st:     agentproto.Status{Version: "1.2.3", System: "Ubuntu 24.04", OS: "linux", Arch: "amd64", Started: "2026-01-02T03:04:05Z"},
			want:   []string{"Signalith Agent 1.2.3 on Ubuntu 24.04 (linux/amd64), started 2026-01-02T03:04:05Z", "configuration: none yet"},
			absent: []string{"health:"},
		},
		{
			name:   "configuration error wins",
			st:     agentproto.Status{Version: "1", Revision: "r7", ConfigError: "server said no"},
			want:   []string{"configuration: could not get a new one: server said no"},
			absent: []string{"configuration: r7"},
		},
		{
			name: "components and health",
			st: agentproto.Status{Version: "1", Revision: "r7", Components: []agentproto.Component{
				{Name: "fluentbit", Version: "3.1", State: agentproto.StateRunning, Since: "s1", Restarts: 2},
				{Name: "osquery", State: agentproto.StateFailed, Since: "s2", Error: "exited 1"},
			}},
			health: "config=ok\nfluentbit=ok\n",
			want: []string{"configuration: r7", "fluentbit (3.1): running since s1, 2 restarts",
				"osquery (version unknown): failed since s2, 0 restarts", "  exited 1", "health:\nconfig=ok\nfluentbit=ok\n"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := testPaths(t)
			writeStatus(t, p, c.st)
			if c.health != "" {
				if err := os.WriteFile(p.HealthFile(), []byte(c.health), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			if err := status(p, &out); err != nil {
				t.Fatal(err)
			}
			for _, w := range c.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("missing %q in\n%s", w, out.String())
				}
			}
			for _, a := range c.absent {
				if strings.Contains(out.String(), a) {
					t.Errorf("unexpected %q in\n%s", a, out.String())
				}
			}
		})
	}
}

func TestOsqueryFlagsWritesCheckedCopy(t *testing.T) {
	p := testPaths(t)
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	if err := os.WriteFile(in, []byte("# comment\n--utc\r\n\n--disable_extensions=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An old copy is replaced, not appended to.
	if err := os.WriteFile(out, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := osqueryFlags(p, in, out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), "--utc\n--disable_extensions=true\n"; got != want {
		t.Errorf("checked copy %q, want %q", got, want)
	}
}

func TestOsqueryFlagsErrors(t *testing.T) {
	p := testPaths(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := osqueryFlags(p, filepath.Join(dir, "missing"), out); !os.IsNotExist(err) {
		t.Errorf("missing flags file: %v", err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("#"), 64<<10+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := osqueryFlags(p, big, out); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("large flags file: %v", err)
	}
	noOff := filepath.Join(dir, "nooff")
	if err := os.WriteFile(noOff, []byte("--utc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := osqueryFlags(p, noOff, out); err == nil || !strings.Contains(err.Error(), "extensions off") {
		t.Errorf("extensions left on: %v", err)
	}
	// The output's folder does not exist: the copy cannot be made.
	ok := filepath.Join(dir, "ok")
	if err := os.WriteFile(ok, []byte("--disable_extensions=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := osqueryFlags(p, ok, filepath.Join(dir, "nodir", "out")); err == nil {
		t.Error("copy written into a missing folder")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("copy written for refused flags: %v", err)
	}
}

// TestCommandsNotInstalled runs the commands that read the system's own
// folders on a computer where the agent is not installed.
func TestCommandsNotInstalled(t *testing.T) {
	p := agentd.DefaultPaths()
	if _, err := os.Stat(p.Conf); err == nil {
		t.Skip("the agent is installed here")
	}
	if _, err := os.Stat(p.State); err == nil {
		t.Skip("the agent is installed here")
	}
	var out bytes.Buffer
	if err := run([]string{"status"}, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "has not reported yet") {
		t.Errorf("status: %v", err)
	}
	if err := run([]string{"run"}, &out, io.Discard); err == nil {
		t.Error("run started with no settings")
	}
	if out.Len() != 0 {
		t.Errorf("printed %q", out.String())
	}
}
