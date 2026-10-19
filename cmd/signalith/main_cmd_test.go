package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runMain runs main with args as the command line and returns what it
// printed. Only commands that succeed return from main.
func runMain(t *testing.T, args ...string) string {
	t.Helper()
	saved := os.Args
	os.Args = append([]string{"signalith"}, args...)
	defer func() { os.Args = saved }()
	out, _ := capture(t, func() error { main(); return nil })
	return out
}

// main runs each command it names.
func TestMainRunsCommands(t *testing.T) {
	fos := newFakeOpenSearch(t)
	path := sampleConfig(t, fos.URL)
	t.Setenv("SIGNALITH_ARCHIVE_DIR", "")
	if out := runMain(t, "version"); out != "signalith "+version+"\n" {
		t.Errorf("version: %q", out)
	}
	t.Setenv("SIGNALITH_CONFIG", path)
	if out := runMain(t, "help"); !strings.Contains(out, "usage") && !strings.Contains(out, "Usage") || !strings.Contains(out, path) {
		t.Errorf("help:\n%s", out)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"validate", "-c", path}, path + " is valid."},
		{[]string{"settings", "list", "-c", path}, "settings"},
		{[]string{"query", "-c", path, "-explain", "datamodel=Authentication | head 1"}, "/_search"},
		{[]string{"ask", "-c", path, "failed logins"}, "Authentication"},
		{[]string{"content", "keygen"}, "Public key"},
		{[]string{"sample-data", "status", "-c", path}, "No sample data is loaded."},
		{[]string{"archive", "list", "-c", path, "-dir", t.TempDir()}, "No archived days."},
		{[]string{"tokens", "list", "-c", path}, "No agent tokens yet."},
		{[]string{"audit", "verify", "-c", path}, "No audit record was changed or removed."},
	} {
		if out := runMain(t, c.args...); !strings.Contains(out, c.want) {
			t.Errorf("%v lacks %q:\n%s", c.args, c.want, out)
		}
	}
	if defaultConfigPath() != path {
		t.Errorf("default config path %q, want SIGNALITH_CONFIG", defaultConfigPath())
	}
	t.Setenv("SIGNALITH_CONFIG", "")
	if p := defaultConfigPath(); !strings.HasSuffix(filepath.ToSlash(p), "signalith/signalith.yaml") && !strings.HasSuffix(p, `Signalith\signalith.yaml`) {
		t.Errorf("default config path %q", p)
	}
}
