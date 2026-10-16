package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

func tokensConfig(t *testing.T) string {
	t.Helper()
	fake := ostest.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "a-test-admin-password")
	conf := "opensearch:\n  url: " + fake.URL + "\n  index_prefix: tt" +
		"\ningest:\n  tokens: [shared-token-0123456789abcdefghij]\nlookups:\n  dir: " + filepath.ToSlash(filepath.Join(dir, "lookups")) + "\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTokensCommand(t *testing.T) {
	path := tokensConfig(t)
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	run := func(args ...string) (string, string, error) {
		var out, errOut bytes.Buffer
		err := runTokens(append(args, "-c", path), devnull, &out, &errOut)
		return out.String(), errOut.String(), err
	}
	out, errOut, err := run("create", "-purpose", "linux", "Linux", "web", "servers")
	if err != nil {
		t.Fatalf("create: %v %s", err, errOut)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 || !agenttokens.IsToken(lines[0]) || !strings.Contains(errOut, `Created agent token "Linux web servers"`) || !strings.Contains(errOut, "only time it is shown") {
		t.Fatalf("create printed %q / %q", out, errOut)
	}
	secret := lines[0]
	out, _, err = run("list")
	m := regexp.MustCompile(`(?m)^([0-9a-f]{12})  Shared token ([0-9a-f]{6}) `).FindStringSubmatch(out)
	old := agenttokens.IDOf("shared-token-0123456789abcdefghij")
	if err != nil || !strings.Contains(out, "Linux web servers") || m == nil || m[1][:6] != m[2] ||
		strings.Contains(out, secret) || strings.Contains(out, "shared-token-0123") || strings.Contains(out, old) || strings.Contains(out, old[:6]) {
		t.Fatalf("list: %v\n%s", err, out)
	}
	// Not at a terminal, revoking needs -yes.
	if _, _, err := run("revoke", "Linux web servers"); err == nil || !strings.Contains(err.Error(), "-yes") {
		t.Fatalf("revoke without -yes: %v", err)
	}
	out, _, err = run("revoke", "-yes", "Linux web servers")
	if err != nil || !strings.Contains(out, `Revoked "Linux web servers"`) {
		t.Fatalf("revoke: %v %s", err, out)
	}
	if out, _, _ := run("list"); strings.Contains(out, "Linux web servers") {
		t.Errorf("revoked token listed without -all:\n%s", out)
	}
	if out, _, _ := run("list", "-all", "-json"); !strings.Contains(out, `"status": "revoked"`) || strings.Contains(out, secret) {
		t.Errorf("list -all -json:\n%s", out)
	}
	id := m[1]
	if out, _, err := run("legacy", "refuse", id); err != nil || !strings.Contains(out, "no longer accepted") {
		t.Errorf("legacy refuse: %v %s", err, out)
	}
	if out, _, err := run("legacy", "accept", id); err != nil || !strings.Contains(out, "accepted again") {
		t.Errorf("legacy accept: %v %s", err, out)
	}
	if _, _, err := run("create", "bad\tname"); err == nil {
		t.Error("bad name accepted")
	}
}
