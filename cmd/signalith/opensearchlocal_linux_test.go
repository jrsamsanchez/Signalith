// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/oslocal"
)

func TestOpenSearchUnit(t *testing.T) {
	l := oslocal.DefaultLayout()
	home := l.VersionHome(oslocal.Version)
	unit := openSearchUnit(l, home)
	for _, want := range []string{
		"User=signalith-opensearch\n",
		"WorkingDirectory=/opt/signalith-opensearch/" + oslocal.Version + "\n",
		"ExecStart=/opt/signalith-opensearch/" + oslocal.Version + "/bin/opensearch -q\n",
		"Environment=OPENSEARCH_PATH_CONF=/var/lib/signalith-opensearch/config\n",
		"Environment=OPENSEARCH_JAVA_HOME=/opt/signalith-opensearch/" + oslocal.Version + "/jdk\n",
		// Not its config: root's, which it may only read.
		"ReadWritePaths=/var/lib/signalith-opensearch/data /var/lib/signalith-opensearch/logs /var/lib/signalith-opensearch/tmp\n",
		"KillMode=mixed\n",
		"IPAddressDeny=any\n",
		"IPAddressAllow=localhost\n",
		"PrivateIPC=true\n",
		"InaccessiblePaths=-/var/lib/signalith-opensearch/ca -/var/lib/signalith-opensearch/download\n",
		"ProtectSystem=strict\n",
		"NoNewPrivileges=true\n",
		"CapabilityBoundingSet=\n",
		"Before=signalith.service\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit has no %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "SendSIGKILL=no") {
		t.Error("a stuck OpenSearch is never killed")
	}
	if l.Home != "/opt/signalith-opensearch" || l.Data != "/var/lib/signalith-opensearch" || l.Client != "/etc/signalith/opensearch" ||
		oslocal.ServiceName != "signalith-opensearch" {
		t.Errorf("layout %+v, service %s", l, oslocal.ServiceName)
	}
}

func TestOpenSearchPathsRefused(t *testing.T) {
	for _, p := range []string{"relative", "/with space", "/a%n", "/a/../etc", `/a"b`, "/a\nb"} {
		l := oslocal.Layout{Home: p, Data: "/var/lib/x", Client: "/etc/x"}
		if err := (linuxOpenSearch{}).prepare(l, ""); err == nil || !strings.Contains(err.Error(), "full path") {
			t.Errorf("%q: %v", p, err)
		}
	}
}

func TestOnlyRootChanges(t *testing.T) {
	if err := onlyRootChanges("/usr/bin"); err != nil && os.Geteuid() == 0 {
		t.Errorf("/usr/bin: %v", err)
	}
	// A folder of this user's (not root's when the tests run as a user),
	// or one anybody may change.
	dir := t.TempDir()
	os.Chmod(dir, 0o777)
	if err := onlyRootChanges(dir); err == nil {
		t.Errorf("%s: no error", dir)
	}
}

func TestRootTree(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, to own the files")
	}
	parent := filepath.Join("/root", "signalith-test-"+strings.ReplaceAll(t.Name(), "/", "-"))
	os.RemoveAll(parent)
	os.MkdirAll(filepath.Join(parent, "home", "bin"), 0o755)
	t.Cleanup(func() { os.RemoveAll(parent) })
	if err := onlyRootChanges(parent); err != nil {
		t.Skipf("the folders above %s are not only root's: %v", parent, err)
	}
	home := filepath.Join(parent, "home")
	os.WriteFile(filepath.Join(home, "bin", "opensearch"), []byte("run"), 0o755)
	os.Symlink("opensearch", filepath.Join(home, "bin", "link"))
	if err := rootTree(home); err != nil {
		t.Fatal(err)
	}
	// Any file deep in it that someone else may change is refused.
	lib := filepath.Join(home, "lib.jar")
	os.WriteFile(lib, []byte("x"), 0o644)
	os.Chmod(lib, 0o666)
	if err := rootTree(home); err == nil || !strings.Contains(err.Error(), "lib.jar") {
		t.Errorf("a file anyone may change: %v", err)
	}
	os.Chmod(lib, 0o644)
	os.Chown(lib, 1, 1)
	if err := rootTree(home); err == nil || !strings.Contains(err.Error(), "lib.jar") {
		t.Errorf("a file of another user's: %v", err)
	}
}

func TestShareConfig(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, to give the files to a group")
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "certs"), 0o700)
	os.WriteFile(filepath.Join(dir, "certs", "node-key.pem"), []byte("key"), 0o600)
	os.WriteFile(filepath.Join(dir, "opensearch.yml"), []byte("x"), 0o600)
	if err := shareConfig(dir, 4242); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{
		dir: 0o750, filepath.Join(dir, "certs"): 0o750,
		filepath.Join(dir, "certs", "node-key.pem"): 0o640, filepath.Join(dir, "opensearch.yml"): 0o640,
	} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		uid, gid, _ := ownerOf(fi)
		if fi.Mode().Perm() != want || uid != 0 || gid != 4242 {
			t.Errorf("%s: %s %d:%d", p, fi.Mode(), uid, gid)
		}
	}
	// A link the service planted is refused, and where it points is left
	// as it was.
	outside := filepath.Join(t.TempDir(), "shadow")
	os.WriteFile(outside, []byte("x"), 0o600)
	os.Symlink(outside, filepath.Join(dir, "certs", "planted"))
	if err := shareConfig(dir, 4242); err == nil || !strings.Contains(err.Error(), "planted") {
		t.Errorf("a link: %v", err)
	}
	if fi, _ := os.Stat(outside); fi.Mode().Perm() != 0o600 {
		t.Errorf("the file outside became %s", fi.Mode())
	}
}

func TestToolEnv(t *testing.T) {
	t.Setenv("JAVA_OPTS", "-javaagent:/tmp/x.jar")
	l := oslocal.DefaultLayout()
	env := strings.Join(toolEnv(l, l.VersionHome(oslocal.Version)), "\n")
	if strings.Contains(env, "javaagent") || !strings.Contains(env, "\nJAVA_OPTS=\n") ||
		!strings.Contains(env, "OPENSEARCH_PATH_CONF=/var/lib/signalith-opensearch/config") {
		t.Errorf("env:\n%s", env)
	}
}

func TestConnectSignalith(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "a-long-test-password")
	old, oldRestart := signalithConfigFile, restartSignalith
	t.Cleanup(func() { signalithConfigFile, restartSignalith = old, oldRestart })
	signalithConfigFile = cfg
	restarted := false
	restartSignalith = func() error { restarted = true; return nil }
	l := oslocal.Layout{Home: filepath.Join(dir, "os"), Data: filepath.Join(dir, "osdata"), Client: filepath.Join(dir, "client")}

	var out bytes.Buffer
	if err := connectSignalith(&out, l); err != nil || !strings.Contains(out.String(), "not installed from its packages") || restarted {
		t.Fatalf("no config: %v %q", err, out.String())
	}
	if err := os.WriteFile(cfg, []byte("opensearch:\n  url: http://127.0.0.1:9200\n  username: admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := oslocal.SaveState(l, oslocal.State{Version: oslocal.Version, Port: 9201}); err != nil {
		t.Fatal(err)
	}
	if err := oslocal.MakeCerts(l, time.Now()); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := connectSignalith(&out, l); err != nil {
		t.Fatal(err)
	}
	if !restarted || !strings.Contains(out.String(), "https://127.0.0.1:9201") {
		t.Errorf("restarted %v, out %q", restarted, out.String())
	}
	c, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.SettingsProblem() != "" {
		t.Fatal(c.SettingsProblem())
	}
	ca, cert, key := l.ClientFiles()
	if c.OpenSearch.URL != "https://127.0.0.1:9201" || c.OpenSearch.CAFile != ca || c.OpenSearch.CertFile != cert || c.OpenSearch.KeyFile != key ||
		c.OpenSearch.Username != "" {
		t.Errorf("opensearch settings %+v", c.OpenSearch)
	}
}
