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
		"ReadWritePaths=/var/lib/signalith-opensearch/config /var/lib/signalith-opensearch/data /var/lib/signalith-opensearch/logs /var/lib/signalith-opensearch/tmp\n",
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
