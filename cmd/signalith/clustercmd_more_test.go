// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/ospki"
)

// foundedCluster is a server whose cluster was founded with signalith
// cluster found on a fake OpenSearch, for the other cluster commands.
type foundedCluster struct {
	t     *testing.T
	fake  *ostest.Server
	dir   string
	path  string
	self  cluster.Identity
	state string
}

// run runs signalith cluster with args, input on its standard input, and
// returns what it printed.
func (fc *foundedCluster) run(input string, args ...string) (string, error) {
	fc.t.Helper()
	in, w, err := os.Pipe()
	if err != nil {
		fc.t.Fatal(err)
	}
	defer in.Close()
	w.WriteString(input)
	w.Close()
	var out, errOut bytes.Buffer
	err = runCluster(append(args, "-c", fc.path), in, &out, &errOut)
	return out.String() + errOut.String(), err
}

// newFoundedCluster founds a cluster of one server. With osCA, the fake
// OpenSearch speaks https, and opensearch.ca_file holds its certificate
// and osCA.
func newFoundedCluster(t *testing.T, osCA []byte) *foundedCluster {
	t.Helper()
	noServiceSettings(t)
	dir := t.TempDir()
	var fake *ostest.Server
	extra := ""
	if osCA == nil {
		fake = ostest.New(t)
	} else {
		var h http.Handler
		fake, h = ostest.NewHandler()
		fake.Server = httptest.NewTLSServer(h)
		t.Cleanup(fake.Close)
		caFile := filepath.Join(dir, "opensearch-ca.pem")
		own := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fake.Certificate().Raw})
		writeTestFile(t, caFile, string(own)+string(osCA))
		extra = "  ca_file: " + filepath.ToSlash(caFile) + "\n"
	}
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "a-test-admin-password")
	t.Setenv(clusterKeyFileEnv, "")
	for _, k := range []string{"SIGNALITH_OPENSEARCH_URL", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_SETTINGS_FILE", "SIGNALITH_MASTER_KEY", "SIGNALITH_MASTER_KEY_FILE"} {
		t.Setenv(k, "")
	}
	conf := "opensearch:\n  url: " + fake.URL + "\n  index_prefix: cc\n" + extra + "lookups:\n  dir: " + filepath.ToSlash(filepath.Join(dir, "lookups")) + "\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	old := cliWatch
	cliWatch = 10 * time.Millisecond
	t.Cleanup(func() { cliWatch = old })
	state := filepath.Join(dir, "state-a")
	fc := &foundedCluster{t: t, fake: fake, dir: dir, path: path, state: state, self: clusterServerDir(t, state, "siem-a")}
	if out, err := fc.run("", "found", "-name", "Plant"); err != nil || !strings.Contains(out, `Founded cluster "Plant"`) {
		t.Fatalf("found: %v\n%s", err, out)
	}
	return fc
}

func TestClusterCommandUsage(t *testing.T) {
	noServiceSettings(t)
	var out, errOut bytes.Buffer
	if err := runCluster(nil, os.Stdin, &out, &errOut); err == nil || !strings.Contains(err.Error(), "signalith cluster") {
		t.Errorf("no command: %v", err)
	}
	if err := runCluster([]string{"bogus"}, os.Stdin, &out, &errOut); err == nil || !strings.Contains(err.Error(), `unknown cluster command "bogus"`) {
		t.Errorf("bogus: %v", err)
	}
	if err := runCluster([]string{"status", "-c", filepath.Join(t.TempDir(), "missing.yaml")}, os.Stdin, &out, &errOut); err == nil {
		t.Error("status with no config file")
	}
	// A server that never started has no identity.
	dir := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "a-test-admin-password")
	t.Setenv("SIGNALITH_OPENSEARCH_URL", "")
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte("opensearch:\n  url: http://127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCluster([]string{"status", "-c", path}, os.Stdin, &out, &errOut); err == nil || !strings.Contains(err.Error(), "has no identity yet") {
		t.Errorf("status with no identity: %v", err)
	}
	clusterServerDir(t, filepath.Join(dir, "state"), "siem-x")
	if err := runCluster([]string{"status", "-c", path}, os.Stdin, &out, &errOut); err == nil || !strings.Contains(err.Error(), "OpenSearch is not reachable") {
		t.Errorf("status with no OpenSearch: %v", err)
	}
}

func TestClusterCommandArguments(t *testing.T) {
	fc := newFoundedCluster(t, nil)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"apply"}, "usage: signalith cluster apply"},
		{[]string{"import"}, "needs -from-cache"},
		{[]string{"import-key"}, "usage: signalith cluster import-key"},
		{[]string{"token", "extra"}, "usage: signalith cluster token"},
		{[]string{"approve", "a", "b"}, "usage: signalith cluster approve"},
		{[]string{"remove"}, "usage: signalith cluster remove"},
		{[]string{"opensearch-ca", "bogus"}, "usage: signalith cluster opensearch-ca"},
	} {
		if _, err := fc.run("", c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v", c.args, err)
		}
	}
}

func TestClusterOpenSearchCA(t *testing.T) {
	// OpenSearch's certificate authority, as opensearch-certs writes it.
	ca, err := ospki.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	caDir := t.TempDir()
	keyFile := filepath.Join(caDir, ospki.RootCAFile[:len(ospki.RootCAFile)-len(".pem")]+"-key.pem")
	writeTestFile(t, filepath.Join(caDir, ospki.RootCAFile), string(ca.CertPEM()))
	writeTestFile(t, keyFile, string(ca.KeyPEM()))
	fc := newFoundedCluster(t, ca.CertPEM())

	out, err := fc.run("", "opensearch-ca")
	if err != nil || !strings.Contains(out, "not kept by the cluster") || !strings.Contains(out, "SERVER") {
		t.Errorf("status before import: %v\n%s", err, out)
	}
	out, err = fc.run("", "opensearch-ca", "-json")
	if err != nil || !strings.Contains(out, `"ca": null`) {
		t.Errorf("status -json before import: %v\n%s", err, out)
	}
	if _, err := fc.run("", "opensearch-ca", "import", filepath.Join(caDir, "missing-key.pem")); !os.IsNotExist(err) {
		t.Errorf("import a missing key: %v", err)
	}
	if _, err := fc.run("", "opensearch-ca", "import", "-cert", filepath.Join(caDir, "missing.pem"), keyFile); err == nil || !strings.Contains(err.Error(), "-cert") {
		t.Errorf("import a missing certificate: %v", err)
	}
	other, err := ospki.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	otherDir := t.TempDir()
	writeTestFile(t, filepath.Join(otherDir, ospki.RootCAFile), string(other.CertPEM()))
	writeTestFile(t, filepath.Join(otherDir, "key.pem"), string(other.KeyPEM()))
	if _, err := fc.run("", "opensearch-ca", "import", "-cert", filepath.Join(otherDir, ospki.RootCAFile), filepath.Join(otherDir, "key.pem")); err == nil ||
		!strings.Contains(err.Error(), "not the one in opensearch.ca_file") {
		t.Errorf("import a CA OpenSearch does not use: %v", err)
	}
	// The key of another CA with this certificate.
	if _, err := fc.run("", "opensearch-ca", "import", "-cert", filepath.Join(caDir, ospki.RootCAFile), filepath.Join(otherDir, "key.pem")); err == nil {
		t.Error("a certificate was imported with another one's key")
	}

	out, err = fc.run("", "opensearch-ca", "import", keyFile)
	if err != nil || !strings.Contains(out, "The cluster keeps OpenSearch's certificate authority now") || !strings.Contains(out, keyFile) {
		t.Fatalf("import: %v\n%s", err, out)
	}
	out, err = fc.run("", "opensearch-ca")
	if err != nil || !strings.Contains(out, "kept by the cluster since ") || !strings.Contains(out, "Fingerprint:") {
		t.Errorf("status after import: %v\n%s", err, out)
	}
	out, err = fc.run("", "opensearch-ca", "-json")
	if err != nil || strings.Contains(out, "PRIVATE KEY") || !strings.Contains(out, `"servers"`) {
		t.Errorf("status -json after import: %v\n%s", err, out)
	}

	crl := filepath.Join(fc.dir, "crl.pem")
	if out, err := fc.run("", "opensearch-ca", "crl", "-o", crl); err != nil {
		t.Fatalf("crl: %v\n%s", err, out)
	}
	b, err := os.ReadFile(crl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ospki.ParseCRL(b, ca.Cert, time.Now()); err != nil {
		t.Errorf("the revocation list: %v\n%s", err, b)
	}

	if _, err := fc.run("", "opensearch-ca", "revoke", "siem-nobody"); err == nil || !strings.Contains(err.Error(), `no server "siem-nobody"`) {
		t.Errorf("revoke an unknown server: %v", err)
	}
	// Another server in the heartbeats, and this one.
	hb := cluster.Heartbeat{Kind: "node", NodeID: "n_other", Name: "siem-z", State: cluster.StateStopped, HeartbeatAt: time.Now().UTC()}
	fc.fake.Put("cc_runtime", "node:n_other", asMap(t, hb))
	if _, err := fc.run("", "opensearch-ca", "revoke", fc.self.NodeID); err == nil {
		t.Error("revoked this server")
	}
	// Not at a terminal, it is done only with -yes.
	if _, err := fc.run("y\n", "opensearch-ca", "revoke", "siem-z"); err == nil || !strings.Contains(err.Error(), "add -yes") {
		t.Errorf("revoke without -yes: %v", err)
	}
	out, err = fc.run("", "opensearch-ca", "revoke", "-yes", "siem-z")
	if err != nil || !strings.Contains(out, "Revoked 0 OpenSearch certificates of siem-z.") {
		t.Errorf("revoke: %v\n%s", err, out)
	}
}
