package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ospki"
	"gopkg.in/yaml.v3"
)

// caVolumes are bootstrap-docker's folders, the way the Docker quick start
// mounts them.
func caVolumes(t *testing.T) bootstrapOptions {
	t.Helper()
	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = 3072 })
	root := t.TempDir()
	o := bootstrapOptions{
		OSDir: filepath.Join(root, "opensearch-certs"), SigDir: filepath.Join(root, "signalith-secrets"),
		CADir: filepath.Join(root, "opensearch-ca"), StateDir: filepath.Join(root, "signalith-data"),
		LoadedDir: filepath.Join(root, "opensearch-security-loaded"),
	}
	return o
}

func mustBootstrap(t *testing.T, o bootstrapOptions) string {
	t.Helper()
	out, err := bootstrapWith(t, o)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return out
}

func certIn(t *testing.T, dir, name string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s: no PEM", name)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestBootstrapKeepsCA follows the CA through the quick start's life: made
// once with its key in its own folder, certificates renewed under it one
// by one, and a new CA only when asked for.
func TestBootstrapKeepsCA(t *testing.T) {
	o := caVolumes(t)
	out := mustBootstrap(t, o)
	if !strings.Contains(out, "OpenSearch certificates: made, valid until") {
		t.Errorf("first run:\n%s", out)
	}
	// The key is only in the CA's folder, which is root's.
	if got := keysOf(readAll(t, o.CADir)); !slices.Equal(got, []string{"root-ca-key.pem", "root-ca.pem"}) {
		t.Errorf("CA folder %v", got)
	}
	checkModes(t, o.CADir, 0, 0o700)
	checkModes(t, filepath.Join(o.CADir, "root-ca-key.pem"), 0, 0o600)
	osFiles, sigFiles := readAll(t, o.OSDir), readAll(t, o.SigDir)
	for name := range mergeMaps(osFiles, sigFiles) {
		if name == "root-ca-key.pem" || name == "opensearch-ca-key.pem" {
			t.Errorf("the CA's key is in %s", name)
		}
	}
	caPEM := readAll(t, o.CADir)["root-ca.pem"]
	if osFiles["root-ca.pem"] != caPEM || sigFiles["opensearch-ca.pem"] != caPEM {
		t.Error("the certificates are not from the kept CA")
	}

	// Again: nothing changes.
	out = mustBootstrap(t, o)
	if !strings.Contains(out, "OpenSearch certificates: kept.") || !mapsEqual(readAll(t, o.OSDir), osFiles) || !mapsEqual(readAll(t, o.SigDir), sigFiles) {
		t.Errorf("second run changed files:\n%s", out)
	}

	// A lost client certificate: only it is made again, under the same CA.
	os.Remove(filepath.Join(o.SigDir, "opensearch-client.pem"))
	out = mustBootstrap(t, o)
	if !strings.Contains(out, "made a new opensearch-client.pem, since opensearch-client.pem is missing") || strings.Count(out, "made a new") != 1 {
		t.Errorf("after a lost client certificate:\n%s", out)
	}
	sigNew := readAll(t, o.SigDir)
	if !mapsEqual(readAll(t, o.OSDir), osFiles) || sigNew["opensearch-ca.pem"] != caPEM || sigNew["opensearch-client-key.pem"] == sigFiles["opensearch-client-key.pem"] {
		t.Error("more than the client certificate changed, or it did not")
	}
	if err := ospki.Check(o.OSDir, o.SigDir, "", time.Now(), renewWithin); err != nil {
		t.Error(err)
	}

	// Lost CA copies are put back from the kept CA.
	os.Remove(filepath.Join(o.OSDir, "root-ca.pem"))
	os.Remove(filepath.Join(o.SigDir, "opensearch-ca.pem"))
	out = mustBootstrap(t, o)
	if readAll(t, o.OSDir)["root-ca.pem"] != caPEM || readAll(t, o.SigDir)["opensearch-ca.pem"] != caPEM || strings.Contains(out, "made a new") {
		t.Errorf("CA copies:\n%s", out)
	}

	// A CA close to expiry is never replaced by itself.
	later := time.Now().Add(ospki.Validity - 10*24*time.Hour)
	osBefore := readAll(t, o.OSDir)
	o2 := o
	o2.Now = later
	if out, err := bootstrapWith(t, o2); err == nil || !strings.Contains(err.Error(), "-new-ca") || !strings.Contains(err.Error(), "expires") {
		t.Errorf("an expiring CA: %v\n%s", err, out)
	}
	if !mapsEqual(readAll(t, o.OSDir), osBefore) || readAll(t, o.CADir)["root-ca.pem"] != caPEM {
		t.Error("an expiring CA changed files")
	}

	// -new-ca replaces the CA and everything it issued; the password and
	// token stay.
	o2 = o
	o2.NewCA = true
	out = mustBootstrap(t, o2)
	newCA := readAll(t, o.CADir)["root-ca.pem"]
	if newCA == caPEM || !strings.Contains(out, "OpenSearch CA: made a new one") || !strings.Contains(out, "-export-ca-key") {
		t.Errorf("-new-ca:\n%s", out)
	}
	if err := ospki.Check(o.OSDir, o.SigDir, "", time.Now(), renewWithin); err != nil {
		t.Error(err)
	}
	if s := readAll(t, o.SigDir); s["opensearch-ca.pem"] != newCA || s["initial-admin-password"] != sigFiles["initial-admin-password"] || s["ingest-token"] != sigFiles["ingest-token"] {
		t.Error("-new-ca: wrong CA for Signalith, or the password or token changed")
	}
}

// TestBootstrapRenewsLeavesUnderCA renews a certificate that is about to
// expire, under the same CA.
func TestBootstrapRenewsLeavesUnderCA(t *testing.T) {
	o := caVolumes(t)
	// A CA from long ago whose admin certificate is close to expiry: issue
	// it again with a short life.
	mustBootstrap(t, o)
	ca, err := ospki.LoadCA(o.CADir)
	if err != nil {
		t.Fatal(err)
	}
	short, err := ospki.IssueClient(ca, ospki.AdminName, time.Now(), 10*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(o.OSDir, "admin.pem"), short.CertPEM(), 0o600)
	os.WriteFile(filepath.Join(o.OSDir, "admin-key.pem"), short.KeyPEM(), 0o600)
	out := mustBootstrap(t, o)
	if !strings.Contains(out, "made a new admin.pem, since admin.pem expires on") || strings.Count(out, "made a new") != 1 {
		t.Errorf("renewal:\n%s", out)
	}
	if c := certIn(t, o.OSDir, "admin.pem"); c.CheckSignatureFrom(ca.Cert) != nil || c.NotAfter.Before(time.Now().Add(365*24*time.Hour)) {
		t.Errorf("renewed admin certificate: until %v", c.NotAfter)
	}
}

// TestBootstrapLegacyCA: an install from before the CA's key was kept
// keeps its certificates while they are good, says how to get a CA with a
// key, and never makes a new CA by itself.
func TestBootstrapLegacyCA(t *testing.T) {
	o := caVolumes(t)
	set, err := ospki.New(ospki.Options{})
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(o.OSDir, 0o700)
	os.MkdirAll(o.SigDir, 0o700)
	writeFiles(o.OSDir, set.OpenSearchFiles())
	writeFiles(o.SigDir, set.SignalithFiles())
	before := readAll(t, o.OSDir)
	out := mustBootstrap(t, o)
	if !strings.Contains(out, "OpenSearch certificates: kept.") || !strings.Contains(out, "key was not kept by older versions") || !strings.Contains(out, "-new-ca") {
		t.Errorf("legacy set:\n%s", out)
	}
	if !mapsEqual(readAll(t, o.OSDir), before) || len(readAll(t, o.CADir)) != 0 {
		t.Error("a legacy set was changed")
	}
	// A certificate that needs renewing: refused, with what to run.
	os.Remove(filepath.Join(o.SigDir, "opensearch-client.pem"))
	if out, err := bootstrapWith(t, o); err == nil || !strings.Contains(err.Error(), "-new-ca") || !strings.Contains(err.Error(), "opensearch-client.pem") {
		t.Errorf("legacy renewal: %v\n%s", err, out)
	}
	if readAll(t, o.OSDir)["root-ca.pem"] != before["root-ca.pem"] {
		t.Error("a new CA was made")
	}
	// Exporting needs a key.
	o2 := o
	o2.ExportCAKey = true
	if _, err := bootstrapWith(t, o2); err == nil || !strings.Contains(err.Error(), "-new-ca") {
		t.Errorf("legacy export: %v", err)
	}
	// -new-ca starts again with a kept CA.
	o2 = o
	o2.NewCA = true
	mustBootstrap(t, o2)
	if _, err := ospki.LoadCA(o.CADir); err != nil {
		t.Error(err)
	}
	if err := ospki.Check(o.OSDir, o.SigDir, "", time.Now(), renewWithin); err != nil {
		t.Error(err)
	}
}

// TestBootstrapNamesAndNodes adds names to the node certificate and more
// node certificates, all under the same CA, and keeps them on renewal.
func TestBootstrapNamesAndNodes(t *testing.T) {
	o := caVolumes(t)
	mustBootstrap(t, o)
	ca := certIn(t, o.CADir, "root-ca.pem")
	o2 := o
	o2.Names = []string{"search.example.com", "192.0.2.9"}
	out := mustBootstrap(t, o2)
	if !strings.Contains(out, "made a new node.pem, since it does not cover search.example.com, 192.0.2.9 yet") {
		t.Errorf("-opensearch-name:\n%s", out)
	}
	node := certIn(t, o.OSDir, "node.pem")
	if !slices.Equal(node.DNSNames, []string{"opensearch", "localhost", "search.example.com"}) || len(node.IPAddresses) != 2 || node.CheckSignatureFrom(ca) != nil {
		t.Errorf("node names %v %v", node.DNSNames, node.IPAddresses)
	}
	// Asked again: kept. Renewed without the flag: the names stay.
	if out := mustBootstrap(t, o2); !strings.Contains(out, "kept.") {
		t.Errorf("same names again:\n%s", out)
	}
	os.Remove(filepath.Join(o.OSDir, "node-key.pem"))
	mustBootstrap(t, o)
	if node := certIn(t, o.OSDir, "node.pem"); !slices.Contains(node.DNSNames, "search.example.com") || len(node.IPAddresses) != 2 {
		t.Errorf("renewal lost names: %v %v", node.DNSNames, node.IPAddresses)
	}

	o2 = o
	o2.Nodes = 3
	out = mustBootstrap(t, o2)
	for i, cn := range map[int]string{2: "opensearch-2", 3: "opensearch-3"} {
		cert, key := ospki.NodeFileNames(i)
		if err := ospki.CheckPair(o.OSDir, cert, key, cn, ca, time.Now(), 0); err != nil {
			t.Errorf("node %d: %v", i, err)
		}
		checkModes(t, filepath.Join(o.OSDir, key), 1000, 0o600)
	}
	if !strings.Contains(out, "made a new node-3.pem") {
		t.Errorf("-nodes 3:\n%s", out)
	}
	// Fewer nodes later: the others are kept, and renewed when needed.
	os.Remove(filepath.Join(o.OSDir, "node-3-key.pem"))
	out = mustBootstrap(t, o)
	if !strings.Contains(out, "made a new node-3.pem, since node-3-key.pem is missing") {
		t.Errorf("node 3 renewal:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(o.OSDir, "node-2.pem")); err != nil {
		t.Error(err)
	}

	o2 = o
	o2.Names = []string{"bad/name"}
	if _, err := bootstrapWith(t, o2); err == nil {
		t.Error("a bad name was accepted")
	}
}

// TestBootstrapExportCAKey hands the CA to Signalith's state folder.
func TestBootstrapExportCAKey(t *testing.T) {
	o := caVolumes(t)
	o.ExportCAKey = true
	// Not before Signalith has used its state folder.
	if _, err := bootstrapWith(t, o); err == nil || !strings.Contains(err.Error(), "has not started yet") {
		t.Errorf("empty state folder: %v", err)
	}
	if entries, _ := os.ReadDir(o.StateDir); len(entries) != 0 {
		t.Error("the empty state folder was written to")
	}
	os.MkdirAll(filepath.Join(o.StateDir, "keys"), 0o700)
	out := mustBootstrap(t, o)
	dir := filepath.Join(o.StateDir, ospki.ImportDir)
	if !strings.Contains(out, "Handed the OpenSearch CA") || strings.Contains(out, "Ready.") {
		t.Errorf("export:\n%s", out)
	}
	files := readAll(t, dir)
	if got := keysOf(files); !slices.Equal(got, []string{ospki.ExportCAKeyFile, ospki.ExportCAFile}) {
		t.Fatalf("import files %v", got)
	}
	checkModes(t, dir, 65532, 0o700)
	for name := range files {
		checkModes(t, filepath.Join(dir, name), 65532, 0o600)
	}
	ca, err := ospki.LoadCA(o.CADir)
	if err != nil {
		t.Fatal(err)
	}
	if files[ospki.ExportCAFile] != string(ca.CertPEM()) || files[ospki.ExportCAKeyFile] != string(ca.KeyPEM()) {
		t.Error("the handed-over CA is not the kept one")
	}
	// Files waiting already are left alone.
	os.WriteFile(filepath.Join(dir, ospki.ExportCAFile), []byte("waiting"), 0o600)
	if out := mustBootstrap(t, o); !strings.Contains(out, "already waiting") || readAll(t, dir)[ospki.ExportCAFile] != "waiting" {
		t.Errorf("second export:\n%s", out)
	}
}

func TestBootstrapApplySecurity(t *testing.T) {
	o := caVolumes(t)
	os.MkdirAll(o.LoadedDir, 0o700)
	os.WriteFile(filepath.Join(o.LoadedDir, loadedFingerprint), []byte("abc\n"), 0o600)
	o.ApplySecurity = true
	out := mustBootstrap(t, o)
	if _, err := os.Stat(filepath.Join(o.LoadedDir, loadedFingerprint)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("fingerprint still there: %v", err)
	}
	if !strings.Contains(out, "Now run: docker compose -f deploy/docker/docker-compose.yml up -d") {
		t.Errorf("output:\n%s", out)
	}
	// Again, with nothing to remove.
	mustBootstrap(t, o)
}

// Flags that need the CA's folder say so when a compose file from before
// does not give it.
func TestBootstrapWithoutCADir(t *testing.T) {
	o := caVolumes(t)
	o.CADir = ""
	out := mustBootstrap(t, o)
	if !strings.Contains(out, "OpenSearch certificates: made") {
		t.Errorf("output:\n%s", out)
	}
	o.ExportCAKey = true
	if _, err := bootstrapWith(t, o); err == nil || !strings.Contains(err.Error(), "-ca-dir") {
		t.Errorf("export without -ca-dir: %v", err)
	}
}

// TestOpenSearchCertsUnderCA makes a second node's certificates with the
// first run's CA.
func TestOpenSearchCertsUnderCA(t *testing.T) {
	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = 3072 })
	root := t.TempDir()
	first, second := filepath.Join(root, "first"), filepath.Join(root, "second")
	var msg bytes.Buffer
	if err := writeOpenSearchCerts(&msg, osCertsOptions{Out: first, Node: "search1", Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.String(), "never copy this folder to OpenSearch") || !strings.Contains(msg.String(), "-ca-dir") {
		t.Errorf("first run:\n%s", msg.String())
	}
	for _, caDir := range []string{first, filepath.Join(first, "ca")} {
		out := filepath.Join(second, filepath.Base(caDir))
		msg.Reset()
		if err := writeOpenSearchCerts(&msg, osCertsOptions{Out: out, Node: "search2", Names: []string{"192.0.2.8"}, Peers: []string{"search1", "search3"}, CADir: caDir, Now: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(out, "ca")); err == nil {
			t.Error("a second run wrote the CA again")
		}
		if _, err := os.Stat(filepath.Join(out, "opensearch", "certs", "admin.pem")); err == nil {
			t.Error("a second run made an admin certificate")
		}
		roots := x509.NewCertPool()
		roots.AddCert(certIn(t, filepath.Join(first, "opensearch", "certs"), "root-ca.pem"))
		node := certIn(t, filepath.Join(out, "opensearch", "certs"), "node.pem")
		if _, err := node.Verify(x509.VerifyOptions{Roots: roots, DNSName: "192.0.2.8", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil || node.Subject.CommonName != "search2" {
			t.Errorf("node certificate: %v %s", err, node.Subject)
		}
		client := certIn(t, filepath.Join(out, "signalith"), "opensearch-client.pem")
		if _, err := client.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Error(err)
		}
		settings, _ := os.ReadFile(filepath.Join(out, "opensearch", "add-to-opensearch.yml"))
		var m map[string]any
		if err := yaml.Unmarshal(settings, &m); err != nil {
			t.Fatal(err)
		}
		if dn := m["plugins.security.nodes_dn"].([]any); len(dn) != 3 || dn[0] != "CN=search2,O=Signalith" || dn[2] != "CN=search3,O=Signalith" {
			t.Errorf("nodes_dn %v", dn)
		}
	}
	if err := writeOpenSearchCerts(&msg, osCertsOptions{Out: filepath.Join(root, "x"), CADir: filepath.Join(first, "opensearch"), Now: time.Now()}); err == nil || !strings.Contains(err.Error(), "no OpenSearch CA") {
		t.Errorf("no CA there: %v", err)
	}
	if err := writeOpenSearchCerts(&msg, osCertsOptions{Out: filepath.Join(root, "y"), Node: "signalith-admin", Now: time.Now()}); err == nil {
		t.Error("a reserved node name was accepted")
	}
	if runtime.GOOS != "windows" {
		checkModes(t, filepath.Join(first, "ca"), os.Getuid(), 0o700)
	}
}
