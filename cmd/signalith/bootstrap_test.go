package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/store"
	"gopkg.in/yaml.v3"
)

// bootstrap runs bootstrap-docker into two new folders, as root would
// for uids 1000 and 65532. It prepares Linux container volumes, so the
// tests using it do not run on Windows, where its read-only secrets could
// not be cleaned up.
func bootstrap(t *testing.T, osDir, sigDir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("bootstrap-docker prepares Linux container volumes")
	}
	var out bytes.Buffer
	if err := bootstrapDocker(&out, osDir, sigDir, 1000, 65532, time.Now()); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func readAll(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// checkModes checks owners (when running as root) and permissions (not
// on Windows, where Go reports 0666 for every file).
func checkModes(t *testing.T, path string, uid int, mode fs.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if fi.Mode().Perm() != mode {
		t.Errorf("%s: mode %v, want %v", path, fi.Mode().Perm(), mode)
	}
	if u, g, ok := fileOwner(fi); ok && os.Geteuid() == 0 && (u != uid || g != uid) {
		t.Errorf("%s: owner %d:%d, want %d:%d", path, u, g, uid, uid)
	}
}

func TestBootstrapDocker(t *testing.T) {
	root := t.TempDir()
	osDir, sigDir := filepath.Join(root, "opensearch-certs"), filepath.Join(root, "signalith-secrets")
	out := bootstrap(t, osDir, sigDir)
	if !strings.Contains(out, "OpenSearch certificates: made") || !strings.Contains(out, "Made initial-admin-password") || !strings.Contains(out, "initial-password") {
		t.Errorf("output:\n%s", out)
	}
	osFiles, sigFiles := readAll(t, osDir), readAll(t, sigDir)
	if got := keysOf(osFiles); !slices.Equal(got, []string{"admin-key.pem", "admin.pem", "node-key.pem", "node.pem", "root-ca.pem"}) {
		t.Errorf("OpenSearch files %v", got)
	}
	if got := keysOf(sigFiles); !slices.Equal(got, []string{"ingest-token", "initial-admin-password", "opensearch-ca.pem", "opensearch-client-key.pem", "opensearch-client.pem"}) {
		t.Errorf("Signalith files %v", got)
	}

	// Owners and permissions: only OpenSearch (1000) reads its files;
	// Signalith (65532) only reads its own.
	checkModes(t, osDir, 1000, 0o700)
	for name := range osFiles {
		checkModes(t, filepath.Join(osDir, name), 1000, 0o600)
	}
	checkModes(t, sigDir, 65532, 0o700)
	for name := range sigFiles {
		checkModes(t, filepath.Join(sigDir, name), 65532, 0o400)
	}

	// Every PEM parses, keys are PKCS#8, and the certificates have the
	// names and uses OpenSearch's settings expect.
	certs := map[string]*x509.Certificate{}
	for name, text := range mergeMaps(osFiles, sigFiles) {
		if !strings.HasSuffix(name, ".pem") {
			continue
		}
		block, rest := pem.Decode([]byte(text))
		if block == nil || strings.TrimSpace(string(rest)) != "" {
			t.Fatalf("%s is not one PEM block", name)
		}
		if strings.HasSuffix(name, "-key.pem") {
			if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); block.Type != "PRIVATE KEY" || err != nil {
				t.Errorf("%s: %s %v", name, block.Type, err)
			}
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		certs[name] = c
	}
	if osFiles["root-ca.pem"] != sigFiles["opensearch-ca.pem"] || !certs["root-ca.pem"].IsCA {
		t.Error("Signalith's CA file is not OpenSearch's CA")
	}
	node := certs["node.pem"]
	if node.Subject.String() != "CN=opensearch,O=Signalith" || !slices.Equal(node.DNSNames, []string{"opensearch", "localhost"}) ||
		len(node.IPAddresses) != 1 || node.IPAddresses[0].String() != "127.0.0.1" ||
		!slices.Equal(node.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		t.Errorf("node: %s %v %v %v", node.Subject, node.DNSNames, node.IPAddresses, node.ExtKeyUsage)
	}
	for name, dn := range map[string]string{"admin.pem": "CN=signalith-admin,O=Signalith", "opensearch-client.pem": "CN=signalith,O=Signalith"} {
		c := certs[name]
		if c.Subject.String() != dn || !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
			t.Errorf("%s: %s %v", name, c.Subject, c.ExtKeyUsage)
		}
		if err := c.CheckSignatureFrom(certs["root-ca.pem"]); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !regexp.MustCompile(`^[a-z2-9]{4}(-[a-z2-9]{4}){3}\n$`).MatchString(sigFiles["initial-admin-password"]) {
		t.Errorf("initial password %q", sigFiles["initial-admin-password"])
	}
	if !regexp.MustCompile(`^[0-9a-f]{48}\n$`).MatchString(sigFiles["ingest-token"]) {
		t.Errorf("ingest token %q", sigFiles["ingest-token"])
	}

	// A second run keeps everything and puts owners and permissions back.
	if runtime.GOOS != "windows" {
		os.Chmod(filepath.Join(osDir, "node-key.pem"), 0o644)
		os.Chmod(filepath.Join(sigDir, "ingest-token"), 0o644)
		if os.Geteuid() == 0 {
			os.Chown(filepath.Join(sigDir, "opensearch-client-key.pem"), 0, 0)
		}
	}
	out = bootstrap(t, osDir, sigDir)
	if !strings.Contains(out, "OpenSearch certificates: kept") || strings.Contains(out, "Made") {
		t.Errorf("second run:\n%s", out)
	}
	if again := readAll(t, osDir); !mapsEqual(again, osFiles) {
		t.Error("the second run changed OpenSearch's files")
	}
	if again := readAll(t, sigDir); !mapsEqual(again, sigFiles) {
		t.Error("the second run changed Signalith's files")
	}
	checkModes(t, filepath.Join(osDir, "node-key.pem"), 1000, 0o600)
	checkModes(t, filepath.Join(sigDir, "ingest-token"), 65532, 0o400)
	checkModes(t, filepath.Join(sigDir, "opensearch-client-key.pem"), 65532, 0o400)

	// A missing key means new certificates for both sides; the password
	// and token stay.
	os.Remove(filepath.Join(osDir, "node-key.pem"))
	out = bootstrap(t, osDir, sigDir)
	if !strings.Contains(out, "made new ones") || !strings.Contains(out, "restart") {
		t.Errorf("after a lost key:\n%s", out)
	}
	osNew, sigNew := readAll(t, osDir), readAll(t, sigDir)
	if osNew["root-ca.pem"] == osFiles["root-ca.pem"] || sigNew["opensearch-ca.pem"] != osNew["root-ca.pem"] {
		t.Error("certificates were not made again together")
	}
	if sigNew["initial-admin-password"] != sigFiles["initial-admin-password"] || sigNew["ingest-token"] != sigFiles["ingest-token"] {
		t.Error("the password or token changed")
	}
	if err := ospki.Check(osDir, sigDir, "", time.Now(), renewWithin); err != nil {
		t.Error(err)
	}
}

// TestBootstrapCertificatesWork connects Signalith's OpenSearch client,
// with the files bootstrap-docker made, to a server using OpenSearch's
// files that, like OpenSearch, accepts only certificates from its CA.
func TestBootstrapCertificatesWork(t *testing.T) {
	root := t.TempDir()
	osDir, sigDir := filepath.Join(root, "os"), filepath.Join(root, "sig")
	bootstrap(t, osDir, sigDir)
	pair, err := tls.LoadX509KeyPair(filepath.Join(osDir, "node.pem"), filepath.Join(osDir, "node-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	caOnly := x509.NewCertPool()
	caPEM, _ := os.ReadFile(filepath.Join(osDir, "root-ca.pem"))
	caOnly.AppendCertsFromPEM(caPEM)
	var who []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who = append(who, r.TLS.PeerCertificates[0].Subject.String())
		w.Write([]byte(`{"status":"green"}`))
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: caOnly}
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	for _, host := range []string{"localhost", "127.0.0.1"} {
		cl := store.New(store.Config{URL: "https://" + net.JoinHostPort(host, port),
			CAFile: filepath.Join(sigDir, "opensearch-ca.pem"), CertFile: filepath.Join(sigDir, "opensearch-client.pem"), KeyFile: filepath.Join(sigDir, "opensearch-client-key.pem")})
		if status, err := cl.Health(context.Background()); err != nil || status != "green" {
			t.Errorf("%s: %q %v", host, status, err)
		}
	}
	// The admin certificate works as a client too (the health check).
	cl := store.New(store.Config{URL: srv.URL, CAFile: filepath.Join(osDir, "root-ca.pem"),
		CertFile: filepath.Join(osDir, "admin.pem"), KeyFile: filepath.Join(osDir, "admin-key.pem")})
	if _, err := cl.Health(context.Background()); err != nil {
		t.Error(err)
	}
	if !slices.Equal(who, []string{"CN=signalith,O=Signalith", "CN=signalith,O=Signalith", "CN=signalith-admin,O=Signalith"}) {
		t.Errorf("clients %v", who)
	}
	// Without a client certificate the server refuses.
	if _, err := store.New(store.Config{URL: srv.URL, CAFile: filepath.Join(sigDir, "opensearch-ca.pem")}).Health(context.Background()); err == nil {
		t.Error("no client certificate was accepted")
	}
}

// TestInitialPassword follows the Docker quick start: the first password
// works and is shown until the admin sets a new one with passwd.
func TestInitialPassword(t *testing.T) {
	root := t.TempDir()
	sigDir, state := filepath.Join(root, "secrets"), filepath.Join(root, "state")
	bootstrap(t, filepath.Join(root, "certs"), sigDir)
	os.MkdirAll(state, 0o700)
	path := filepath.Join(root, "signalith.yaml")
	os.WriteFile(path, []byte("lookups:\n  dir: "+filepath.Join(state, "lookups")+"\n"), 0o600)
	first, _ := os.ReadFile(filepath.Join(sigDir, initialPasswordFile))
	t.Setenv("SIGNALITH_STATE_DIR", state)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", filepath.Join(sigDir, initialPasswordFile))
	t.Setenv("SIGNALITH_INGEST_TOKEN_FILE", filepath.Join(sigDir, ingestTokenFile))

	var out bytes.Buffer
	if err := printInitialPassword(&out, path); err != nil || out.String() != string(first) {
		t.Fatalf("initial-password printed %q, %v; want %q", out.String(), err, first)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.CheckPassword("admin", strings.TrimSpace(string(first))) {
		t.Fatal("the first password does not sign in")
	}

	t.Setenv("SIGNALITH_NEW_PASSWORD", "my own admin password")
	printed := captureStdout(t, func() {
		if err := cmdPasswd([]string{"-c", path}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(printed, filepath.Join(state, "admin-password-hash")) || !strings.Contains(printed, "docker compose -f deploy/docker/docker-compose.yml restart signalith") {
		t.Errorf("passwd said:\n%s", printed)
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "admin_password_hash") {
		t.Error("passwd wrote the read-only config file")
	}
	checkModes(t, filepath.Join(state, "admin-password-hash"), os.Getuid(), 0o600)
	c, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.CheckPassword("admin", strings.TrimSpace(string(first))) || !c.CheckPassword("admin", "my own admin password") {
		t.Error("the first password still works, or the new one does not")
	}
	out.Reset()
	if err := printInitialPassword(&out, path); err == nil || !strings.Contains(err.Error(), "no longer works") || !strings.Contains(err.Error(), "docker-compose.yml restart signalith") || out.Len() != 0 {
		t.Errorf("initial-password after the change: %q %v", out.String(), err)
	}
	// A second change goes to the same place.
	t.Setenv("SIGNALITH_NEW_PASSWORD", "another admin password")
	captureStdout(t, func() {
		if err := cmdPasswd([]string{"-c", path}); err != nil {
			t.Fatal(err)
		}
	})
	if c, err := config.Load(path); err != nil || !c.CheckPassword("admin", "another admin password") {
		t.Errorf("second change: %v", err)
	}

	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", "")
	if err := printInitialPassword(&out, path); err == nil || !strings.Contains(err.Error(), "no generated first password") {
		t.Errorf("without the variable: %v", err)
	}
}

func TestOpenSearchCerts(t *testing.T) {
	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = 3072 })
	out := filepath.Join(t.TempDir(), "pki")
	var msg bytes.Buffer
	if err := writeOpenSearchCerts(&msg, out, "search1", []string{"search1.example.com", "192.0.2.7"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.String(), "docs/opensearch-security.md") || !strings.Contains(msg.String(), "search1.example.com") {
		t.Errorf("output:\n%s", msg.String())
	}
	var files []string
	filepath.WalkDir(out, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(out, p)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	slices.Sort(files)
	want := []string{
		"opensearch/add-to-opensearch.yml",
		"opensearch/certs/admin-key.pem", "opensearch/certs/admin.pem", "opensearch/certs/node-key.pem", "opensearch/certs/node.pem", "opensearch/certs/root-ca.pem",
		"opensearch/opensearch-security/config.yml", "opensearch/opensearch-security/internal_users.yml",
		"opensearch/opensearch-security/roles.yml", "opensearch/opensearch-security/roles_mapping.yml",
		"signalith/add-to-signalith.yaml", "signalith/opensearch-ca.pem", "signalith/opensearch-client-key.pem", "signalith/opensearch-client.pem",
	}
	if !slices.Equal(files, want) {
		t.Errorf("files:\n%v\nwant:\n%v", files, want)
	}
	if err := ospki.Check(filepath.Join(out, "opensearch", "certs"), filepath.Join(out, "signalith"), "search1", time.Now(), 0); err != nil {
		t.Error(err)
	}
	if runtime.GOOS != "windows" {
		checkModes(t, filepath.Join(out, "opensearch", "certs", "node-key.pem"), os.Getuid(), 0o600)
		checkModes(t, filepath.Join(out, "signalith", "opensearch-client-key.pem"), os.Getuid(), 0o600)
		checkModes(t, out, os.Getuid(), 0o700)
	}
	settings, _ := os.ReadFile(filepath.Join(out, "opensearch", "add-to-opensearch.yml"))
	var m map[string]any
	if err := yaml.Unmarshal(settings, &m); err != nil {
		t.Fatal(err)
	}
	if dn := m["plugins.security.nodes_dn"].([]any); dn[0] != "CN=search1,O=Signalith" {
		t.Errorf("nodes_dn %v", dn)
	}

	// The Signalith settings load as they are, next to the files.
	sig := filepath.Join(out, "signalith")
	snippet, _ := os.ReadFile(filepath.Join(sig, "add-to-signalith.yaml"))
	os.WriteFile(filepath.Join(sig, "signalith.yaml"), snippet, 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	c, err := config.Load(filepath.Join(sig, "signalith.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if ca, cert, key := c.OpenSearchTLSFiles(); ca != filepath.Join(sig, "opensearch-ca.pem") || cert == "" || key == "" || c.OpenSearch.URL != "https://search1:9200" {
		t.Errorf("settings %s %s %s %s", c.OpenSearch.URL, ca, cert, key)
	}

	// Never over files that are there.
	if err := writeOpenSearchCerts(&msg, out, "", nil, time.Now()); err == nil || !strings.Contains(err.Error(), "already has files") {
		t.Errorf("second run: %v", err)
	}
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func mergeMaps(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// The packages run init -save-password: the generated password is not
// printed but kept privately next to the config file, where
// initial-password finds it.
func TestInitSavePassword(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(root, "state"))
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", "")
	path := filepath.Join(root, "etc", "signalith.yaml")
	os.MkdirAll(filepath.Dir(path), 0o700)
	var out bytes.Buffer
	if err := printInitialPassword(&out, path); err == nil || !strings.Contains(err.Error(), "no generated first password") {
		t.Fatalf("before init: %q %v", out.String(), err)
	}
	printed := captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path, "-save-password"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(printed, "signalith initial-password") {
		t.Errorf("init said:\n%s", printed)
	}
	saved := filepath.Join(filepath.Dir(path), initialPasswordFile)
	checkModes(t, saved, os.Getuid(), 0o600)
	if err := printInitialPassword(&out, path); err != nil {
		t.Fatal(err)
	}
	pw := strings.TrimSpace(out.String())
	if pw == "" || strings.Contains(printed, pw) {
		t.Fatalf("password %q, printed by init:\n%s", pw, printed)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.CheckPassword("admin", pw) {
		t.Error("the saved password does not sign in")
	}
}
