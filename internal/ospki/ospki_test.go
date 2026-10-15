package ospki

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func writeSet(t *testing.T, s *Set) (osDir, sigDir string) {
	t.Helper()
	osDir, sigDir = t.TempDir(), t.TempDir()
	for name, b := range s.OpenSearchFiles() {
		if err := os.WriteFile(filepath.Join(osDir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, b := range s.SignalithFiles() {
		if err := os.WriteFile(filepath.Join(sigDir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return osDir, sigDir
}

func TestNewSet(t *testing.T) {
	KeyBits = 3072
	now := time.Now()
	s, err := New(Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	ca := s.CA.Cert
	if !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 || ca.PublicKey.(*rsa.PublicKey).N.BitLen() != 3072 {
		t.Errorf("CA: IsCA %v, usage %v, %d bits", ca.IsCA, ca.KeyUsage, ca.PublicKey.(*rsa.PublicKey).N.BitLen())
	}
	if years := ca.NotAfter.Sub(now).Hours() / 24 / 365; years < 9.9 || years > 10.1 {
		t.Errorf("CA lasts %.1f years", years)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	// The node certificate serves HTTPS for its names and is also a
	// client between nodes.
	node := s.Node.Cert
	if node.Subject.String() != "CN=opensearch,O=Signalith" || node.Subject.String() != DN(NodeName) {
		t.Errorf("node subject %q", node.Subject)
	}
	if !slices.Equal(node.DNSNames, []string{"opensearch", "localhost"}) || len(node.IPAddresses) != 1 || !node.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("node names %v %v", node.DNSNames, node.IPAddresses)
	}
	for _, host := range []string{"opensearch", "localhost", "127.0.0.1"} {
		if _, err := node.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("node as server for %s: %v", host, err)
		}
	}
	if !slices.Equal(node.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		t.Errorf("node EKU %v", node.ExtKeyUsage)
	}
	for _, p := range []struct {
		pair *Pair
		dn   string
	}{{s.Admin, "CN=signalith-admin,O=Signalith"}, {s.Client, "CN=signalith,O=Signalith"}} {
		c := p.pair.Cert
		if c.Subject.String() != p.dn {
			t.Errorf("subject %q, want %q", c.Subject, p.dn)
		}
		if !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || c.IsCA {
			t.Errorf("%s: EKU %v, CA %v", p.dn, c.ExtKeyUsage, c.IsCA)
		}
		if _, err := c.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Errorf("%s as client: %v", p.dn, err)
		}
		if _, err := c.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
			t.Errorf("%s works as a server certificate", p.dn)
		}
	}
	// Keys are PKCS#8, the only form OpenSearch reads, and belong to
	// their certificates.
	for name, b := range s.OpenSearchFiles() {
		block, rest := pem.Decode(b)
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatalf("%s is not one PEM block", name)
		}
		if IsKey(name) {
			if block.Type != "PRIVATE KEY" {
				t.Errorf("%s: %s", name, block.Type)
			}
			if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		} else if block.Type != "CERTIFICATE" {
			t.Errorf("%s: %s", name, block.Type)
		}
	}
	if !bytes.Equal(s.SignalithFiles()[ClientCAFile], s.OpenSearchFiles()[RootCAFile]) {
		t.Error("Signalith's CA file is not OpenSearch's CA")
	}
	osDir, sigDir := writeSet(t, s)
	if err := Check(osDir, sigDir, "", now, 30*24*time.Hour); err != nil {
		t.Errorf("check: %v", err)
	}
}

func TestNodeNames(t *testing.T) {
	KeyBits = 2048
	t.Cleanup(func() { KeyBits = 3072 })
	s, err := New(Options{Node: "search1", Names: []string{"search1.example.com", "192.0.2.7", "LOCALHOST", " ", "::1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Node.Cert.DNSNames; !slices.Equal(got, []string{"search1", "localhost", "search1.example.com"}) {
		t.Errorf("DNS names %v", got)
	}
	if got := s.Node.Cert.IPAddresses; len(got) != 3 || !got[1].Equal(net.ParseIP("192.0.2.7")) || !got[2].Equal(net.ParseIP("::1")) {
		t.Errorf("IP addresses %v", got)
	}
	if s.Node.Cert.Subject.String() != "CN=search1,O=Signalith" {
		t.Errorf("subject %s", s.Node.Cert.Subject)
	}
	for _, bad := range []Options{{Node: "192.0.2.7"}, {Node: "bad name"}, {Names: []string{"a/b"}}} {
		if _, err := New(bad); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

func TestCheckFindsProblems(t *testing.T) {
	KeyBits = 2048
	t.Cleanup(func() { KeyBits = 3072 })
	now := time.Now()
	a, err := New(Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(osDir, sigDir string){
		"missing node key": func(osDir, _ string) { os.Remove(filepath.Join(osDir, NodeKeyFile)) },
		"other CA": func(_, sigDir string) {
			os.WriteFile(filepath.Join(sigDir, ClientCAFile), b.CA.CertPEM(), 0o600)
		},
		"key of another set": func(osDir, _ string) {
			os.WriteFile(filepath.Join(osDir, AdminKeyFile), b.Admin.KeyPEM(), 0o600)
		},
		"certificate from another CA": func(_, sigDir string) {
			os.WriteFile(filepath.Join(sigDir, ClientCertFile), b.Client.CertPEM(), 0o600)
			os.WriteFile(filepath.Join(sigDir, ClientKeyFile), b.Client.KeyPEM(), 0o600)
		},
		"wrong name": func(osDir, _ string) {
			os.WriteFile(filepath.Join(osDir, AdminCertFile), a.Client.CertPEM(), 0o600)
			os.WriteFile(filepath.Join(osDir, AdminKeyFile), a.Client.KeyPEM(), 0o600)
		},
		"PKCS#1 key": func(osDir, _ string) {
			der := x509.MarshalPKCS1PrivateKey(a.Node.Key)
			os.WriteFile(filepath.Join(osDir, NodeKeyFile), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), 0o600)
		},
		"garbage": func(osDir, _ string) { os.WriteFile(filepath.Join(osDir, RootCAFile), []byte("x"), 0o600) },
	}
	for name, spoil := range cases {
		osDir, sigDir := writeSet(t, a)
		spoil(osDir, sigDir)
		if err := Check(osDir, sigDir, "", now, 0); err == nil {
			t.Errorf("%s: no problem found", name)
		}
	}
	osDir, sigDir := writeSet(t, a)
	if err := Check(osDir, sigDir, "", now, 0); err != nil {
		t.Errorf("good set: %v", err)
	}
	if err := Check(osDir, sigDir, "", now.Add(Validity-24*time.Hour), 30*24*time.Hour); err == nil || !strings.Contains(err.Error(), "expires") {
		t.Errorf("expiring set: %v", err)
	}
	if err := Check(osDir, sigDir, "search1", now, 0); err == nil {
		t.Error("another node name was accepted")
	}
}

// TestSecurityFiles checks the OpenSearch security files: valid YAML of
// the right type, sign-in by certificate only, no users, and the role
// Signalith's certificate gets.
func TestSecurityFiles(t *testing.T) {
	files := SecurityFiles()
	want := map[string]string{"config.yml": "config", "internal_users.yml": "internalusers", "roles.yml": "roles", "roles_mapping.yml": "rolesmapping"}
	if len(files) != len(want) {
		t.Errorf("files %v", keys(files))
	}
	docs := map[string]map[string]any{}
	for name, typ := range want {
		var doc map[string]any
		if err := yaml.Unmarshal(files[name], &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		meta, _ := doc["_meta"].(map[string]any)
		if meta["type"] != typ || meta["config_version"] != 2 {
			t.Errorf("%s: _meta %v", name, meta)
		}
		docs[name] = doc
	}
	if len(docs["internal_users.yml"]) != 1 {
		t.Errorf("internal users: %v", docs["internal_users.yml"])
	}
	authc := dig(docs["config.yml"], "config", "dynamic", "authc").(map[string]any)
	if len(authc) != 1 {
		t.Errorf("sign-in methods: %v", keys(authc))
	}
	cc := authc["clientcert_auth_domain"].(map[string]any)
	if dig(cc, "http_authenticator", "type") != "clientcert" || dig(cc, "http_authenticator", "config", "username_attribute") != "cn" ||
		dig(cc, "authentication_backend", "type") != "noop" || cc["http_enabled"] != true {
		t.Errorf("clientcert domain: %v", cc)
	}
	if dig(docs["config.yml"], "config", "dynamic", "http", "anonymous_auth_enabled") != false {
		t.Error("anonymous access is not off")
	}
	if users := dig(docs["roles_mapping.yml"], "signalith_server", "users").([]any); len(users) != 2 || users[0] != ClientName || users[1] != ServerClientPrefix+"*" {
		t.Errorf("role mapping: %v", users)
	}
	role := docs["roles.yml"]["signalith_server"].(map[string]any)
	ip := role["index_permissions"].([]any)[0].(map[string]any)
	if pats := ip["index_patterns"].([]any); len(pats) != 1 || pats[0] != "signalith*" {
		t.Errorf("index patterns %v", pats)
	}
	if acts := ip["allowed_actions"].([]any); len(acts) != 3 || acts[0] != "crud" || acts[2] != "manage" {
		t.Errorf("index actions %v", acts)
	}
	if cl := role["cluster_permissions"].([]any); !slices.Contains(cl, any("cluster_monitor")) || !slices.Contains(cl, any("indices:admin/index_template/*")) {
		t.Errorf("cluster permissions %v", cl)
	}
}

// TestDockerFilesMatch checks that the Docker quick start uses the same
// security files, and the same settings, as this package writes for
// other installs.
func TestDockerFilesMatch(t *testing.T) {
	dir := filepath.Join("..", "..", "deploy", "docker", "opensearch")
	for name, want := range SecurityFiles() {
		got, err := os.ReadFile(filepath.Join(dir, "security", name))
		if err != nil {
			t.Fatal(err)
		}
		if lf(got) != lf(want) {
			t.Errorf("deploy/docker/opensearch/security/%s differs from internal/ospki/security/%s", name, name)
		}
	}
	yml, err := os.ReadFile(filepath.Join(dir, "opensearch.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var docker map[string]any
	if err := yaml.Unmarshal(yml, &docker); err != nil {
		t.Fatalf("opensearch.yml: %v", err)
	}
	var settings map[string]any
	if err := yaml.Unmarshal([]byte(Settings("")), &settings); err != nil {
		t.Fatalf("settings: %v", err)
	}
	for k, v := range settings {
		if !equalYAML(docker[k], v) {
			t.Errorf("opensearch.yml %s = %v, want %v", k, docker[k], v)
		}
	}
	for k, v := range map[string]any{"network.host": "0.0.0.0", "cluster.name": "docker-cluster", "node.store.allow_mmap": false} {
		if docker[k] != v {
			t.Errorf("opensearch.yml %s = %v, want %v", k, docker[k], v)
		}
	}
	if _, ok := docker["bootstrap.memory_lock"]; ok {
		t.Error("bootstrap.memory_lock is set; Docker Desktop may not allow locking memory")
	}
	if dn := settings["plugins.security.nodes_dn"].([]any); dn[0] != "CN=opensearch,O=Signalith" {
		t.Errorf("nodes_dn %v", dn)
	}
	if dn := settings["plugins.security.authcz.admin_dn"].([]any); dn[0] != "CN=signalith-admin,O=Signalith" {
		t.Errorf("admin_dn %v", dn)
	}
}

func lf(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }

func equalYAML(a, b any) bool {
	x, _ := yaml.Marshal(a)
	y, _ := yaml.Marshal(b)
	return string(x) == string(y)
}

func dig(m map[string]any, path ...string) any {
	var v any = m
	for _, p := range path {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mm[p]
	}
	return v
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
