package ospki

import (
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func smallKeys(t *testing.T) {
	KeyBits = 2048
	t.Cleanup(func() { KeyBits = 3072 })
}

func TestLoadCA(t *testing.T) {
	smallKeys(t)
	s, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := LoadCA(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("empty folder: %v", err)
	}
	os.WriteFile(filepath.Join(dir, RootCAFile), s.CA.CertPEM(), 0o600)
	if _, err := LoadCA(dir); !errors.Is(err, ErrNoCAKey) {
		t.Errorf("no key: %v", err)
	}
	os.WriteFile(filepath.Join(dir, RootCAKeyFile), other.KeyPEM(), 0o600)
	if _, err := LoadCA(dir); err == nil || !strings.Contains(err.Error(), "not the key") {
		t.Errorf("another key: %v", err)
	}
	for name, b := range s.CAFiles() {
		os.WriteFile(filepath.Join(dir, name), b, 0o600)
	}
	ca, err := LoadCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.Equal(s.CA.Cert) || !ca.Key.Equal(s.CA.Key) {
		t.Error("loaded another CA")
	}
	// A leaf is no CA.
	os.WriteFile(filepath.Join(dir, RootCAFile), s.Client.CertPEM(), 0o600)
	if _, err := LoadCA(dir); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Errorf("leaf as CA: %v", err)
	}
}

func TestIssueUnderCA(t *testing.T) {
	smallKeys(t)
	now := time.Now()
	ca, err := NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	node, err := IssueNode(ca, "opensearch-2", []string{"search.example.com", "192.0.2.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"opensearch-2", "localhost", "127.0.0.1", "search.example.com", "192.0.2.1"} {
		if _, err := node.Cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("node for %s: %v", host, err)
		}
	}
	if _, err := node.Cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("node as client: %v", err)
	}
	name, err := ServerClientName("siem-a")
	if err != nil || name != "signalith-server-siem-a" {
		t.Fatalf("%q %v", name, err)
	}
	client, err := IssueClient(ca, name, now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Error(err)
	}
	if client.Cert.Subject.String() != "CN=signalith-server-siem-a,O=Signalith" {
		t.Errorf("subject %s", client.Cert.Subject)
	}
	if d := client.Cert.NotAfter.Sub(now); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("client lasts %v", d)
	}
	// Never past the CA.
	late, err := IssueClient(ca, ClientName, now.Add(Validity-24*time.Hour), Validity)
	if err != nil {
		t.Fatal(err)
	}
	if !late.Cert.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Errorf("leaf until %v, CA until %v", late.Cert.NotAfter, ca.Cert.NotAfter)
	}
	// Without the key nothing is issued.
	if _, err := IssueClient(&Pair{Cert: ca.Cert}, ClientName, now, Validity); !errors.Is(err, ErrNoCAKey) {
		t.Errorf("no key: %v", err)
	}
	// NamesOf gives back what a renewal must keep.
	if got := NamesOf(node); !slices.Equal(got, []string{"opensearch-2", "localhost", "search.example.com", "127.0.0.1", "192.0.2.1"}) {
		t.Errorf("names %v", got)
	}
	again, err := IssueNode(ca, "opensearch-2", NamesOf(node), now)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(NamesOf(again), NamesOf(node)) {
		t.Errorf("renewed names %v", NamesOf(again))
	}
}

func TestNames(t *testing.T) {
	for _, ok := range []string{"siem-a", "a", "web01"} {
		if _, err := ServerClientName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Admin", "a.b", "-a", "a-", "a_b", strings.Repeat("a", 60)} {
		if _, err := ServerClientName(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, bad := range []string{"signalith", "signalith-admin", "Signalith-server-x", "signalith-anything"} {
		if err := CheckNodeName(bad); err == nil {
			t.Errorf("node name %q was accepted", bad)
		}
		if _, err := New(Options{Node: bad}); err == nil {
			t.Errorf("New with node %q", bad)
		}
	}
	for _, ok := range []string{"opensearch", "opensearch-2", "search1.example.com", "signalithsearch"} {
		if err := CheckNodeName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for i, want := range map[int][3]string{1: {"node.pem", "node-key.pem", "opensearch"}, 2: {"node-2.pem", "node-2-key.pem", "opensearch-2"}, 3: {"node-3.pem", "node-3-key.pem", "opensearch-3"}} {
		c, k := NodeFileNames(i)
		if c != want[0] || k != want[1] || NodeCN(i) != want[2] || !IsKey(k) || IsKey(c) {
			t.Errorf("node %d: %s %s %s", i, c, k, NodeCN(i))
		}
	}
	if got := NodesDN("opensearch", "opensearch-2"); !slices.Equal(got, []string{"CN=opensearch,O=Signalith", "CN=opensearch-2,O=Signalith"}) {
		t.Errorf("NodesDN %v", got)
	}
}

func TestSettingsFor(t *testing.T) {
	if Settings("search1") != SettingsFor("search1", nil) || !strings.Contains(Settings(""), `plugins.security.nodes_dn: ["CN=opensearch,O=Signalith"]`) {
		t.Error("Settings changed")
	}
	var m map[string]any
	if err := yaml.Unmarshal([]byte(SettingsFor("opensearch", []string{"opensearch-2", "opensearch-3"})), &m); err != nil {
		t.Fatal(err)
	}
	dn := m["plugins.security.nodes_dn"].([]any)
	if len(dn) != 3 || dn[0] != "CN=opensearch,O=Signalith" || dn[2] != "CN=opensearch-3,O=Signalith" {
		t.Errorf("nodes_dn %v", dn)
	}
}

func TestCheckErrorKinds(t *testing.T) {
	smallKeys(t)
	now := time.Now()
	s, err := New(Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		spoil func(osDir, sigDir string)
		ca    bool
		file  string
	}{
		"CA missing":     {func(o, _ string) { os.Remove(filepath.Join(o, RootCAFile)) }, true, RootCAFile},
		"CA not a CA":    {func(o, _ string) { os.WriteFile(filepath.Join(o, RootCAFile), s.Node.CertPEM(), 0o600) }, true, RootCAFile},
		"client missing": {func(_, g string) { os.Remove(filepath.Join(g, ClientCertFile)) }, false, ClientCertFile},
		"node key":       {func(o, _ string) { os.Remove(filepath.Join(o, NodeKeyFile)) }, false, NodeKeyFile},
		"CA copy":        {func(_, g string) { os.Remove(filepath.Join(g, ClientCAFile)) }, false, ClientCAFile},
	}
	for name, c := range cases {
		osDir, sigDir := writeSet(t, s)
		c.spoil(osDir, sigDir)
		var ce *CheckError
		if err := Check(osDir, sigDir, "", now, 0); !errors.As(err, &ce) || ce.CA != c.ca || ce.File != c.file {
			t.Errorf("%s: %#v", name, err)
		}
	}
	osDir, sigDir := writeSet(t, s)
	var ce *CheckError
	if err := Check(osDir, sigDir, "", now.Add(Validity-24*time.Hour), 30*24*time.Hour); !errors.As(err, &ce) || !ce.CA {
		t.Errorf("expiring CA: %#v", err)
	}
}
