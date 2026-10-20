// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package tlsauto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeMachine makes the machine's own names predictable.
func fakeMachine(t *testing.T) {
	t.Helper()
	prev := localNames
	localNames = func() []string { return []string{"localhost", "127.0.0.1", "::1", "WS-Test", "10.1.2.3"} }
	t.Cleanup(func() { localNames = prev })
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newAuto(t *testing.T, dir string, c *clock, names ...string) *Manager {
	t.Helper()
	m, err := New(Options{Dir: dir, Names: names, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func caPool(t *testing.T, m *Manager) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(m.CAPEM()) {
		t.Fatalf("CAPEM is not a certificate: %q", m.CAPEM())
	}
	return pool
}

func TestAutoMakesCAAndCertificate(t *testing.T) {
	fakeMachine(t)
	dir := filepath.Join(t.TempDir(), "tls")
	c := &clock{time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}
	m := newAuto(t, dir, c, "siem.example.com", "192.0.2.10", "SIEM.example.com.")
	if !m.LocalCA() || m.CAPath() != filepath.Join(dir, "ca.pem") {
		t.Errorf("LocalCA %v, CAPath %s", m.LocalCA(), m.CAPath())
	}

	ca, err := parseCert(m.CAPEM())
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || !ca.MaxPathLenZero || ca.KeyUsage&x509.KeyUsageCertSign == 0 || !strings.HasPrefix(ca.Subject.CommonName, "Signalith Local CA (") {
		t.Errorf("CA = %+v", ca.Subject)
	}
	if k, ok := ca.PublicKey.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
		t.Errorf("CA key is %T", ca.PublicKey)
	}
	if years := ca.NotAfter.Sub(c.t).Hours() / 24 / 365; years < 9.9 || years > 10.1 {
		t.Errorf("CA lasts %.1f years", years)
	}
	sum := sha256.Sum256(ca.Raw)
	if want := strings.ToUpper(hex.EncodeToString(sum[:])); strings.ReplaceAll(m.Fingerprint(), ":", "") != want || len(m.Fingerprint()) != 95 {
		t.Errorf("fingerprint %s, want %s", m.Fingerprint(), want)
	}

	leaf := m.Leaf()
	if leaf.Subject.CommonName != "siem.example.com" {
		t.Errorf("common name %q", leaf.Subject.CommonName)
	}
	if d := leaf.NotAfter.Sub(c.t); d < LeafValidity-time.Minute || d > LeafValidity {
		t.Errorf("leaf lasts %s", d)
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) || leaf.IsCA {
		t.Errorf("leaf usage %v, CA %v", leaf.ExtKeyUsage, leaf.IsCA)
	}
	if k, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
		t.Errorf("leaf key is %T", leaf.PublicKey)
	}
	// Every name, verified against the CA alone. The duplicate in another
	// case is listed once.
	pool := caPool(t, m)
	for _, name := range []string{"siem.example.com", "192.0.2.10", "localhost", "127.0.0.1", "::1", "ws-test", "10.1.2.3"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: c.t}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := strings.Join(certNames(leaf), " "); strings.Count(got, "siem.example.com") != 1 {
		t.Errorf("names %s", got)
	}
	if m.Covers("other.example.com") || !m.Covers("[::1]") {
		t.Error("Covers is wrong")
	}

	// Keys are private; certificates readable.
	if runtime.GOOS != "windows" {
		for name, want := range map[string]os.FileMode{"ca.key": 0o600, "server.key": 0o600, "ca.pem": 0o644, "server.pem": 0o644} {
			fi, err := os.Stat(filepath.Join(dir, name))
			if err != nil || fi.Mode().Perm() != want {
				t.Errorf("%s: %v %v, want %v", name, err, fi.Mode().Perm(), want)
			}
		}
		if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
			t.Errorf("dir mode %v", fi.Mode().Perm())
		}
	}
	// Keys are PKCS#8.
	for _, name := range []string{"ca.key", "server.key"} {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		if block, _ := pem.Decode(b); block == nil || block.Type != "PRIVATE KEY" {
			t.Errorf("%s is not PKCS#8 PEM", name)
		}
	}
}

// A folder and key left open, by an older version or by hand, are made
// private again: the folder when the server starts, a key when it is
// written.
func TestOpenFolderAndKeyMadePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes; tlsauto_windows_test.go checks the access lists")
	}
	fakeMachine(t)
	dir := filepath.Join(t.TempDir(), "tls")
	c := &clock{time.Now()}
	newAuto(t, dir, c)
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Join(dir, "server.key"), 0o644)
	// A new name: a new server certificate and key.
	if m := newAuto(t, dir, c, "10.9.8.7"); !m.Covers("10.9.8.7") {
		t.Fatal("no new certificate")
	}
	for name, want := range map[string]os.FileMode{"": 0o700, "server.key": 0o600, "ca.key": 0o600} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%q: %v, want %v", name, err, want)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestHandshake(t *testing.T) {
	fakeMachine(t)
	m := newAuto(t, t.TempDir(), &clock{time.Now()}, "siem.example.com")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", m.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.(*tls.Conn).Handshake()
				io.WriteString(c, "ok")
				c.Close()
			}()
		}
	}()
	dial := func(cfg *tls.Config) error {
		c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err == nil {
			c.Close()
		}
		return err
	}
	if err := dial(&tls.Config{RootCAs: caPool(t, m), ServerName: "siem.example.com"}); err != nil {
		t.Errorf("client trusting the CA: %v", err)
	}
	if err := dial(&tls.Config{ServerName: "siem.example.com"}); err == nil {
		t.Error("client without the CA connected")
	}
	if err := dial(&tls.Config{RootCAs: caPool(t, m), ServerName: "siem.example.com", MaxVersion: tls.VersionTLS11}); err == nil {
		t.Error("TLS 1.1 accepted")
	}
}

func TestRestartReusesCAAndCertificate(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	c := &clock{time.Now()}
	m1 := newAuto(t, dir, c, "siem.example.com")
	m2 := newAuto(t, dir, c, "siem.example.com")
	if m1.Fingerprint() != m2.Fingerprint() || m1.Leaf().SerialNumber.Cmp(m2.Leaf().SerialNumber) != 0 {
		t.Error("a restart made a new CA or certificate")
	}
	// A new name in the config: a new certificate from the same CA.
	m3 := newAuto(t, dir, c, "siem.example.com", "siem.corp.lan")
	if m3.Fingerprint() != m1.Fingerprint() || m3.Leaf().SerialNumber.Cmp(m1.Leaf().SerialNumber) == 0 || !m3.Covers("siem.corp.lan") {
		t.Error("new name not added with the same CA")
	}
	// The name taken out again: it leaves the certificate, the CA stays.
	m5 := newAuto(t, dir, c, "siem.example.com")
	if m5.Fingerprint() != m1.Fingerprint() || m5.Covers("siem.corp.lan") || !m5.Covers("siem.example.com") {
		t.Errorf("removed name still covered, or a new CA: %v", certNames(m5.Leaf()))
	}
	// One the CA may not sign is left out, and said so; the rest still
	// verify.
	m4 := newAuto(t, dir, c, "siem.example.com", "alias.example.com", "203.0.113.9")
	if m4.Covers("alias.example.com") || m4.Covers("203.0.113.9") || !slices.Equal(m4.Outside(), []string{"alias.example.com", "203.0.113.9"}) {
		t.Errorf("outside names: %v, certificate %v", m4.Outside(), certNames(m4.Leaf()))
	}
	if _, err := m4.Leaf().Verify(x509.VerifyOptions{Roots: caPool(t, m4), DNSName: "siem.example.com", CurrentTime: c.t}); err != nil {
		t.Error(err)
	}
	// A key that does not belong to the CA is refused.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := writeKey(filepath.Join(dir, "ca.key"), other); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Dir: dir}); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("wrong CA key: %v", err)
	}
}

func TestRenewalKeepsCA(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	m := newAuto(t, t.TempDir(), c)
	first := m.Leaf()
	fp := m.Fingerprint()

	c.t = first.NotAfter.Add(-RenewBefore - time.Hour)
	if err := m.Check(); err != nil {
		t.Fatal(err)
	}
	if m.Leaf() != first {
		t.Error("renewed too early")
	}
	c.t = first.NotAfter.Add(-RenewBefore + time.Hour)
	if err := m.Check(); err != nil {
		t.Fatal(err)
	}
	renewed := m.Leaf()
	if renewed == first || !renewed.NotAfter.After(first.NotAfter) || m.Fingerprint() != fp {
		t.Errorf("not renewed with the same CA: %v -> %v", first.NotAfter, renewed.NotAfter)
	}
	if _, err := renewed.Verify(x509.VerifyOptions{Roots: caPool(t, m), DNSName: "ws-test", CurrentTime: c.t}); err != nil {
		t.Error(err)
	}
	// A restart after the old certificate is due also renews it.
	c.t = renewed.NotAfter.Add(-time.Hour)
	m2, err := New(Options{Dir: m.opts.Dir, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	if !m2.Leaf().NotAfter.After(renewed.NotAfter) {
		t.Error("restart served a certificate about to expire")
	}
}

func TestEnsureName(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	c := &clock{time.Now()}
	m := newAuto(t, dir, c)
	before := m.Leaf()
	if err := m.EnsureName("ws-test"); err != nil || m.Leaf() != before {
		t.Errorf("a covered name made a new certificate: %v", err)
	}
	if err := m.EnsureName("0.0.0.0"); err != nil || m.Leaf() != before {
		t.Errorf("0.0.0.0: %v", err)
	}
	if err := m.EnsureName("bad name"); err == nil {
		t.Error("bad name accepted")
	}
	if err := m.EnsureName("192.168.1.20"); err != nil {
		t.Fatal(err)
	}
	if !m.Covers("192.168.1.20") || !m.Covers("ws-test") || m.Leaf() == before {
		t.Error("192.168.1.20 not added")
	}
	if err := m.EnsureName("SIEM.Corp.Local"); err != nil || !m.Covers("siem.corp.local") {
		t.Errorf("name not added: %v", err)
	}
	if _, err := m.Leaf().Verify(x509.VerifyOptions{Roots: caPool(t, m), DNSName: "192.168.1.20"}); err != nil {
		t.Error(err)
	}
	// Kept across restarts.
	m2 := newAuto(t, dir, c)
	if !m2.Covers("192.168.1.20") || !m2.Covers("siem.corp.local") {
		t.Errorf("added names lost on restart: %v", certNames(m2.Leaf()))
	}
	// Only the latest names are kept.
	for i := 0; i < maxAddedNames+5; i++ {
		if err := m2.EnsureName("host" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".lan"); err != nil {
			t.Fatal(err)
		}
	}
	if len(m2.added) != maxAddedNames || m2.Covers("192.168.1.20") {
		t.Errorf("%d names kept", len(m2.added))
	}
	// A machine name is not lost by trimming.
	if !m2.Covers("10.1.2.3") {
		t.Error("machine address dropped")
	}
}

// TestRefreshTakesNamesAddedElsewhere checks that a Manager made for new
// settings takes in the names the Manager in use added since (a restart
// prepares one before it stops the other), and does not lose them when it
// adds one of its own.
func TestRefreshTakesNamesAddedElsewhere(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	c := &clock{time.Now()}
	cur := newAuto(t, dir, c)
	next := newAuto(t, dir, c, "extra.example.lan")
	if err := cur.EnsureName("10.9.8.7"); err != nil || !cur.Covers("10.9.8.7") {
		t.Fatalf("EnsureName: %v", err)
	}
	if next.Covers("10.9.8.7") {
		t.Fatal("the other Manager already covers it")
	}
	before := next.Leaf()
	if err := next.Refresh(); err != nil {
		t.Fatal(err)
	}
	if !next.Covers("10.9.8.7") || !next.Covers("extra.example.lan") || next.Leaf() == before {
		t.Errorf("after Refresh: %v", certNames(next.Leaf()))
	}
	// Nothing new: the same certificate.
	before = next.Leaf()
	if err := next.Refresh(); err != nil || next.Leaf() != before {
		t.Errorf("a second Refresh made a new certificate: %v", err)
	}
	// Its own EnsureName keeps the other's names in names.txt.
	if err := next.EnsureName("192.168.7.7"); err != nil {
		t.Fatal(err)
	}
	if again := newAuto(t, dir, c, "extra.example.lan"); !again.Covers("10.9.8.7") || !again.Covers("192.168.7.7") {
		t.Errorf("names.txt lost names: %v", certNames(again.Leaf()))
	}
	// Files mode has nothing to refresh.
	if err := (&Manager{opts: Options{CertFile: "x", KeyFile: "y"}}).Refresh(); err != nil {
		t.Error(err)
	}
}

// TestCANameConstraints checks that Signalith's CA can only vouch for
// this server: names it was made with, private names and private
// addresses. A certificate it signed for another website fails to
// verify, so a stolen ca.key cannot be used against other sites.
func TestCANameConstraints(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	c := &clock{time.Now()}
	m := newAuto(t, dir, c, "siem.example.com", "198.51.100.7")
	ca := m.ca
	if !slices.Contains(ca.PermittedDNSDomains, "siem.example.com") || !slices.Contains(ca.PermittedDNSDomains, "ws-test") ||
		!slices.Contains(ca.PermittedDNSDomains, "home.arpa") || !ca.PermittedDNSDomainsCritical {
		t.Errorf("DNS constraints %v", ca.PermittedDNSDomains)
	}
	// A certificate signed with the CA's key for any name, the way a
	// stolen key would be used.
	forge := func(name string) *x509.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: serial(), NotBefore: c.t.Add(-time.Hour), NotAfter: c.t.Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		} else {
			tmpl.DNSNames = []string{name}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca, key.Public(), m.caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		return leaf
	}
	pool := caPool(t, m)
	for name, ok := range map[string]bool{
		"siem.example.com": true, "ws-test": true, "siem.corp.local": true, "nas.home.arpa": true,
		// Not the names under this server's own public ones.
		"api.siem.example.com": false, "x.ws-test": false,
		"192.168.1.20": true, "10.9.8.7": true, "100.101.102.103": true, "fd00::5": true, "198.51.100.7": true, "127.0.0.1": true,
		"www.bank.example": false, "example.com": false, "login.microsoftonline.com": false, "8.8.8.8": false, "198.51.100.8": false, "2001:db8::1": false,
	} {
		_, err := forge(name).Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: c.t})
		if (err == nil) != ok {
			t.Errorf("%s: verify error %v, want allowed %v", name, err, ok)
		}
		if got := m.CanCover(name) == nil; got != ok {
			t.Errorf("CanCover(%s) = %v, want %v", name, got, ok)
		}
	}
	// EnsureName refuses another site's name, saying what to use, and
	// keeps nothing.
	err := m.EnsureName("www.bank.example")
	if err == nil || !strings.Contains(err.Error(), "can't include www.bank.example") || !strings.Contains(err.Error(), "(198.51.100.7, 10.1.2.3, siem.example.com, ws-test)") ||
		strings.Contains(err.Error(), "127.0.0.1") || !strings.Contains(err.Error(), "docs/https.md") {
		t.Errorf("EnsureName: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, namesFile)); strings.Contains(string(b), "bank") {
		t.Errorf("names.txt: %s", b)
	}
	// CanCover changes nothing.
	before := m.Leaf()
	if err := m.CanCover("192.168.7.7"); err != nil || m.Leaf() != before || m.Covers("192.168.7.7") {
		t.Errorf("CanCover changed the certificate: %v", err)
	}
}

// selfSignedPair writes a self-signed certificate for names to dir.
func selfSignedPair(t *testing.T, dir, prefix string, names ...string) (certPath, keyPath string, der []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, prefix+".pem"), filepath.Join(dir, prefix+".key")
	if err := writeFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeKey(keyPath, key); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, der
}

func TestFilesModeReloads(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, derA := selfSignedPair(t, dir, "a", "siem.example.com")
	m, err := New(Options{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if m.LocalCA() || m.PublicCA() || !m.Covers("siem.example.com") || m.CAPath() != "" {
		t.Errorf("files mode: local %v public %v", m.LocalCA(), m.PublicCA())
	}
	// A self-signed certificate is its own CA, so agents get it.
	if ca, err := parseCert(m.CAPEM()); err != nil || string(ca.Raw) != string(derA) || m.Fingerprint() != Fingerprint(derA) {
		t.Errorf("CA = %v", err)
	}
	if err := m.EnsureName("192.168.1.20"); err == nil || !strings.Contains(err.Error(), "siem.example.com") {
		t.Errorf("EnsureName in files mode: %v", err)
	}
	if err := m.Check(); err != nil {
		t.Fatal(err)
	}

	// Renewed files (as certbot would write them) are picked up.
	newCert, newKey, derB := selfSignedPair(t, dir, "b", "siem2.example.com")
	time.Sleep(10 * time.Millisecond) // a different modification time
	copyFile(t, newCert, certPath)
	copyFile(t, newKey, keyPath)
	if err := m.Check(); err != nil {
		t.Fatal(err)
	}
	if !m.Covers("siem2.example.com") || m.Fingerprint() != Fingerprint(derB) {
		t.Error("changed files not loaded")
	}
	served, _ := m.GetCertificate(nil)
	if string(served.Certificate[0]) != string(derB) {
		t.Error("GetCertificate serves the old certificate")
	}

	// A half-written change keeps the working certificate, and is
	// reported once.
	os.WriteFile(keyPath, []byte("not a key"), 0o600)
	if err := m.Check(); err == nil || !strings.Contains(err.Error(), "previous certificate stays in use") {
		t.Errorf("broken key: %v", err)
	}
	if err := m.Check(); err != nil {
		t.Errorf("reported twice: %v", err)
	}
	if !m.Covers("siem2.example.com") {
		t.Error("lost the working certificate")
	}

	// Missing files at startup are an error.
	if _, err := New(Options{CertFile: filepath.Join(dir, "none.pem"), KeyFile: keyPath}); err == nil || !strings.Contains(err.Error(), "server.tls_cert") {
		t.Errorf("missing file: %v", err)
	}
}

func TestFilesModeChainGivesRoot(t *testing.T) {
	fakeMachine(t)
	// A private CA from auto mode stands in for a company CA.
	ca := newAuto(t, t.TempDir(), &clock{time.Now()}, "siem.corp.example")
	dir := t.TempDir()
	leaf, _ := ca.GetCertificate(nil)
	var chain []byte
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})...)
	chain = append(chain, ca.CAPEM()...)
	certPath, keyPath := filepath.Join(dir, "chain.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, chain, 0o644)
	writeKey(keyPath, leaf.PrivateKey.(*ecdsa.PrivateKey))
	m, err := New(Options{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if string(m.CAPEM()) != string(ca.CAPEM()) || m.Fingerprint() != ca.Fingerprint() {
		t.Error("the root at the end of the chain is not offered")
	}
	// Just the server certificate: its CA is unknown.
	os.WriteFile(certPath, chain[:len(chain)-len(ca.CAPEM())], 0o644)
	m, err = New(Options{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if m.CAPEM() != nil || m.Fingerprint() != "" || m.PublicCA() {
		t.Error("an unknown CA was offered")
	}
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"SIEM.Example.com.": "siem.example.com", "[::1]": "::1", "::ffff:10.0.0.1": "10.0.0.1",
		" 192.0.2.1 ": "192.0.2.1", "my_host": "my_host",
	} {
		if got, ok := normalizeName(in); !ok || got != want {
			t.Errorf("normalizeName(%q) = %q %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "a b", "-x.com", "x..com", "fe80::1%eth0", "a/b", strings.Repeat("a", 64) + ".com"} {
		if _, ok := normalizeName(bad); ok {
			t.Errorf("normalizeName(%q) accepted", bad)
		}
	}
}

func TestMachineNames(t *testing.T) {
	names := machineNames()
	for _, want := range []string{"localhost", "127.0.0.1", "::1"} {
		if !slices.Contains(names, want) {
			t.Errorf("%s missing from %v", want, names)
		}
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil && ip.IsLinkLocalUnicast() {
			t.Errorf("link-local %s listed", n)
		}
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
