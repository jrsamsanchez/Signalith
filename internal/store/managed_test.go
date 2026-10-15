package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a self-signed client certificate for cn, lasting
// until notAfter, and its key.
func writePair(t *testing.T, dir, cn string, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: notAfter.Add(-48 * time.Hour), NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, k := filepath.Join(dir, cn+".pem"), filepath.Join(dir, cn+"-key.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	return cert, k
}

func presented(t *testing.T, cfg Config) string {
	t.Helper()
	tr, err := Transport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	get := tr.TLSClientConfig.GetClientCertificate
	if get == nil {
		return ""
	}
	c, err := get(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Certificate) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestManagedClientCertificate(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePair(t, dir, "signalith", time.Now().Add(24*time.Hour))
	mcert, mkey := filepath.Join(dir, "m.pem"), filepath.Join(dir, "m-key.pem")
	cfg := Config{URL: "https://os:9200", CertFile: cert, KeyFile: key, ManagedCertFile: mcert, ManagedKeyFile: mkey}
	// None issued yet: the configured one.
	if got := presented(t, cfg); got != "signalith" {
		t.Fatalf("presented %q", got)
	}
	// The cluster's, once there, without a new transport.
	tr, _ := Transport(cfg)
	get := tr.TLSClientConfig.GetClientCertificate
	c, k := writePair(t, dir, "signalith-server-a", time.Now().Add(24*time.Hour))
	os.Rename(k, mkey)
	os.Rename(c, mcert)
	if cc, err := get(&tls.CertificateRequestInfo{}); err != nil || cc.Leaf == nil || cc.Leaf.Subject.CommonName != "signalith-server-a" {
		t.Fatalf("presented %v, %v", cc, err)
	}
	// An expired one falls back to the configured one.
	c, k = writePair(t, dir, "signalith-server-old", time.Now().Add(-time.Hour))
	os.Rename(k, mkey)
	os.Rename(c, mcert)
	if got := presented(t, cfg); got != "signalith" {
		t.Fatalf("presented %q with an expired managed certificate", got)
	}
	// With a password and no certificate configured: nothing until the
	// cluster issued one.
	pw := Config{URL: "https://os:9200", Username: "u", ManagedCertFile: filepath.Join(dir, "none.pem"), ManagedKeyFile: filepath.Join(dir, "none-key.pem")}
	if got := presented(t, pw); got != "" {
		t.Fatalf("presented %q", got)
	}
}
