package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

func TestTLSFactsFromAutoCA(t *testing.T) {
	if TLSFactsFrom(nil, nil) != nil || SeenFrom(context.Background(), nil) != nil {
		t.Error("no manager, yet facts")
	}
	m, err := tlsauto.New(tlsauto.Options{Dir: t.TempDir(), Names: []string{"siem.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	c := loadConfig(t, httpsAuto)
	f := TLSFactsFrom(m, c)
	if f.Mode != config.TLSAuto || f.Leaf == nil || f.Leaf.SHA1 || f.CA == nil {
		t.Fatalf("auto = %+v", f)
	}
	if _, ok := f.WouldCover[tlsauto.ScopeStrict]; !ok {
		t.Errorf("would cover = %v", f.WouldCover)
	}
	if seen := SeenFrom(context.Background(), m); seen == nil {
		t.Error("seen names of a local CA are nil")
	}
	if len(ownAddrs()) == 0 {
		t.Error("no own addresses")
	}
}

func TestTLSFactsFromFiles(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "siem.example.com"},
		DNSNames: []string{"siem.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := tlsauto.New(tlsauto.Options{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	c := loadConfig(t, "server:\n  listen: 0.0.0.0:8080\n  public_url: https://siem.example.com:8080\n  tls_cert: "+certFile+"\n  tls_key: "+keyFile+"\n  tls:\n    mode: files\n")
	f := TLSFactsFrom(m, c)
	if f.Mode != config.TLSFiles || f.PublicHost != "siem.example.com" || !f.CoversPublicHost || f.Leaf == nil || f.Leaf.RSABits != 0 {
		t.Errorf("files = %+v", f)
	}
	if f.CertFile != certFile || f.KeyFile != keyFile {
		t.Errorf("files = %q %q", f.CertFile, f.KeyFile)
	}
	if SeenFrom(context.Background(), m) != nil {
		t.Error("seen names without a local CA")
	}
}
