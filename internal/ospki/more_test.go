package ospki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func ecKeyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pemOf("PRIVATE KEY", der)
}

func TestRevocationLists(t *testing.T) {
	smallKeys(t)
	now := time.Now()
	ca, err := NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MakeCRL(nil, nil, big.NewInt(1), now); !errors.Is(err, ErrNoCAKey) {
		t.Errorf("no CA = %v", err)
	}
	if _, err := MakeCRL(&Pair{Cert: ca.Cert}, nil, big.NewInt(1), now); !errors.Is(err, ErrNoCAKey) {
		t.Errorf("no CA key = %v", err)
	}
	b, err := MakeCRL(ca, []*big.Int{big.NewInt(0x2b), big.NewInt(0x1a)}, big.NewInt(7), now)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseCRL(b, ca.Cert, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := CRLSerials(l); !slices.Equal(got, []string{"1a", "2b"}) || l.Number.Int64() != 7 || !l.NextUpdate.Equal(ca.Cert.NotAfter) {
		t.Errorf("list = %v #%v until %v", got, l.Number, l.NextUpdate)
	}
	// DER works too, and without a CA nothing is checked.
	block, _ := pem.Decode(b)
	if l, err := ParseCRL(block.Bytes, nil, now.Add(2*Validity)); err != nil || len(l.RevokedCertificateEntries) != 2 {
		t.Errorf("DER, no CA = %v", err)
	}

	path := filepath.Join(t.TempDir(), CRLFile)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := ReadCRL(path, ca.Cert, now); err != nil || len(CRLSerials(l)) != 2 {
		t.Errorf("ReadCRL = %v", err)
	}
	if _, err := ReadCRL(path+".gone", ca.Cert, now); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing = %v", err)
	}

	for name, c := range map[string]struct {
		b    []byte
		ca   *x509.Certificate
		at   time.Time
		want string
	}{
		"certificate": {ca.CertPEM(), ca.Cert, now, "holds a CERTIFICATE"},
		"empty":       {nil, ca.Cert, now, "empty"},
		"junk":        {[]byte("junk"), ca.Cert, now, "cannot be read"},
		"another CA":  {b, other.Cert, now, "not signed by"},
		"expired":     {b, ca.Cert, ca.Cert.NotAfter, "expired on"},
		"future":      {b, ca.Cert, now.Add(-time.Hour), "later than this computer's clock"},
	} {
		if _, err := ParseCRL(c.b, c.ca, c.at); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestClientRequests(t *testing.T) {
	smallKeys(t)
	now := time.Now()
	ca, err := NewCA(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := IssueClient(ca, "someone", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if p, err := PairFromPEM(ca.CertPEM(), ca.KeyPEM()); err != nil || !p.Cert.Equal(ca.Cert) || !p.Key.Equal(ca.Key) {
		t.Errorf("PairFromPEM = %v", err)
	}
	for name, c := range map[string]struct {
		cert, key []byte
		want      string
	}{
		"bad cert":    {[]byte("x"), ca.KeyPEM(), "the CA certificate"},
		"leaf":        {leaf.CertPEM(), leaf.KeyPEM(), "not a CA certificate"},
		"bad key":     {ca.CertPEM(), []byte("x"), "the CA key"},
		"another key": {ca.CertPEM(), other.KeyPEM(), "not the CA certificate's key"},
	} {
		if _, err := PairFromPEM(c.cert, c.key); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}

	keyPEM, csrPEM, err := NewClientRequest("ignored-name")
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	c, err := SignClientRequest(ca, "signalith-server-a", csrPEM, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "signalith-server-a" || !key.PublicKey.Equal(c.PublicKey) || c.CheckSignatureFrom(ca.Cert) != nil ||
		!slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || c.NotAfter.After(now.Add(time.Hour)) {
		t.Errorf("signed %+v", c.Subject)
	}

	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, ek)
	block, _ := pem.Decode(csrPEM)
	tampered := slices.Clone(block.Bytes)
	tampered[len(tampered)-1] ^= 0xff
	for name, c := range map[string]struct {
		ca   *Pair
		cn   string
		csr  []byte
		want string
	}{
		"no name":       {ca, "", csrPEM, "needs a name"},
		"no PEM":        {ca, "x", []byte("x"), "no PEM certificate request"},
		"wrong PEM":     {ca, "x", ca.CertPEM(), "no PEM certificate request"},
		"junk":          {ca, "x", pemOf("CERTIFICATE REQUEST", []byte("junk")), "asn1"},
		"bad signature": {ca, "x", pemOf("CERTIFICATE REQUEST", tampered), "signature"},
		"EC key":        {ca, "x", pemOf("CERTIFICATE REQUEST", ecCSR), "RSA key of at least 2048"},
		"no CA key":     {&Pair{Cert: ca.Cert}, "x", csrPEM, ErrNoCAKey.Error()},
	} {
		if _, err := SignClientRequest(c.ca, c.cn, c.csr, now, time.Hour); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestIssuingEdges(t *testing.T) {
	smallKeys(t)
	now := time.Now()
	ca, err := NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IssueClient(ca, "", now, time.Hour); err == nil {
		t.Error("a nameless client certificate was made")
	}
	if _, err := IssueClient(nil, "x", now, time.Hour); !errors.Is(err, ErrNoCAKey) {
		t.Errorf("no CA = %v", err)
	}
	if _, err := IssueNode(ca, "signalith", nil, now); err == nil {
		t.Error("a node took Signalith's name")
	}
	// No start given: now. A start before the CA's: the CA's.
	p, err := IssueClient(ca, "x", time.Time{}, time.Hour)
	if err != nil || time.Until(p.Cert.NotAfter) > time.Hour || time.Until(p.Cert.NotAfter) < 50*time.Minute {
		t.Errorf("now by default = %v %v", p, err)
	}
	early := ca.Cert.NotBefore.Add(-time.Hour)
	if p, err := IssueClient(ca, "x", early, 4*time.Hour); err != nil || !p.Cert.NotBefore.Equal(ca.Cert.NotBefore) {
		t.Errorf("early = %v %v", p, err)
	}

	if err := CheckNames([]string{"search-2.example.com", "10.0.0.5", "[::1]"}); err != nil {
		t.Errorf("good names = %v", err)
	}
	for _, bad := range []string{"bad name", "a..b", "-a.example", strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 130)} {
		if err := CheckNames([]string{bad}); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
	if NamesOf(nil) != nil || NamesOf(&Pair{}) != nil {
		t.Error("names of nothing")
	}
	if _, err := New(Options{Node: "opensearch", Names: []string{"bad name"}}); err == nil {
		t.Error("New took a bad name")
	}
}

func TestReadPairAndKeys(t *testing.T) {
	smallKeys(t)
	now := time.Now()
	ca, err := NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := IssueClient(ca, "x", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("c.pem", leaf.CertPEM())
	write("k.pem", leaf.KeyPEM())
	write("bad.pem", []byte("x"))
	write("ec.pem", ecKeyPEM(t))
	write("junk-key.pem", pemOf("PRIVATE KEY", []byte("junk")))

	if p, err := ReadPair(dir, "c.pem", "k.pem"); err != nil || !p.Key.Equal(leaf.Key) || !p.Cert.Equal(leaf.Cert) {
		t.Errorf("ReadPair = %v", err)
	}
	if p, err := ReadPair(dir, "c.pem", ""); err != nil || p.Key != nil {
		t.Errorf("certificate only = %v", err)
	}
	for _, c := range []struct{ cert, key, want string }{
		{"gone.pem", "", "gone.pem is missing"},
		{"bad.pem", "", "bad.pem: no PEM certificate"},
		{"c.pem", "gone.pem", "gone.pem is missing"},
		{"c.pem", "bad.pem", "bad.pem: no PKCS#8 key"},
		{"c.pem", "ec.pem", "not an RSA key"},
		{"c.pem", "junk-key.pem", "junk-key.pem"},
	} {
		if _, err := ReadPair(dir, c.cert, c.key); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s/%s: %v, want %q", c.cert, c.key, err, c.want)
		}
	}
	if _, err := ReadPair(dir, "gone.pem", ""); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing is not ErrNotExist: %v", err)
	}
	// A folder where a file belongs cannot be read, and is not missing.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPair(dir, "sub", ""); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a folder as the certificate = %v", err)
	}

	// LoadCA with a broken certificate or key.
	cadir := t.TempDir()
	os.WriteFile(filepath.Join(cadir, RootCAFile), []byte("x"), 0o600)
	if _, err := LoadCA(cadir); err == nil || !strings.Contains(err.Error(), RootCAFile) {
		t.Errorf("bad CA cert = %v", err)
	}
	os.WriteFile(filepath.Join(cadir, RootCAFile), ca.CertPEM(), 0o600)
	os.WriteFile(filepath.Join(cadir, RootCAKeyFile), []byte("x"), 0o600)
	if _, err := LoadCA(cadir); err == nil || !strings.Contains(err.Error(), RootCAKeyFile) {
		t.Errorf("bad CA key = %v", err)
	}

	// CheckPair: a certificate that expires within the margin, and the
	// error's parts.
	write("ca.pem", ca.CertPEM())
	err = CheckPair(dir, "c.pem", "k.pem", "x", ca.Cert, now, 24*time.Hour)
	var ce *CheckError
	if !errors.As(err, &ce) || ce.File != "c.pem" || !strings.Contains(err.Error(), "expires on") || errors.Unwrap(err) != ce.Err {
		t.Errorf("expiring = %#v", err)
	}
	if err := CheckPair(dir, "c.pem", "k.pem", "x", ca.Cert, now, 0); err != nil {
		t.Errorf("good pair = %v", err)
	}
	if err := CheckPair(dir, "bad.pem", "k.pem", "x", ca.Cert, now, 0); !errors.As(err, &ce) || ce.File != "bad.pem" {
		t.Errorf("bad cert = %v", err)
	}
}
