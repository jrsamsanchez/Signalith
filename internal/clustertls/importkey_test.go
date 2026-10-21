// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustertls

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// resetKey does what signalith cluster reset-key does to the shared
// settings: a new cluster key signs every document again, and the values
// sealed with the old one are emptied. It returns a server on the new key.
func (e *env) resetKey(name string) *TLS {
	e.t.Helper()
	ctx := context.Background()
	docs, _, err := shared.ReadAll(ctx, e.cl, prefix)
	if err != nil {
		e.t.Fatal(err)
	}
	k, err := shared.NewClusterKey()
	if err != nil {
		e.t.Fatal(err)
	}
	var rev int64
	for _, d := range docs {
		rev = max(rev, d.Envelope.Rev)
	}
	at := time.Now().UTC().Format(time.RFC3339)
	if _, err := shared.Resign(ctx, e.cl, prefix, docs, k, rev+1, "admin", name, at, "n_"+name,
		shared.KeyringMember{Name: name, AddedAt: at, AddedBy: "admin"}); err != nil {
		e.t.Fatal(err)
	}
	e.key = k
	tl, _ := e.server(name)
	return tl
}

// After reset-key the cluster's certificate authority has no key: only
// its own key, with its own certificate, gives it back, and servers can
// issue certificates again.
func TestImportKeyAfterReset(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now().Add(-time.Hour))
	ta, _ := e.server("siem-a")
	if err := ta.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, []string{"agents.lan"}); err != nil {
		t.Fatal(err)
	}
	tl := e.resetKey("siem-a")
	b, ok := tl.Get()
	if !ok || !b.KeyLost() || !SameFingerprint(b.CASHA256, ca.fp) {
		t.Fatalf("after reset-key: ok %v lost %v", ok, b.KeyLost())
	}
	if r := BuildReport(ReportInput{Body: b}); r.CA == nil || !r.CA.KeyLost {
		t.Error("the report does not say the key was lost")
	}
	if _, _, err := tl.Store().Load(); !errors.Is(err, ErrKeyNotSealed) {
		t.Fatalf("load without a key: %v", err)
	}

	// Another CA's key: refused.
	other := makeCA(t, "b", time.Now())
	if _, err := tl.ImportKey(ctx, "admin", nil, other.key); !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("wrong key: %v", err)
	}
	// The right key with another certificate made from it (another
	// fingerprint): refused.
	tmpl := *ca.cert
	tmpl.SerialNumber = big.NewInt(42)
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, ca.key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	twin := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if _, err := tl.ImportKey(ctx, "admin", twin, ca.key); err == nil {
		t.Error("a key given with a certificate of another fingerprint was taken")
	}
	if b, _ := tl.Get(); !b.KeyLost() {
		t.Fatal("a refused import changed the document")
	}

	// The right one, with its certificate.
	done, err := tl.ImportKey(ctx, "admin", ca.pem, ca.key)
	if err != nil || !done {
		t.Fatalf("import: %v %v", done, err)
	}
	if done, err := tl.ImportKey(ctx, "admin", ca.pem, ca.key); err != nil || done {
		t.Errorf("again: %v %v", done, err)
	}
	b, _ = tl.Get()
	if b.KeyLost() || !SameFingerprint(b.CASHA256, ca.fp) {
		t.Fatal("the key is not back")
	}
	// Sealed with the new cluster key, bound to the fingerprint.
	other2 := *b
	other2.CACertPEM, other2.CASHA256 = string(other.pem), other.fp
	if _, _, err := tl.open(&other2); err == nil {
		t.Error("the imported key opened under another certificate")
	}
	// Another server reads it and renews from it.
	tb, _ := e.server("siem-b")
	m, err := tlsauto.New(tlsauto.Options{Dir: filepath.Join(t.TempDir(), "tls"), Store: tb.Store()})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := m.Leaf().Verify(x509.VerifyOptions{Roots: pool, DNSName: "agents.lan"}); err != nil {
		t.Errorf("certificate after import: %v", err)
	}
}

// A key is never taken when the cluster has no certificate authority.
func TestImportKeyNoCA(t *testing.T) {
	e := newEnv(t)
	tl, _ := e.server("siem-a")
	ca := makeCA(t, "a", time.Now())
	if _, err := tl.ImportKey(context.Background(), "admin", nil, ca.key); err == nil {
		t.Error("a key imported with no certificate authority published")
	}
}

func TestParseKey(t *testing.T) {
	ca := makeCA(t, "a", time.Now())
	der, _ := x509.MarshalPKCS8PrivateKey(ca.key)
	k, err := ParseKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil || !samePublicKey(k.Public(), ca.key.Public()) {
		t.Errorf("pkcs8: %v", err)
	}
	if _, err := ParseKey(ca.pem); err == nil {
		t.Error("a certificate read as a key")
	}
	if _, err := ParseKey([]byte("nothing")); err == nil {
		t.Error("text read as a key")
	}
}
