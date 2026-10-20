// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package tlsauto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func csrFor(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "siem-c"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func keyPEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestSignCSRAndSeed(t *testing.T) {
	cluster, err := New(Options{Dir: t.TempDir(), Names: []string{"siem.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafPEM, err := SignCSR(cluster.ca, cluster.caKey, csrFor(t, key), []string{"SIEM-C.internal", "www.example.org", "siem-c", "siem-c.internal", "10.0.0.7"}, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := parseCert(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(leaf.DNSNames, []string{"siem-c.internal"}) || len(leaf.IPAddresses) != 1 || leaf.CheckSignatureFrom(cluster.ca) != nil || !leaf.NotAfter.After(now.Add(LeafValidity-2*time.Hour)) {
		t.Fatalf("leaf %v %v", leaf.DNSNames, leaf.NotAfter)
	}
	if slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) || leaf.IsCA {
		t.Error("the leaf can do more than serve HTTPS")
	}
	// Names the certificate authority may not sign are refused.
	if _, err := SignCSR(cluster.ca, cluster.caKey, csrFor(t, key), []string{"www.example.org"}, now); err == nil {
		t.Error("signed a name outside the certificate authority's")
	}
	// A request that is not one, or with a weak key.
	if _, err := SignCSR(cluster.ca, cluster.caKey, []byte("nope"), []string{"siem-c.internal"}, now); err == nil {
		t.Error("signed a request that is not one")
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := SignCSR(cluster.ca, cluster.caKey, csrFor(t, weak), []string{"siem-c.internal"}, now); err == nil {
		t.Error("signed a 1024-bit RSA key")
	}

	// A fresh install made its own certificate authority: seeding retires
	// it and the server starts detached on the cluster's.
	dir := t.TempDir()
	own, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	ownFP := own.Fingerprint()
	caPEM := cluster.CAPEM()
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := SeedCluster(dir, caPEM, leafPEM, keyPEM(t, other), now); err == nil {
		t.Fatal("seeded a certificate with another key")
	}
	if err := SeedCluster(dir, caPEM, leafPEM, keyPEM(t, key), now); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(dir, caKeyFile)) {
		t.Error("the server's own ca.key is still there")
	}
	if readMark(dir) != cluster.Fingerprint() {
		t.Errorf("mark %q", readMark(dir))
	}
	for _, f := range SeedFiles(dir) {
		if !exists(f) {
			t.Errorf("%s was not written", f)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, keyFile)); err == nil && fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("server.key mode %v", fi.Mode())
	}
	m, err := New(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if m.Store() != KindCluster || m.Fingerprint() != cluster.Fingerprint() {
		t.Fatalf("store %s, CA %s", m.Store(), m.Fingerprint())
	}
	if got := m.Leaf(); got == nil || !slices.Equal(got.Raw, leaf.Raw) {
		t.Error("the server does not serve the seeded certificate")
	}
	if r := m.Retired(); len(r) != 1 || r[0].Fingerprint != ownFP {
		t.Errorf("retired %+v, want %s", r, ownFP)
	}
	// A certificate from another certificate authority is refused.
	stranger, _ := New(Options{Dir: t.TempDir()})
	if err := SeedCluster(t.TempDir(), stranger.CAPEM(), leafPEM, keyPEM(t, key), now); err == nil {
		t.Error("seeded a certificate from another certificate authority")
	}
}
