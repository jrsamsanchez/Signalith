// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package tlsauto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
	"time"
)

// TestCAIsForWebServersOnly checks that a stolen ca.key can only make
// certificates for web servers with this server's names: not ones that
// sign code or email or sign in as a client, and none carrying an email
// address or URI. Both a CA made on first start and one prepared on the
// Security page are checked.
func TestCAIsForWebServersOnly(t *testing.T) {
	m, err := New(Options{Dir: t.TempDir(), Names: []string{"siem.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(ScopeStrict); err != nil {
		t.Fatal(err)
	}
	next, nextKey, err := readPair(m.path(nextDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		ca   *x509.Certificate
		key  any
	}{{"first", m.ca, m.caKey}, {"prepared", next, nextKey}} {
		if !ServerOnly(c.ca) || infoOf(c.ca).AnyUse {
			t.Errorf("%s: not limited to web servers: %v", c.name, c.ca.ExtKeyUsage)
		}
		roots := x509.NewCertPool()
		roots.AddCert(c.ca)
		issue := func(usage []x509.ExtKeyUsage, edit func(*x509.Certificate)) *x509.Certificate {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "siem.example.com"}, DNSNames: []string{"siem.example.com"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: usage}
			if edit != nil {
				edit(tmpl)
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, key.Public(), c.key)
			if err != nil {
				t.Fatal(err)
			}
			leaf, _ := x509.ParseCertificate(der)
			return leaf
		}
		verify := func(leaf *x509.Certificate, usage x509.ExtKeyUsage) error {
			_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "siem.example.com", KeyUsages: []x509.ExtKeyUsage{usage}})
			return err
		}
		if err := verify(issue([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil), x509.ExtKeyUsageServerAuth); err != nil {
			t.Errorf("%s: server certificate refused: %v", c.name, err)
		}
		for _, u := range []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageTimeStamping} {
			if err := verify(issue([]x509.ExtKeyUsage{u}, nil), u); err == nil {
				t.Errorf("%s: certificate for use %v accepted", c.name, u)
			}
		}
		// No extended key usage means any use; the CA's limit still holds.
		if err := verify(issue(nil, nil), x509.ExtKeyUsageCodeSigning); err == nil {
			t.Errorf("%s: certificate without a usage accepted for code signing", c.name)
		}
		email := issue([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, func(c *x509.Certificate) { c.EmailAddresses = []string{"ceo@bank.example"} })
		if err := verify(email, x509.ExtKeyUsageServerAuth); err == nil {
			t.Errorf("%s: certificate with an email address accepted", c.name)
		}
		uri, _ := url.Parse("spiffe://bank.example/payments")
		withURI := issue([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, func(c *x509.Certificate) { c.URIs = []*url.URL{uri} })
		if err := verify(withURI, x509.ExtKeyUsageServerAuth); err == nil {
			t.Errorf("%s: certificate with a URI accepted", c.name)
		}
	}
	// The certificate Signalith serves still verifies, by name.
	roots := x509.NewCertPool()
	roots.AddCert(m.ca)
	if _, err := m.Leaf().Verify(x509.VerifyOptions{Roots: roots, DNSName: "siem.example.com"}); err != nil {
		t.Errorf("served certificate: %v", err)
	}
	// A CA made by an earlier version, without the limit, is told apart.
	old := *m.ca
	old.ExtKeyUsage = nil
	if ServerOnly(&old) || !infoOf(&old).AnyUse {
		t.Error("a CA without the limit counts as limited")
	}
}
