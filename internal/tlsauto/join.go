// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package tlsauto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// A server that joins a cluster with a join token gets its first HTTPS
// certificate from the cluster's certificate authority, signed by the
// server that answers for the key of its own certificate request
// (SignCSR), and starts with the tls folder seeded (SeedCluster): the
// cluster's certificate authority in ca.pem, the cluster mark, and that
// certificate. It then never makes a certificate authority of its own,
// and has nothing to retire once it takes the cluster's at its first
// start.

// SignCSR signs the certificate request csrPEM with the certificate
// authority ca and its key, for the names among names the certificate
// authority may sign (the others are left out), as a server certificate
// valid from now for LeafValidity (or until the certificate authority
// expires). It returns the certificate in PEM.
func SignCSR(ca *x509.Certificate, key crypto.Signer, csrPEM []byte, names []string, now time.Time) ([]byte, error) {
	if ca == nil || key == nil {
		return nil, errors.New("there is no certificate authority key to sign with")
	}
	b, _ := pem.Decode(csrPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the certificate request cannot be read: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the certificate request's signature does not match its key: %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, errors.New("the certificate request's RSA key is shorter than 2048 bits")
		}
	default:
		return nil, errors.New("the certificate request's key is not ECDSA, Ed25519 or RSA")
	}
	var ok []string
	for _, n := range names {
		if n, valid := normalizeName(n); valid && caAllows(ca, n) && !slices.Contains(ok, n) {
			ok = append(ok, n)
		}
	}
	if len(ok) == 0 {
		return nil, fmt.Errorf("the cluster's certificate authority may sign none of the names %v", names)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: ok[0], Organization: []string{"Signalith"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(LeafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, isRSA := csr.PublicKey.(*rsa.PublicKey); isRSA {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if tmpl.NotAfter.After(ca.NotAfter) {
		tmpl.NotAfter = ca.NotAfter
	}
	for _, n := range ok {
		if a, err := netip.ParseAddr(n); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, a.AsSlice())
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// SeedCluster seeds the tls folder dir of a server that joins a cluster:
// the cluster's certificate authority caPEM becomes ca.pem, with the
// cluster mark, so the server never makes one of its own; leafPEM and
// keyPEM (PKCS #8) become its certificate and key. A certificate
// authority of the server's own already in dir (made when the package was
// installed) is retired, without its key. It refuses a folder where a
// change of certificate authority is in progress, and a certificate that
// is not from caPEM or not for keyPEM.
func SeedCluster(dir string, caPEM, leafPEM, keyPEM []byte, now time.Time) error {
	ca, err := parseCert(caPEM)
	if err != nil {
		return fmt.Errorf("the cluster's certificate authority: %w", err)
	}
	leaf, err := parseCert(leafPEM)
	if err != nil {
		return fmt.Errorf("the server's certificate: %w", err)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return errors.New("the server's certificate is not from the cluster's certificate authority")
	}
	key, err := parseKey(keyPEM, "the server's key")
	if err != nil {
		return err
	}
	if !samePublicKey(leaf.PublicKey, key.Public()) {
		return errors.New("the server's certificate is not for its key")
	}
	if err := securefile.MkdirPrivate(dir); err != nil {
		return err
	}
	for _, p := range []string{nextDir, previousDir, journalFile} {
		if exists(filepath.Join(dir, p)) {
			return &StateError{"A change of this server's certificate authority is in progress in " + dir + ". Finish or cancel it on the Security page first."}
		}
	}
	m := &Manager{opts: Options{Dir: dir, Now: func() time.Time { return now }}}
	m.mu.Lock()
	err = m.adoptLocked(ca)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, keyFile), key); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, certFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o644)
}

// SeedFiles lists the files SeedCluster writes in dir, for a caller that
// rolls them back.
func SeedFiles(dir string) []string {
	return []string{filepath.Join(dir, CAFile), filepath.Join(dir, clusterMark), filepath.Join(dir, certFile), filepath.Join(dir, keyFile)}
}
