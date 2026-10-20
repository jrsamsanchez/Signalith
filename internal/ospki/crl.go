// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ospki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"time"
)

// CRLFile is the name of the revocation list OpenSearch checks client
// certificates against (plugins.security.ssl.http.crl.file_path), in the
// Docker quick start's opensearch-crl volume.
const CRLFile = "crl.pem"

// MakeCRL signs a revocation list under ca naming serials, numbered
// number. It is valid from now until the certificate authority expires:
// OpenSearch refuses every client certificate once the list it checks is
// past its next update, so the list never asks for one sooner.
func MakeCRL(ca *Pair, serials []*big.Int, number *big.Int, now time.Time) ([]byte, error) {
	if ca == nil || ca.Key == nil {
		return nil, ErrNoCAKey
	}
	tmpl := &x509.RevocationList{
		Number:     number,
		ThisUpdate: now.Add(-5 * time.Minute).UTC(),
		NextUpdate: ca.Cert.NotAfter.UTC(),
	}
	for _, s := range serials {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: now.UTC()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.Cert, ca.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

// ParseCRL reads the revocation list in b, PEM or DER, and checks that
// ca signed it and that it is in force at now.
func ParseCRL(b []byte, ca *x509.Certificate, now time.Time) (*x509.RevocationList, error) {
	if block, _ := pem.Decode(b); block != nil {
		if block.Type != "X509 CRL" {
			return nil, fmt.Errorf("it holds a %s, not a revocation list (X509 CRL)", block.Type)
		}
		b = block.Bytes
	}
	if len(b) == 0 {
		return nil, errors.New("it is empty")
	}
	l, err := x509.ParseRevocationList(b)
	if err != nil {
		return nil, fmt.Errorf("it cannot be read: %w", err)
	}
	if ca == nil {
		return l, nil
	}
	if err := l.CheckSignatureFrom(ca); err != nil {
		return nil, errors.New("it is not signed by OpenSearch's certificate authority (opensearch.ca_file)")
	}
	if !l.NextUpdate.IsZero() && !now.Before(l.NextUpdate) {
		return nil, fmt.Errorf("it expired on %s", l.NextUpdate.Format(time.DateOnly))
	}
	if now.Add(5 * time.Minute).Before(l.ThisUpdate) {
		return nil, fmt.Errorf("it starts on %s, later than this computer's clock", l.ThisUpdate.Format(time.RFC3339))
	}
	return l, nil
}

// ReadCRL reads the revocation list in the file path, as ParseCRL.
func ReadCRL(path string, ca *x509.Certificate, now time.Time) (*x509.RevocationList, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCRL(b, ca, now)
}

// CRLSerials returns the serial numbers l names, in hex, sorted.
func CRLSerials(l *x509.RevocationList) []string {
	out := make([]string, 0, len(l.RevokedCertificateEntries))
	for _, e := range l.RevokedCertificateEntries {
		out = append(out, e.SerialNumber.Text(16))
	}
	slices.Sort(out)
	return out
}
