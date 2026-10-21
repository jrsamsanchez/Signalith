// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustertls

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// ErrKeyNotSealed: the tls document names the cluster's certificate
// authority but holds no key for it. signalith cluster reset-key empties
// it, since a key sealed with the lost cluster key cannot be opened again;
// no server can renew its certificate until an admin gives it back
// (ImportKey).
var ErrKeyNotSealed = errors.New("the tls document holds no key for the cluster's certificate authority " +
	"(it was emptied when the cluster key was reset): give it back with signalith cluster tls import <ca.key>")

// ErrKeyMismatch: the key given is not the cluster certificate
// authority's.
var ErrKeyMismatch = errors.New("this key does not belong to the cluster's certificate authority")

// KeyLost reports whether b names a certificate authority but holds no
// key for it.
func (b *Body) KeyLost() bool { return b.CASHA256 != "" && b.CAKey == "" }

// ImportKey gives the cluster its certificate authority's key again, by
// the user by: key must be the key of the certificate authority the tls
// document names, and certPEM, when not nil, the certificate it came with
// (an export's ca.pem), whose fingerprint must be the document's. It
// seals the key with the active cluster key, bound to the fingerprint, as
// Publish does, so every server can renew its certificate again. It
// reports false when the document already held a key that opens to it,
// and changes nothing then.
func (t *TLS) ImportKey(ctx context.Context, by string, certPEM []byte, key crypto.Signer) (bool, error) {
	h, d, err := t.parts()
	if err != nil {
		return false, err
	}
	if key == nil {
		return false, errors.New("no key to import")
	}
	if err := d.Load(ctx); err != nil {
		return false, err
	}
	b, ok := d.Get()
	if !ok || b.CASHA256 == "" {
		return false, errors.New("the cluster has no certificate authority yet, so there is nothing to give a key to (signalith cluster tls shows it)")
	}
	ca, err := b.Cert()
	if err != nil {
		return false, err
	}
	fp := b.CASHA256
	if err := matchKey(ca, fp, certPEM, key); err != nil {
		return false, err
	}
	if !b.KeyLost() {
		if _, k, err := t.open(b); err == nil && samePublicKey(k.Public(), key.Public()) {
			return false, nil
		}
	}
	k := h.Keys().Active()
	if k == nil {
		return false, errors.New("this server has no cluster key")
	}
	keyPEM, err := marshalKey(key)
	if err != nil {
		return false, err
	}
	sealed, err := k.SecretsKey().Seal(keyField(fp), keyPEM)
	if err != nil {
		return false, err
	}
	_, err = d.Mutate(ctx, by, func(cur *Body) error {
		// The certificate authority must still be the one checked.
		if !SameFingerprint(cur.CASHA256, fp) {
			return ErrOtherCA
		}
		cur.CAKey = sealed
		return nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

// matchKey checks that key is the key of ca, whose fingerprint is fp,
// and that certPEM, when given, is ca itself.
func matchKey(ca *x509.Certificate, fp string, certPEM []byte, key crypto.Signer) error {
	if !SameFingerprint(tlsauto.Fingerprint(ca.Raw), fp) {
		return errors.New("the tls document's fingerprint does not match its certificate")
	}
	if certPEM != nil {
		block, _ := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("the certificate given is not a PEM certificate")
		}
		got, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("the certificate given cannot be read: %w", err)
		}
		if g := tlsauto.Fingerprint(got.Raw); !SameFingerprint(g, fp) {
			return fmt.Errorf("the certificate given (%s) is not the cluster's certificate authority (%s)", g, fp)
		}
	}
	if !samePublicKey(ca.PublicKey, key.Public()) {
		return ErrKeyMismatch
	}
	return nil
}

// ParseKey reads a certificate authority's private key in PEM: PKCS #8,
// or the EC and RSA forms older tools write.
func ParseKey(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("the file holds no PEM private key")
	}
	defer clear(block.Bytes)
	var k any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("the file holds a %q block, not a private key", block.Type)
	}
	if err != nil {
		return nil, errors.New("the private key in the file cannot be read")
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("the private key in the file cannot sign")
	}
	return s, nil
}
