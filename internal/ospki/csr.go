package ospki

// Client certificates issued from a certificate request, so the key of a
// Signalith server's own client certificate never leaves the server that
// uses it, and the CA read back from PEM, as Signalith keeps it.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// PairFromPEM reads a CA certificate and its key (PKCS#8 PEM, as
// bootstrap-docker -export-ca-key and opensearch-certs write them).
func PairFromPEM(certPEM, keyPEM []byte) (*Pair, error) {
	c, err := parseCert(certPEM)
	if err != nil {
		return nil, fmt.Errorf("the CA certificate: %w", err)
	}
	if !c.IsCA {
		return nil, errors.New("the certificate is not a CA certificate")
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("the CA key: %w", err)
	}
	if !key.PublicKey.Equal(c.PublicKey) {
		return nil, errors.New("the key is not the CA certificate's key")
	}
	return &Pair{Cert: c, Key: key}, nil
}

// NewClientRequest makes a key and a certificate request for a client
// certificate with the common name cn. The key is PKCS#8 PEM.
func NewClientRequest(cn string) (keyPEM, csrPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, KeyBits)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn, Organization: []string{Org}},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	defer clear(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// SignClientRequest makes a client certificate under ca for the common
// name cn and the key of the certificate request csrPEM, lasting
// validity or until the CA expires if sooner. Only the request's key is
// used: its subject and extensions are not, so the name is always cn.
func SignClientRequest(ca *Pair, cn string, csrPEM []byte, now time.Time, validity time.Duration) (*x509.Certificate, error) {
	if cn == "" {
		return nil, errors.New("a client certificate needs a name")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("no PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the certificate request's signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return nil, errors.New("the certificate request needs an RSA key of at least 2048 bits")
	}
	return issueKey(ca, cn, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil, pub, now, validity)
}
