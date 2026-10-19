// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// filesManager serves a self-signed certificate for dns and ips from
// files, as with a certificate from a company CA (server.tls.mode files).
func filesManager(t *testing.T, dns []string, ips ...string) *tlsauto.Manager {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "siem"},
		DNSNames: dns, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	cert, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := tlsauto.New(tlsauto.Options{CertFile: cert, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestAgentConfigTiesAnIPAddressToTheServer: with a certificate from a CA
// that vouches for other computers too, an agent set up with the
// server's IP address checks a name the certificate carries, and without
// one Add data says why it can't make the config.
func TestAgentConfigTiesAnIPAddressToTheServer(t *testing.T) {
	q := url.Values{"os": {"linux"}, "server": {"https://192.168.1.20:8080"}}
	m := filesManager(t, []string{"siem.corp.example"}, "192.168.1.20")
	ts, _ := newTestServerWith(t, func(s *Server) { s.TLS = m })
	code, body := do(t, ts, "GET", "/api/agents/config?"+q.Encode(), "", true)
	cfg, _ := body["config"].(string)
	if code != 200 || !strings.Contains(cfg, "Host                 192.168.1.20\n") ||
		!strings.Contains(cfg, "tls.vhost            siem.corp.example\n") || !strings.Contains(cfg, "tls.verify_hostname  On\n") {
		t.Errorf("company CA by IP: %d %v", code, body)
	}

	m = filesManager(t, nil, "192.168.1.20")
	ts, _ = newTestServerWith(t, func(s *Server) { s.TLS = m })
	code, body = do(t, ts, "GET", "/api/agents/config?"+q.Encode(), "", true)
	if msg, _ := body["error"].(string); code != 400 || body["field"] != "server" || !strings.Contains(msg, "no host name to check") {
		t.Errorf("certificate with no name: %d %v", code, body)
	}

	// Signalith's own CA vouches for nothing else: checking who issued
	// the certificate is enough.
	ts, _ = newTestServerWith(t, func(s *Server) { s.TLS = newCertManager(t) })
	code, body = do(t, ts, "GET", "/api/agents/config?"+q.Encode(), "", true)
	if cfg, _ := body["config"].(string); code != 200 || strings.Contains(cfg, "vhost") {
		t.Errorf("own CA by IP: %d %v", code, body)
	}
}
