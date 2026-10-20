// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// loadYAML loads a config file with the given text and an admin password.
func loadYAML(t *testing.T, text string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	return Load(path)
}

func TestHTTPSDefaults(t *testing.T) {
	// A config from before HTTPS was the default: HTTPS on, the http
	// public_url upgraded (same port), and old agents may still send
	// over plain HTTP.
	c, err := loadYAML(t, "server:\n  listen: 0.0.0.0:8080\n  public_url: http://siem.corp.local:8080\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.TLSMode() != TLSAuto || !c.Server.HTTPS() || !c.Server.PlaintextIngest() || c.Server.PublicURL != "https://siem.corp.local:8080" {
		t.Errorf("old config: mode %s, plaintext %v, public_url %s", c.Server.TLSMode(), c.Server.PlaintextIngest(), c.Server.PublicURL)
	}
	// No public_url: the default is https.
	c, err = loadYAML(t, "server:\n  listen: 127.0.0.1:8443\n")
	if err != nil || c.Server.PublicURL != "https://127.0.0.1:8443" {
		t.Errorf("default public_url: %v %s", err, c.Server.PublicURL)
	}
	// What init writes: auto, and agents only over HTTPS.
	c, err = loadYAML(t, "server:\n  listen: 0.0.0.0:8080\n  tls:\n    mode: auto\n    plaintext_ingest: deny\n")
	if err != nil || c.Server.TLSMode() != TLSAuto || c.Server.PlaintextIngest() {
		t.Errorf("init config: %v mode %s plaintext %v", err, c.Server.TLSMode(), c.Server.PlaintextIngest())
	}
	// A tls section without plaintext_ingest denies it.
	c, err = loadYAML(t, "server:\n  tls:\n    names: [siem.example.com, 192.0.2.10]\n")
	if err != nil || c.Server.PlaintextIngest() || strings.Join(c.Server.TLSNames(), ",") != "siem.example.com,192.0.2.10" {
		t.Errorf("tls section: %v %v %v", err, c.Server.PlaintextIngest(), c.Server.TLSNames())
	}
	// An http public_url with HTTPS on, such as an old config after
	// following the upgrade steps (a tls section added) or one with no
	// port: the same host and port over HTTPS, and a warning to fix it.
	for text, want := range map[string]string{
		"server:\n  public_url: http://siem:18775\n  tls:\n    mode: auto\n    plaintext_ingest: deny\n": "https://siem:18775",
		"server:\n  listen: 0.0.0.0:80\n  public_url: http://siem.corp\n":                                "https://siem.corp:80",
		"server:\n  public_url: http://[2001:db8::5]\n":                                                  "https://[2001:db8::5]:80",
	} {
		c, err := loadYAML(t, text)
		if err != nil || c.Server.PublicURL != want || !strings.Contains(strings.Join(c.Warnings(), "\n"), "Change public_url to "+want+" in signalith.yaml") {
			t.Errorf("%q: %v, public_url %s, warnings %v", text, err, c.Server.PublicURL, c.Warnings())
		}
	}
	// An old config with an https public_url and no certificate had a
	// reverse proxy adding HTTPS: it stays plain behind it.
	c, err = loadYAML(t, "server:\n  listen: 127.0.0.1:8080\n  public_url: https://siem.example.com\n")
	if err != nil || c.Server.TLSMode() != TLSOff || c.Server.HTTPS() {
		t.Errorf("old proxied config: %v mode %s", err, c.Server.TLSMode())
	}
}

func TestHTTPSFilesMode(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestPair(t, dir)
	// An old config with a certificate: files mode, nothing over plain HTTP.
	c, err := loadYAML(t, "server:\n  listen: 0.0.0.0:8443\n  tls_cert: "+cert+"\n  tls_key: "+key+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.TLSMode() != TLSFiles || c.Server.PlaintextIngest() || !strings.HasPrefix(c.Server.PublicURL, "https://") {
		t.Errorf("files: mode %s plaintext %v url %s", c.Server.TLSMode(), c.Server.PlaintextIngest(), c.Server.PublicURL)
	}
	if gc, gk := c.TLSFiles(); gc != cert || gk != key {
		t.Errorf("TLSFiles = %s %s", gc, gk)
	}
	if _, err := loadYAML(t, "server:\n  tls:\n    mode: files\n  tls_cert: "+cert+"\n  tls_key: "+key+"\n"); err != nil {
		t.Error(err)
	}
}

func TestHTTPSValidation(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestPair(t, dir)
	for text, want := range map[string]string{
		"server:\n  tls:\n    mode: on\n":                                                     `server.tls.mode "on" must be auto`,
		"server:\n  tls:\n    mode: files\n":                                                  "server.tls.mode is files, so set server.tls_cert",
		"server:\n  tls:\n    mode: auto\n  tls_cert: " + cert + "\n  tls_key: " + key + "\n": "server.tls.mode is auto",
		"server:\n  tls_cert: " + cert + "\n":                                                 "must be set together",
		"server:\n  tls_cert: " + key + "\n  tls_key: " + key + "\n":                          "server.tls_cert and tls_key:",
		"server:\n  tls:\n    plaintext_ingest: maybe\n":                                      `plaintext_ingest "maybe" must be allow or deny`,
		"server:\n  tls:\n    names: [\"bad name\", \"ok.example.com\"]\n":                    `server.tls.names[0] "bad name"`,
		"server:\n  trusted_proxies: [10.0.0.0/33]\n":                                         `server.trusted_proxies[0] "10.0.0.0/33"`,
	} {
		if _, err := loadYAML(t, text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %q", text, err, want)
		}
	}
	// With HTTPS off, http is fine.
	if c, err := loadYAML(t, "server:\n  public_url: http://siem:8080\n  tls:\n    mode: off\n"); err != nil || c.Server.HTTPS() {
		t.Errorf("mode off: %v", err)
	}
	// syslog.tls no longer needs a certificate file: it uses Signalith's own.
	if _, err := loadYAML(t, "syslog:\n  tls: 0.0.0.0:6514\n"); err != nil {
		t.Errorf("syslog.tls without tls_cert: %v", err)
	}
}

func TestHTTPSWarnings(t *testing.T) {
	warned := func(c *Config) bool {
		for _, w := range c.Warnings() {
			if strings.Contains(w, "HTTPS is off") {
				return true
			}
		}
		return false
	}
	c, err := loadYAML(t, "server:\n  listen: 0.0.0.0:8080\n  public_url: http://siem:8080\n  tls:\n    mode: off\n")
	if err != nil || !warned(c) {
		t.Errorf("off on all interfaces: %v %v", err, c.Warnings())
	}
	// On loopback (a proxy on this machine) or with a trusted proxy: fine.
	for _, text := range []string{
		"server:\n  listen: 127.0.0.1:8080\n  tls:\n    mode: off\n",
		"server:\n  listen: 0.0.0.0:8080\n  trusted_proxies: [10.0.0.5]\n  tls:\n    mode: off\n",
		"server:\n  listen: 0.0.0.0:8080\n",
	} {
		if c, err := loadYAML(t, text); err != nil || warned(c) {
			t.Errorf("%q: %v %v", text, err, c.Warnings())
		}
	}
}

func TestTrustedProxies(t *testing.T) {
	s := Server{TrustedProxies: []string{"10.0.0.5", "192.0.2.0/24", "::ffff:198.51.100.1"}}
	for in, want := range map[string]bool{"10.0.0.5": true, "10.0.0.6": false, "192.0.2.77": true, "::ffff:10.0.0.5": true, "198.51.100.1": true} {
		if got := s.TrustsProxy(netip.MustParseAddr(in)); got != want {
			t.Errorf("TrustsProxy(%s) = %v", in, got)
		}
	}
}

func TestTLSDir(t *testing.T) {
	// t.TempDir is absolute on every system; "/var/..." is not on Windows,
	// where an absolute path needs a drive letter.
	root := t.TempDir()
	c := Default()
	c.path = filepath.Join(root, "etc", "signalith.yaml")
	c.Lookups.Dir = filepath.Join(root, "var", "lookups")
	t.Setenv("SIGNALITH_STATE_DIR", "")
	if got := c.StateDir(); got != filepath.Join(root, "var") {
		t.Errorf("StateDir = %s", got)
	}
	if got := c.TLSDir(); got != filepath.Join(root, "var", "tls") {
		t.Errorf("TLSDir = %s", got)
	}
	// A relative lookups.dir is relative to the config file.
	c.Lookups.Dir = "lookups"
	if got := c.StateDir(); got != filepath.Join(root, "etc") {
		t.Errorf("StateDir with a relative lookups.dir = %s", got)
	}
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(root, "state"))
	if got := c.TLSDir(); got != filepath.Join(root, "state", "tls") {
		t.Errorf("TLSDir with SIGNALITH_STATE_DIR = %s", got)
	}
}

func TestSavedFileHasTLSSection(t *testing.T) {
	c := Default()
	h, _ := HashPassword("correct horse")
	c.Auth.AdminPasswordHash = h
	c.Server.TLS = &ServerTLS{Mode: TLSAuto, PlaintextIngest: "deny"}
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "    tls:\n        mode: auto\n        plaintext_ingest: deny\n") || !strings.Contains(string(data), "# server.tls.mode") {
		t.Errorf("saved file:\n%s", data)
	}
	got, err := Load(path)
	if err != nil || got.Server.PlaintextIngest() || got.Server.TLSMode() != TLSAuto {
		t.Errorf("reload: %v", err)
	}
}

// writeTestPair writes a self-signed certificate and key.
func writeTestPair(t *testing.T, dir string) (cert, key string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "siem.example.com"}, DNSNames: []string{"siem.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(k)
	cert, key = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600)
	return cert, key
}
