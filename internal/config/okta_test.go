// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testOktaKey stands in for a private key: config only checks its shape.
const testOktaKey = "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----"

func TestOktaChecks(t *testing.T) {
	for _, d := range []string{"", "example.okta.com", "https://Example.Okta.com/", "login.example.org", "acme.oktapreview.com"} {
		if err := checkOktaDomain(d); err != nil {
			t.Errorf("domain %q: %v", d, err)
		}
	}
	for _, d := range []string{"example.okta.com:8443", "10.0.0.1", "example.okta.com/path", "okta", "http://example.okta.com", "a b.com", "-x.okta.com"} {
		if err := checkOktaDomain(d); err == nil {
			t.Errorf("domain %q was taken", d)
		}
	}
	if err := checkOktaClientID("0oa1b2c3d4e5f6g7h8i9"); err != nil {
		t.Error(err)
	}
	if err := checkOktaClientID("0oa1 bad"); err == nil {
		t.Error("client ID with a space was taken")
	}
	good := []string{"", testOktaKey, strings.ReplaceAll(testOktaKey, "\n", ""), `{"kty":"RSA","n":"x","e":"AQAB","d":"y"}`}
	for _, k := range good {
		if err := CheckOktaPrivateKey(k); err != nil {
			t.Errorf("key %.30q: %v", k, err)
		}
	}
	bad := map[string]string{
		"-----BEGIN PRIVATE KEY-----": "cut short",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----": "passphrase",
		"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----":                       "public key",
		`{"kty":"RSA","n":"x","e":"AQAB"}`:                                                 "no private part",
		"hunter2":                                                                          "PEM",
		strings.Repeat("A", 17<<10):                                                        "longer",
	}
	for k, want := range bad {
		err := CheckOktaPrivateKey(k)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("key %.30q: %v, want %q", k, err, want)
		}
		// No message repeats the value it was given.
		if err != nil && len(k) > 6 && strings.Contains(err.Error(), k) {
			t.Errorf("key %.30q: the message repeats it", k)
		}
	}
}

func TestOktaConfig(t *testing.T) {
	c := &Config{Okta: Okta{Domain: " https://Example.okta.com/ ", ClientID: "0oaapp"}}
	if c.OktaOn() || c.OktaDomain() != "example.okta.com" || c.OktaTokenURL() != "https://example.okta.com/oauth2/v1/token" {
		t.Errorf("on %v, domain %q, token URL %q", c.OktaOn(), c.OktaDomain(), c.OktaTokenURL())
	}
	c.Okta.PrivateKey = testOktaKey
	if !c.OktaOn() {
		t.Error("app and key: not on")
	}
	c.Okta = Okta{Domain: "example.okta.com", APIToken: "t"}
	if !c.OktaOn() {
		t.Error("API token: not on")
	}
	// Both secrets say where they are sent: the organization's own domain.
	for _, key := range []string{"okta.private_key", "okta.api_token"} {
		s, ok := Lookup(key)
		if !ok || s.SentTo(c) != "https://example.okta.com:443" {
			t.Errorf("%s sent to %q", key, s.SentTo(c))
		}
	}
}

func TestOktaKeyFromFile(t *testing.T) {
	path := writeConfig(t, "okta:\n  domain: example.okta.com\n  client_id: 0oaapp\n")
	file := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(file, []byte(testOktaKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_OKTA_PRIVATE_KEY_FILE", file)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// A PEM file keeps its line breaks.
	if c.Okta.PrivateKey != testOktaKey || !c.OktaOn() || c.Source("okta.private_key").Env != "SIGNALITH_OKTA_PRIVATE_KEY_FILE" {
		t.Errorf("key %q, source %+v", c.Okta.PrivateKey, c.Source("okta.private_key"))
	}
}

func TestOktaValidate(t *testing.T) {
	path := writeConfig(t, "okta:\n  domain: example.okta.com:8443\n  client_id: 0oaapp\n  private_key: hunter2\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "okta.domain") || !strings.Contains(err.Error(), "okta.private_key") {
		t.Fatalf("load: %v", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("the problem repeats the key: %v", err)
	}
}

func TestOktaSecretSet(t *testing.T) {
	if err := CheckSecret("okta.private_key", "-----BEGIN PRIVATE KEY-----"); err == nil {
		t.Error("a key's first line alone was taken")
	}
	if err := CheckSecret("okta.private_key", testOktaKey); err != nil {
		t.Error(err)
	}
	if err := CheckSecret("okta.api_token", "token"); err != nil {
		t.Error(err)
	}
	out, err := SetSecretText([]byte("okta:\n  domain: example.okta.com\n"), "okta.private_key", "enc:v1:00000000:AAAA")
	if err != nil || !strings.Contains(string(out), "private_key: enc:v1:00000000:AAAA") || !strings.Contains(string(out), "domain: example.okta.com") {
		t.Errorf("set %v:\n%s", err, out)
	}
}
