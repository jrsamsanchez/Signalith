// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/saml/samltest"
)

// withCert is the provider's metadata with a certificate valid from
// notBefore to notAfter instead of its own.
func withCert(t *testing.T, idp *samltest.IdP, notBefore, notAfter time.Time) string {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test IdP"}, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &idp.Key.PublicKey, idp.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	other := *idp
	other.Cert = cert
	return mustJSON(string(other.Metadata()))
}

// The SAML test names what to fill in, says when the metadata cannot be
// read, and checks the signing certificates' dates.
func TestTestSAMLMore(t *testing.T) {
	ts, _, idp := newSAMLServer(t, nil)
	test := func(body string) (int, map[string]any, string) {
		t.Helper()
		return call(t, ts, "POST", "/api/auth/saml/test", body, "admin", adminPass, nil)
	}
	if code, _, _ := test(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	for body, key := range map[string]string{
		`{"clear":["auth.saml.provider"]}`:                                               "auth.saml.provider",
		`{"values":{"auth.saml.metadata_xml":` + mustJSON(string(idp.Metadata())) + `}}`: "auth.saml.metadata_xml",
	} {
		code, out, raw := test(body)
		if fields, _ := out["fields"].(map[string]any); code != http.StatusBadRequest || fields[key] == nil {
			t.Errorf("%s: %d %s", body, code, raw)
		}
	}

	gone := httptest.NewServer(http.NotFoundHandler())
	defer gone.Close()
	code, out, raw := test(`{"values":{"auth.saml.metadata_url":"` + gone.URL + `/metadata"}}`)
	if code != http.StatusOK || out["ok"] != false || !strings.Contains(out["message"].(string), "could not use the identity provider's metadata") {
		t.Errorf("metadata not found: %d %s", code, raw)
	}

	now := time.Now()
	code, out, raw = test(`{"values":{"auth.saml.metadata_url":"","auth.saml.metadata_xml":` + withCert(t, idp, now.Add(-48*time.Hour), now.Add(-time.Hour)) + `}}`)
	if code != http.StatusOK || out["ok"] != false || !strings.Contains(raw, "has expired or is not valid yet") {
		t.Errorf("expired certificate: %d %s", code, raw)
	}
	code, out, raw = test(`{"values":{"auth.saml.metadata_url":"","auth.saml.metadata_xml":` + withCert(t, idp, now.Add(-time.Hour), now.Add(10*24*time.Hour)) + `}}`)
	if code != http.StatusOK || out["ok"] != true || !strings.Contains(raw, "within 30 days") {
		t.Errorf("certificate expiring soon: %d %s", code, raw)
	}
}
