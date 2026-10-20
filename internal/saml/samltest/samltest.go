// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package samltest is a SAML 2.0 identity provider for tests: it has a
// signing key, publishes metadata, and makes signed responses, honest or
// not.
package samltest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
)

// IdP is a test identity provider.
type IdP struct {
	EntityID string
	SSOURL   string
	Key      *rsa.PrivateKey
	Cert     *x509.Certificate
}

// New returns a provider with a fresh 2048-bit key and a certificate
// valid for a year around now.
func New(t testing.TB, entityID, ssoURL string) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test IdP"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &IdP{EntityID: entityID, SSOURL: ssoURL, Key: key, Cert: cert}
}

// Metadata is the provider's metadata.
func (p *IdP) Metadata() []byte {
	doc := etree.NewDocument()
	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("xmlns:ds", dsig.Namespace)
	ed.CreateAttr("entityID", p.EntityID)
	d := ed.CreateElement("md:IDPSSODescriptor")
	d.CreateAttr("protocolSupportEnumeration", nsProtocol)
	kd := d.CreateElement("md:KeyDescriptor")
	kd.CreateAttr("use", "signing")
	kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(p.Cert.Raw))
	for _, b := range []string{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"} {
		s := d.CreateElement("md:SingleSignOnService")
		s.CreateAttr("Binding", b)
		s.CreateAttr("Location", p.SSOURL)
	}
	out, _ := doc.WriteToBytes()
	return out
}

// Response is what a response says; New fills in an honest one with
// Honest.
type Response struct {
	ID, AssertionID string
	// InResponseTo is the response's, and SubjectInResponseTo the bearer
	// confirmation's.
	InResponseTo, SubjectInResponseTo string
	Destination, Recipient, Audience  string
	Issuer, AssertionIssuer           string
	NameID, NameIDFormat              string
	Status                            string
	Issued, NotBefore, NotOnOrAfter   time.Time
	Attributes                        map[string][]string
	// SignResponse and SignAssertion choose what is signed; SHA1 signs
	// with SHA-1.
	SignResponse, SignAssertion, SHA1 bool
	// Key signs instead of the provider's key, with Cert in KeyInfo.
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
	// Change edits the response after it is signed.
	Change func(resp *etree.Element)
}

// Honest is the response the provider would send to the service provider
// with entityID and acs, in answer to requestID, at now.
func (p *IdP) Honest(entityID, acs, requestID string, now time.Time) Response {
	return Response{ID: "_r" + rnd(), AssertionID: "_a" + rnd(), InResponseTo: requestID, SubjectInResponseTo: requestID,
		Destination: acs, Recipient: acs, Audience: entityID, Issuer: p.EntityID, AssertionIssuer: p.EntityID,
		NameID: "alice@example.com", NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		Status: "urn:oasis:names:tc:SAML:2.0:status:Success", Issued: now, NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(5 * time.Minute),
		Attributes: map[string][]string{"email": {"alice@example.com"}, "groups": {"soc-admins"}}, SignAssertion: true}
}

func rnd() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// Assertion returns the assertion element of r, signed when r says.
func (p *IdP) Assertion(t testing.TB, r Response) *etree.Element {
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsAssertion)
	a.CreateAttr("ID", r.AssertionID)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", stamp(r.Issued))
	a.CreateElement("saml:Issuer").SetText(r.AssertionIssuer)
	subj := a.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	if r.NameIDFormat != "" {
		nid.CreateAttr("Format", r.NameIDFormat)
	}
	nid.SetText(r.NameID)
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	if r.SubjectInResponseTo != "" {
		scd.CreateAttr("InResponseTo", r.SubjectInResponseTo)
	}
	scd.CreateAttr("NotOnOrAfter", stamp(r.NotOnOrAfter))
	scd.CreateAttr("Recipient", r.Recipient)
	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", stamp(r.NotBefore))
	cond.CreateAttr("NotOnOrAfter", stamp(r.NotOnOrAfter))
	if r.Audience != "" {
		cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(r.Audience)
	}
	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", stamp(r.Issued))
	as.CreateAttr("SessionIndex", r.AssertionID)
	as.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	if len(r.Attributes) > 0 {
		st := a.CreateElement("saml:AttributeStatement")
		for name, vals := range r.Attributes {
			at := st.CreateElement("saml:Attribute")
			at.CreateAttr("Name", name)
			for _, v := range vals {
				at.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
	if r.SignAssertion {
		a = p.sign(t, r, a)
	}
	return a
}

func (p *IdP) sign(t testing.TB, r Response, el *etree.Element) *etree.Element {
	t.Helper()
	key, cert := p.Key, p.Cert
	if r.Key != nil {
		key, cert = r.Key, r.Cert
	}
	ctx, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if r.SHA1 {
		ctx.Hash = crypto.SHA1
	}
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// Build returns the response element of r.
func (p *IdP) Build(t testing.TB, r Response) *etree.Element {
	t.Helper()
	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("ID", r.ID)
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", stamp(r.Issued))
	if r.Destination != "" {
		resp.CreateAttr("Destination", r.Destination)
	}
	if r.InResponseTo != "" {
		resp.CreateAttr("InResponseTo", r.InResponseTo)
	}
	resp.CreateElement("saml:Issuer").SetText(r.Issuer)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", r.Status)
	if r.Status == "urn:oasis:names:tc:SAML:2.0:status:Success" {
		resp.AddChild(p.Assertion(t, r))
	}
	if r.SignResponse {
		resp = p.sign(t, r, resp)
	}
	return resp
}

// Encode returns the response as the browser posts it.
func Encode(t testing.TB, resp *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(resp)
	b, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Respond returns r, built, changed and encoded.
func (p *IdP) Respond(t testing.TB, r Response) string {
	t.Helper()
	resp := p.Build(t, r)
	if r.Change != nil {
		r.Change(resp)
	}
	return Encode(t, resp)
}
