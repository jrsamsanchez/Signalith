// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package saml is single sign-on with a SAML 2.0 identity provider, such
// as AD FS, Okta or Microsoft Entra ID, in the Web Browser SSO profile:
// Signalith sends the browser to the provider with an AuthnRequest
// (HTTP-Redirect binding), and the provider posts a signed Response back
// to the assertion consumer service (HTTP-POST binding).
//
// Signatures are checked with goxmldsig, and only what a valid signature
// covers is read: Validate returns the signed element as signed, and
// everything after it reads that copy, never the document as received, so
// a second, unsigned assertion slipped in beside or inside a signed one
// (signature wrapping) is never seen. SHA-1 is refused, as are DTDs,
// encrypted assertions, responses nobody asked for (IdP-initiated) and
// assertions seen before (replays).
package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// The namespaces and values of SAML 2.0.
const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"

	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	bearer        = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	entityFormat  = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"

	// NameIDTransient is a NameID that changes at every sign-in, so it
	// cannot name a user.
	NameIDTransient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

// Skew is how far the provider's clock may be from Signalith's.
const Skew = 3 * time.Minute

// MaxResponse is the largest SAMLResponse taken, base64-encoded.
const MaxResponse = 512 << 10

// MaxMetadata is the largest metadata document taken.
const MaxMetadata = 1 << 20

// ErrDenied is a response in which the provider refused the sign-in, such
// as a user not assigned to the application. Errors wrap it.
var ErrDenied = errors.New("the identity provider refused the sign-in")

// IdP is what Signalith needs to know about an identity provider, from
// its metadata.
type IdP struct {
	// EntityID names the provider; assertions must be issued by it.
	EntityID string
	// SSOURL is where AuthnRequests go, with the HTTP-Redirect binding.
	SSOURL string
	// Certs are the provider's signing certificates. A response must be
	// signed with one of them.
	Certs []*x509.Certificate
}

// SP is Signalith as a service provider.
type SP struct {
	// EntityID names Signalith to the provider; assertions must be meant
	// for it (their audience).
	EntityID string
	// ACSURL is the assertion consumer service, where the provider posts
	// responses.
	ACSURL string
}

// readXML reads an XML document, refusing DTDs (and so entities, which
// Go's parser would not expand anyway).
func readXML(data []byte, max int) (*etree.Document, error) {
	if len(data) > max {
		return nil, fmt.Errorf("the document is larger than %d KB", max>>10)
	}
	if up := bytes.ToUpper(data); bytes.Contains(up, []byte("<!DOCTYPE")) || bytes.Contains(up, []byte("<!ENTITY")) {
		return nil, errors.New("the document has a DTD, which SAML never needs")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, fmt.Errorf("the document is not XML: %w", err)
	}
	if doc.Root() == nil {
		return nil, errors.New("the document is empty")
	}
	return doc, nil
}

// is reports whether el is the element tag in namespace ns.
func is(el *etree.Element, ns, tag string) bool {
	return el != nil && el.Tag == tag && el.NamespaceURI() == ns
}

// children returns el's child elements tag in namespace ns.
func children(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if is(c, ns, tag) {
			out = append(out, c)
		}
	}
	return out
}

// child returns el's only child element tag in namespace ns: nil when
// there is none, an error when there are several.
func child(el *etree.Element, ns, tag string) (*etree.Element, error) {
	cs := children(el, ns, tag)
	switch len(cs) {
	case 0:
		return nil, nil
	case 1:
		return cs[0], nil
	}
	return nil, fmt.Errorf("%s has %d %s elements; it may have only one", el.Tag, len(cs), tag)
}

// descendants returns every element tag in namespace ns at or below el.
func descendants(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	var walk func(*etree.Element)
	walk = func(e *etree.Element) {
		if is(e, ns, tag) {
			out = append(out, e)
		}
		for _, c := range e.ChildElements() {
			walk(c)
		}
	}
	walk(el)
	return out
}

// attr returns el's attribute key, without a namespace prefix (SAML's own
// attributes have none).
func attr(el *etree.Element, key string) string {
	for _, a := range el.Attr {
		if a.Space == "" && a.Key == key {
			return a.Value
		}
	}
	return ""
}

// text returns el's text, refusing an element with elements inside, so
// nothing past a nested element is quietly dropped.
func text(el *etree.Element) (string, error) {
	var b strings.Builder
	for _, t := range el.Child {
		switch t := t.(type) {
		case *etree.CharData:
			b.WriteString(t.Data)
		case *etree.Element:
			return "", fmt.Errorf("%s holds an element where text belongs", el.Tag)
		}
	}
	return strings.TrimSpace(b.String()), nil
}

// instant reads an xs:dateTime attribute; zero when it is absent.
func instant(el *etree.Element, key string) (time.Time, error) {
	v := attr(el, key)
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s %s is not a time: %q", el.Tag, key, clip(v))
	}
	return t, nil
}

// clip keeps text from the provider short and printable, for errors.
func clip(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, v)
	if r := []rune(v); len(r) > 120 {
		v = string(r[:120]) + "…"
	}
	return v
}

// ---- metadata ----

// ParseMetadata reads an identity provider's metadata: an
// EntityDescriptor, or an EntitiesDescriptor with exactly one identity
// provider in it.
func ParseMetadata(data []byte) (*IdP, error) {
	doc, err := readXML(data, MaxMetadata)
	if err != nil {
		return nil, err
	}
	root := doc.Root()
	if !is(root, nsMetadata, "EntityDescriptor") && !is(root, nsMetadata, "EntitiesDescriptor") {
		return nil, errors.New("this is not SAML metadata: it has no EntityDescriptor")
	}
	var found []*etree.Element
	for _, ed := range descendants(root, nsMetadata, "EntityDescriptor") {
		for _, d := range children(ed, nsMetadata, "IDPSSODescriptor") {
			if strings.Contains(attr(d, "protocolSupportEnumeration"), nsProtocol) {
				found = append(found, d)
			}
		}
	}
	switch len(found) {
	case 0:
		return nil, errors.New("the metadata describes no SAML 2.0 identity provider (IDPSSODescriptor)")
	case 1:
	default:
		return nil, fmt.Errorf("the metadata describes %d identity providers; use the metadata of just yours", len(found))
	}
	d := found[0]
	idp := &IdP{EntityID: strings.TrimSpace(attr(d.Parent(), "entityID"))}
	if idp.EntityID == "" || strings.ContainsAny(idp.EntityID, " \t\r\n") {
		return nil, errors.New("the metadata's entityID is missing or not a URI")
	}
	if attr(d, "WantAuthnRequestsSigned") == "true" {
		return nil, errors.New("the identity provider wants signed sign-in requests, which Signalith does not send; turn that off at the provider (assertions are still signed)")
	}
	for _, kd := range children(d, nsMetadata, "KeyDescriptor") {
		if use := attr(kd, "use"); use != "" && use != "signing" {
			continue
		}
		for _, cd := range descendants(kd, dsig.Namespace, "X509Certificate") {
			raw, err := text(cd)
			if err != nil {
				return nil, err
			}
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(raw), ""))
			if err != nil {
				return nil, errors.New("a signing certificate in the metadata is not base64")
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("a signing certificate in the metadata cannot be read: %w", err)
			}
			if !containsCert(idp.Certs, cert) {
				idp.Certs = append(idp.Certs, cert)
			}
		}
	}
	if len(idp.Certs) == 0 {
		return nil, errors.New("the metadata lists no signing certificate")
	}
	for _, s := range children(d, nsMetadata, "SingleSignOnService") {
		if attr(s, "Binding") == BindingRedirect {
			idp.SSOURL = strings.TrimSpace(attr(s, "Location"))
			break
		}
	}
	if idp.SSOURL == "" {
		return nil, errors.New("the metadata has no single sign-on address with the HTTP-Redirect binding")
	}
	if u, err := url.Parse(idp.SSOURL); err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname()))) {
		return nil, fmt.Errorf("the single sign-on address %q must be an https:// address", clip(idp.SSOURL))
	}
	return idp, nil
}

func containsCert(list []*x509.Certificate, c *x509.Certificate) bool {
	for _, x := range list {
		if x.Equal(c) {
			return true
		}
	}
	return false
}

func loopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// SPMetadata returns Signalith's own metadata, for the provider to read.
// Assertions must be signed; requests are not.
func SPMetadata(sp SP) []byte {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("entityID", sp.EntityID)
	d := ed.CreateElement("md:SPSSODescriptor")
	d.CreateAttr("AuthnRequestsSigned", "false")
	d.CreateAttr("WantAssertionsSigned", "true")
	d.CreateAttr("protocolSupportEnumeration", nsProtocol)
	acs := d.CreateElement("md:AssertionConsumerService")
	acs.CreateAttr("Binding", BindingPOST)
	acs.CreateAttr("Location", sp.ACSURL)
	acs.CreateAttr("index", "0")
	acs.CreateAttr("isDefault", "true")
	doc.Indent(2)
	out, _ := doc.WriteToBytes()
	return out
}

// ---- the request ----

// Request is a sign-in sent to the provider. Its ID comes back in the
// response's InResponseTo, which ties the response to this browser.
type Request struct {
	ID         string
	RelayState string
	Issued     time.Time
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewRequest makes a sign-in with a fresh, unguessable ID and RelayState.
func NewRequest(now time.Time) Request {
	// An xs:ID must not start with a digit.
	return Request{ID: "_" + randomHex(20), RelayState: randomHex(16), Issued: now.UTC()}
}

// RedirectURL is where to send the browser to sign in: the provider's
// single sign-on address with the AuthnRequest, deflated and base64ed,
// and the RelayState (HTTP-Redirect binding).
func RedirectURL(idp *IdP, sp SP, req Request) (string, error) {
	doc := etree.NewDocument()
	ar := doc.CreateElement("samlp:AuthnRequest")
	ar.CreateAttr("xmlns:samlp", nsProtocol)
	ar.CreateAttr("xmlns:saml", nsAssertion)
	ar.CreateAttr("ID", req.ID)
	ar.CreateAttr("Version", "2.0")
	ar.CreateAttr("IssueInstant", req.Issued.Format("2006-01-02T15:04:05Z"))
	ar.CreateAttr("Destination", idp.SSOURL)
	ar.CreateAttr("AssertionConsumerServiceURL", sp.ACSURL)
	ar.CreateAttr("ProtocolBinding", BindingPOST)
	ar.CreateElement("saml:Issuer").SetText(sp.EntityID)
	np := ar.CreateElement("samlp:NameIDPolicy")
	np.CreateAttr("AllowCreate", "true")
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = fw.Write(raw)
	if err := fw.Close(); err != nil {
		return "", err
	}
	u, err := url.Parse(idp.SSOURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))
	q.Set("RelayState", req.RelayState)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
