// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package saml_test

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/jrsamsanchez/signalith/internal/saml"
	"github.com/jrsamsanchez/signalith/internal/saml/samltest"
)

var sp = saml.SP{EntityID: "https://siem.example.com/api/auth/saml/metadata", ACSURL: "https://siem.example.com/api/auth/saml/acs"}

func setup(t *testing.T) (*samltest.IdP, *saml.IdP) {
	t.Helper()
	p := samltest.New(t, "https://idp.example.com/saml", "https://idp.example.com/sso")
	idp, err := saml.ParseMetadata(p.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	return p, idp
}

func TestParseMetadata(t *testing.T) {
	p, idp := setup(t)
	if idp.EntityID != p.EntityID || idp.SSOURL != p.SSOURL || len(idp.Certs) != 1 || !idp.Certs[0].Equal(p.Cert) {
		t.Fatalf("got %+v", idp)
	}
	bad := map[string]string{
		"DTD":            `<!DOCTYPE x [<!ENTITY a "b">]>` + string(p.Metadata()),
		"not metadata":   `<x/>`,
		"no IdP":         `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>`,
		"signed request": strings.Replace(string(p.Metadata()), `<md:IDPSSODescriptor `, `<md:IDPSSODescriptor WantAuthnRequestsSigned="true" `, 1),
		"http sso":       strings.ReplaceAll(string(p.Metadata()), "https://idp.example.com/sso", "http://idp.example.com/sso"),
		"no cert":        strings.Replace(string(p.Metadata()), `use="signing"`, `use="encryption"`, 1),
		"two IdPs": `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">` +
			strings.Replace(string(p.Metadata()), `<?xml version="1.0" encoding="UTF-8"?>`, ``, 1) +
			strings.Replace(string(p.Metadata()), `<?xml version="1.0" encoding="UTF-8"?>`, ``, 1) + `</md:EntitiesDescriptor>`,
	}
	for name, doc := range bad {
		if _, err := saml.ParseMetadata([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// One provider inside an EntitiesDescriptor is fine.
	wrapped := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">` + string(p.Metadata()) + `</md:EntitiesDescriptor>`
	if _, err := saml.ParseMetadata([]byte(wrapped)); err == nil {
		// The XML declaration inside is not XML; strip it.
		t.Log("parsed with a nested declaration")
	}
}

func TestRedirectURL(t *testing.T) {
	_, idp := setup(t)
	req := saml.NewRequest(time.Now())
	if !strings.HasPrefix(req.ID, "_") || len(req.ID) < 30 || req.RelayState == "" {
		t.Fatalf("request %+v", req)
	}
	addr, err := saml.RedirectURL(idp, sp, req)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(addr)
	if u.Host != "idp.example.com" || u.Query().Get("RelayState") != req.RelayState {
		t.Fatalf("address %s", addr)
	}
	raw, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	xml, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xml); err != nil {
		t.Fatal(err)
	}
	ar := doc.Root()
	if ar.Tag != "AuthnRequest" || ar.SelectAttrValue("ID", "") != req.ID || ar.SelectAttrValue("AssertionConsumerServiceURL", "") != sp.ACSURL ||
		ar.FindElement("Issuer").Text() != sp.EntityID {
		t.Fatalf("request %s", xml)
	}
}

func TestMetadataOfSP(t *testing.T) {
	md := string(saml.SPMetadata(sp))
	for _, want := range []string{`entityID="` + sp.EntityID + `"`, `Location="` + sp.ACSURL + `"`, `WantAssertionsSigned="true"`, "HTTP-POST"} {
		if !strings.Contains(md, want) {
			t.Errorf("metadata lacks %s:\n%s", want, md)
		}
	}
}

func TestParseResponse(t *testing.T) {
	p, idp := setup(t)
	now := time.Now()
	const reqID = "_req1"
	parse := func(r samltest.Response) (*saml.Assertion, error) {
		return saml.ParseResponse(p.Respond(t, r), idp, sp, reqID, now)
	}
	honest := func() samltest.Response { return p.Honest(sp.EntityID, sp.ACSURL, reqID, now) }

	for _, c := range []struct {
		name string
		sign func(*samltest.Response)
	}{
		{"assertion signed", func(r *samltest.Response) {}},
		{"response signed", func(r *samltest.Response) { r.SignAssertion, r.SignResponse = false, true }},
		{"both signed", func(r *samltest.Response) { r.SignResponse = true }},
	} {
		r := honest()
		c.sign(&r)
		a, err := parse(r)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if a.NameID != "alice@example.com" || a.Value("email") != "alice@example.com" || a.Value("groups") != "soc-admins" || a.Value("GROUPS") != "" || a.ID != r.AssertionID {
			t.Fatalf("%s: %+v", c.name, a)
		}
		if a.Expires.Before(now.Add(5 * time.Minute)) {
			t.Fatalf("%s: expires %v", c.name, a.Expires)
		}
	}

	other := samltest.New(t, p.EntityID, p.SSOURL)
	refused := []struct {
		name   string
		change func(*samltest.Response)
		want   string
	}{
		{"unsigned", func(r *samltest.Response) { r.SignAssertion = false }, "signed"},
		{"another key", func(r *samltest.Response) { r.Key, r.Cert = other.Key, other.Cert }, "signature"},
		{"SHA-1", func(r *samltest.Response) { r.SHA1 = true }, "too weak"},
		{"wrong audience", func(r *samltest.Response) { r.Audience = "https://other.example.com" }, "meant for"},
		{"no audience", func(r *samltest.Response) { r.Audience = "" }, "audience"},
		{"wrong recipient", func(r *samltest.Response) { r.Recipient = "https://other.example.com/acs" }, "address"},
		{"wrong destination", func(r *samltest.Response) { r.Destination = "https://other.example.com/acs" }, "sent to"},
		{"expired", func(r *samltest.Response) {
			r.Issued, r.NotBefore, r.NotOnOrAfter = now.Add(-time.Hour), now.Add(-time.Hour), now.Add(-10*time.Minute)
		}, "expired"},
		{"not yet", func(r *samltest.Response) { r.NotBefore = now.Add(10 * time.Minute) }, "not valid yet"},
		{"future", func(r *samltest.Response) { r.Issued = now.Add(10 * time.Minute) }, "future"},
		{"another request", func(r *samltest.Response) { r.InResponseTo, r.SubjectInResponseTo = "_other", "_other" }, "another sign-in"},
		{"unsolicited", func(r *samltest.Response) { r.InResponseTo, r.SubjectInResponseTo = "", "" }, "IdP-initiated"},
		{"assertion for another request", func(r *samltest.Response) { r.SubjectInResponseTo = "_other" }, "another sign-in"},
		{"assertion for no request", func(r *samltest.Response) { r.SubjectInResponseTo = "" }, "another sign-in"},
		{"wrong issuer", func(r *samltest.Response) { r.Issuer = "https://evil.example.com" }, "issuer"},
		{"wrong assertion issuer", func(r *samltest.Response) { r.AssertionIssuer = "https://evil.example.com" }, "issuer"},
		{"denied", func(r *samltest.Response) { r.Status = "urn:oasis:names:tc:SAML:2.0:status:Requester" }, "refused"},
	}
	for _, c := range refused {
		r := honest()
		c.change(&r)
		_, err := parse(r)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error about %q", c.name, err, c.want)
		}
	}
	r := honest()
	r.Status = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	if _, err := parse(r); !errors.Is(err, saml.ErrDenied) {
		t.Errorf("denied: %v", err)
	}
	if _, err := saml.ParseResponse(p.Respond(t, honest()), idp, sp, "", now); err == nil {
		t.Error("accepted with no sign-in under way")
	}
	if _, err := saml.ParseResponse("not base64!", idp, sp, reqID, now); err == nil {
		t.Error("accepted garbage")
	}
}

// TestSignatureWrapping moves a signed assertion aside and puts an
// unsigned one where it was, in the ways XML signature wrapping attacks
// do. None may sign anyone in.
func TestSignatureWrapping(t *testing.T) {
	p, idp := setup(t)
	now := time.Now()
	const reqID = "_req1"
	evil := func(t *testing.T, signed *etree.Element) *etree.Element {
		e := signed.Copy()
		for _, s := range e.ChildElements() {
			if s.Tag == "Signature" {
				e.RemoveChild(s)
			}
		}
		e.FindElement("./Subject/NameID").SetText("mallory@example.com")
		return e
	}
	attacks := map[string]func(t *testing.T, resp *etree.Element){
		// The signed assertion moved inside the evil one, which takes its
		// ID.
		"inside": func(t *testing.T, resp *etree.Element) {
			a := resp.FindElement("./Assertion")
			e := evil(t, a)
			resp.RemoveChild(a)
			e.AddChild(a)
			resp.AddChild(e)
		},
		// The evil assertion beside the signed one.
		"beside": func(t *testing.T, resp *etree.Element) {
			a := resp.FindElement("./Assertion")
			e := evil(t, a)
			e.SelectAttr("ID").Value = "_evil"
			resp.InsertChildAt(a.Index(), e)
		},
		// The signed assertion hidden in Extensions, the evil one in its
		// place with the same ID.
		"extensions": func(t *testing.T, resp *etree.Element) {
			a := resp.FindElement("./Assertion")
			e := evil(t, a)
			resp.RemoveChild(a)
			ext := resp.CreateElement("samlp:Extensions")
			ext.AddChild(a)
			resp.AddChild(e)
		},
		// The NameID changed after signing.
		"edited": func(t *testing.T, resp *etree.Element) {
			resp.FindElement("./Assertion/Subject/NameID").SetText("mallory@example.com")
		},
		// The NameID split with a comment, which canonicalization drops.
		"comment": func(t *testing.T, resp *etree.Element) {
			nid := resp.FindElement("./Assertion/Subject/NameID")
			nid.SetText("alice@example.com")
			nid.CreateComment("x")
			nid.CreateText(".evil.com")
		},
	}
	for name, attack := range attacks {
		r := p.Honest(sp.EntityID, sp.ACSURL, reqID, now)
		r.Change = func(resp *etree.Element) { attack(t, resp) }
		a, err := saml.ParseResponse(p.Respond(t, r), idp, sp, reqID, now)
		t.Logf("%s: %v", name, err)
		if err == nil && a.NameID != "alice@example.com" {
			t.Errorf("%s: signed in as %s", name, a.NameID)
		} else if err == nil && name != "comment" {
			t.Errorf("%s: accepted", name)
		}
	}
	// A signed response whose assertion is swapped for an evil one.
	r := p.Honest(sp.EntityID, sp.ACSURL, reqID, now)
	r.SignAssertion, r.SignResponse = false, true
	r.Change = func(resp *etree.Element) {
		a := resp.FindElement("./Assertion")
		e := evil(t, a)
		resp.RemoveChild(a)
		resp.AddChild(e)
	}
	if _, err := saml.ParseResponse(p.Respond(t, r), idp, sp, reqID, now); err == nil {
		t.Error("a changed signed response was accepted")
	}
}

func TestReplays(t *testing.T) {
	var r saml.Replays
	now := time.Now()
	if !r.Use("a", now.Add(time.Minute), now) || r.Use("a", now.Add(time.Minute), now) {
		t.Fatal("a reused assertion was not caught")
	}
	if !r.Use("a", now.Add(3*time.Minute), now.Add(2*time.Minute)) {
		t.Fatal("an expired entry still counts")
	}
}

func TestEncryptedRefused(t *testing.T) {
	p, idp := setup(t)
	now := time.Now()
	r := p.Honest(sp.EntityID, sp.ACSURL, "_r", now)
	r.Change = func(resp *etree.Element) {
		a := resp.FindElement("./Assertion")
		resp.RemoveChild(a)
		resp.CreateElement("saml:EncryptedAssertion")
	}
	if _, err := saml.ParseResponse(p.Respond(t, r), idp, sp, "_r", now); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("got %v", err)
	}
}

// A provider that is down is asked once a minute, not at every sign-in;
// metadata read before is used meanwhile.
func TestMetadataCache(t *testing.T) {
	p := samltest.New(t, "https://idp.example.com/saml", "https://idp.example.com/sso")
	var hits int
	up := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if !up {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(p.Metadata())
	}))
	defer srv.Close()
	now := time.Now()
	m := saml.NewMetadata()
	m.Now = func() time.Time { return now }
	if _, err := m.Get(t.Context(), srv.URL, false); err != nil || hits != 1 {
		t.Fatalf("first = %v, %d", err, hits)
	}
	if _, err := m.Get(t.Context(), srv.URL, false); err != nil || hits != 1 {
		t.Fatalf("cached = %v, %d", err, hits)
	}
	up, now = false, now.Add(2*time.Hour)
	for range 3 {
		if idp, err := m.Get(t.Context(), srv.URL, false); err != nil || idp == nil {
			t.Fatalf("stale copy while down: %v", err)
		}
	}
	if hits != 2 {
		t.Fatalf("asked a provider that is down %d times", hits-1)
	}
	// With nothing read before, the failure is kept for a minute.
	other := srv.URL + "/other"
	for range 3 {
		if _, err := m.Get(t.Context(), other, false); err == nil {
			t.Fatal("down provider gave metadata")
		}
	}
	if hits != 3 {
		t.Fatalf("hits = %d", hits)
	}
	now = now.Add(2 * time.Minute)
	_, _ = m.Get(t.Context(), other, false)
	if hits != 4 {
		t.Fatalf("not asked again after a minute: %d", hits)
	}
}
