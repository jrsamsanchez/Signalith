package saml_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/jrsamsanchez/signalith/internal/saml"
	"github.com/jrsamsanchez/signalith/internal/saml/samltest"
	dsig "github.com/russellhaering/goxmldsig"
)

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// signedAfter builds r's response with its assertion changed by edit
// before the provider signs it, as a provider that sends such an
// assertion would.
func signedAfter(t *testing.T, p *samltest.IdP, r samltest.Response, edit func(a *etree.Element)) string {
	t.Helper()
	r.SignAssertion = false
	resp := p.Build(t, r)
	a := resp.FindElement("./Assertion")
	edit(a)
	ctx, err := dsig.NewSigningContext(p.Key, [][]byte{p.Cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(a)
	if err != nil {
		t.Fatal(err)
	}
	resp.RemoveChild(a)
	resp.AddChild(signed)
	if r.Change != nil {
		r.Change(resp)
	}
	return samltest.Encode(t, resp)
}

func setAttr(path, key, value string) func(a *etree.Element) {
	return func(a *etree.Element) { a.FindElement(path).CreateAttr(key, value) }
}

func remove(path string) func(a *etree.Element) {
	return func(a *etree.Element) {
		e := a.FindElement(path)
		e.Parent().RemoveChild(e)
	}
}

func twice(path string) func(a *etree.Element) {
	return func(a *etree.Element) {
		e := a.FindElement(path)
		e.Parent().AddChild(e.Copy())
	}
}

func TestSignedAssertionRefusals(t *testing.T) {
	p, idp := setup(t)
	now := time.Now()
	const reqID = "_req1"
	honest := p.Honest(sp.EntityID, sp.ACSURL, reqID, now)
	if a, err := saml.ParseResponse(signedAfter(t, p, honest, func(*etree.Element) {}), idp, sp, reqID, now); err != nil || a.NameID != "alice@example.com" {
		t.Fatalf("the helper's own response = %+v %v", a, err)
	}
	for _, c := range []struct {
		name string
		edit func(a *etree.Element)
		want string
	}{
		{"version", setAttr(".", "Version", "1.1"), "not SAML 2.0"},
		{"no issue time", func(a *etree.Element) { a.RemoveAttr("IssueInstant") }, "no issue time"},
		{"issue time not a time", setAttr(".", "IssueInstant", "yesterday"), "not a time"},
		{"no issuer", remove("./Issuer"), "no issuer"},
		{"two issuers", twice("./Issuer"), "may have only one"},
		{"issuer not an entity", setAttr("./Issuer", "Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"), "not an entity ID"},
		{"issuer holds an element", func(a *etree.Element) { a.FindElement("./Issuer").CreateElement("saml:X") }, "where text belongs"},
		{"no conditions", remove("./Conditions"), "no conditions"},
		{"two conditions", twice("./Conditions"), "may have only one"},
		{"conditions start not a time", setAttr("./Conditions", "NotBefore", "soon"), "not a time"},
		{"conditions end not a time", setAttr("./Conditions", "NotOnOrAfter", "later"), "not a time"},
		{"conditions expired", setAttr("./Conditions", "NotOnOrAfter", stamp(now.Add(-time.Hour))), "expired"},
		{"audience holds an element", func(a *etree.Element) {
			a.FindElement("./Conditions/AudienceRestriction/Audience").CreateElement("saml:X")
		}, "where text belongs"},
		{"no subject", remove("./Subject"), "no subject"},
		{"two subjects", twice("./Subject"), "may have only one"},
		{"encrypted name", func(a *etree.Element) { a.FindElement("./Subject").CreateElement("saml:EncryptedID") }, "encrypted"},
		{"no name", remove("./Subject/NameID"), "no NameID"},
		{"two names", twice("./Subject/NameID"), "may have only one"},
		{"name holds an element", func(a *etree.Element) { a.FindElement("./Subject/NameID").CreateElement("saml:X") }, "where text belongs"},
		{"empty name", func(a *etree.Element) { a.FindElement("./Subject/NameID").SetText(" ") }, "empty or too long"},
		{"long name", func(a *etree.Element) { a.FindElement("./Subject/NameID").SetText(strings.Repeat("n", 513)) }, "empty or too long"},
		{"not bearer", setAttr("./Subject/SubjectConfirmation", "Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"), "no bearer subject confirmation"},
		{"no confirmation data", remove("./Subject/SubjectConfirmation/SubjectConfirmationData"), "has no data"},
		{"two confirmation data", twice("./Subject/SubjectConfirmation/SubjectConfirmationData"), "may have only one"},
		{"confirmation end not a time", setAttr("./Subject/SubjectConfirmation/SubjectConfirmationData", "NotOnOrAfter", "x"), "not a time"},
		{"confirmation start not a time", setAttr("./Subject/SubjectConfirmation/SubjectConfirmationData", "NotBefore", "x"), "not a time"},
		{"confirmation with no end", func(a *etree.Element) {
			a.FindElement("./Subject/SubjectConfirmation/SubjectConfirmationData").RemoveAttr("NotOnOrAfter")
		}, "no expiry"},
		{"confirmation expired", setAttr("./Subject/SubjectConfirmation/SubjectConfirmationData", "NotOnOrAfter", stamp(now.Add(-time.Hour))), "expired"},
		{"confirmation with a start", setAttr("./Subject/SubjectConfirmation/SubjectConfirmationData", "NotBefore", stamp(now.Add(-time.Minute))), "may not have a NotBefore"},
		{"no authn statement", remove("./AuthnStatement"), "no authentication statement"},
		{"session over", setAttr("./AuthnStatement", "SessionNotOnOrAfter", stamp(now.Add(-time.Minute))), "session at the identity provider has ended"},
		{"session end not a time", setAttr("./AuthnStatement", "SessionNotOnOrAfter", "x"), "not a time"},
		{"too many attributes", func(a *etree.Element) {
			st := a.FindElement("./AttributeStatement")
			for i := range 201 {
				st.CreateElement("saml:Attribute").CreateAttr("Name", fmt.Sprintf("a%d", i))
			}
		}, "more than 200 attributes"},
		{"long value", func(a *etree.Element) {
			at := a.FindElement("./AttributeStatement").CreateElement("saml:Attribute")
			at.CreateAttr("Name", "long")
			at.CreateElement("saml:AttributeValue").SetText(strings.Repeat("v", 2049))
		}, "longer than 2048"},
	} {
		_, err := saml.ParseResponse(signedAfter(t, p, honest, c.edit), idp, sp, reqID, now)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}

	// Kept: a later end in the conditions, a later session end,
	// structured values (skipped) and nameless attributes (dropped); an
	// extra confirmation that is not a bearer is passed over.
	later := now.Add(30 * time.Minute)
	a, err := saml.ParseResponse(signedAfter(t, p, honest, func(a *etree.Element) {
		a.FindElement("./Conditions").CreateAttr("NotOnOrAfter", stamp(later))
		a.FindElement("./AuthnStatement").CreateAttr("SessionNotOnOrAfter", stamp(later))
		a.FindElement("./Subject").CreateElement("saml:SubjectConfirmation").CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches")
		st := a.FindElement("./AttributeStatement")
		at := st.CreateElement("saml:Attribute")
		at.CreateAttr("Name", "structured")
		at.CreateElement("saml:AttributeValue").CreateElement("saml:X")
		at.CreateElement("saml:AttributeValue").SetText("plain")
		st.CreateElement("saml:Attribute").CreateElement("saml:AttributeValue").SetText("nameless")
	}), idp, sp, reqID, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := later.Truncate(time.Millisecond).Add(saml.Skew); !a.Expires.Equal(want) {
		t.Errorf("expires %v, want %v", a.Expires, want)
	}
	if got := a.Attributes["structured"]; len(got) != 1 || got[0] != "plain" {
		t.Errorf("structured = %v", got)
	}
	if _, ok := a.Attributes[""]; ok {
		t.Error("a nameless attribute was kept")
	}
}

func TestResponseRefusals(t *testing.T) {
	p, idp := setup(t)
	now := time.Now()
	const reqID = "_req1"
	parse := func(r samltest.Response) error {
		_, err := saml.ParseResponse(p.Respond(t, r), idp, sp, reqID, now)
		return err
	}
	for _, c := range []struct {
		name   string
		change func(resp *etree.Element)
		want   string
	}{
		{"version", func(resp *etree.Element) { resp.CreateAttr("Version", "1.0") }, "the response is not SAML 2.0"},
		{"no ID", func(resp *etree.Element) { resp.RemoveAttr("ID") }, "the response has no ID"},
		{"issue time", func(resp *etree.Element) { resp.CreateAttr("IssueInstant", "x") }, "not a time"},
		{"two issuers", func(resp *etree.Element) { resp.InsertChildAt(0, resp.FindElement("./Issuer").Copy()) }, "may have only one"},
		{"no status", func(resp *etree.Element) { resp.RemoveChild(resp.FindElement("./Status")) }, "no status"},
		{"no status code", func(resp *etree.Element) {
			st := resp.FindElement("./Status")
			st.RemoveChild(st.FindElement("./StatusCode"))
		}, "no status code"},
		{"no assertion", func(resp *etree.Element) { resp.RemoveChild(resp.FindElement("./Assertion")) }, "0 assertions"},
		{"two IDs", func(resp *etree.Element) { resp.CreateAttr("x:ID", "_dup") }, "two IDs"},
		{"two signatures", func(resp *etree.Element) {
			a := resp.FindElement("./Assertion")
			a.AddChild(a.FindElement("./Signature").Copy())
		}, "2 signatures"},
		{"signed with no ID", func(resp *etree.Element) { resp.FindElement("./Assertion").RemoveAttr("ID") }, "has no ID"},
		{"signature for another", func(resp *etree.Element) {
			resp.FindElement("./Assertion/Signature/SignedInfo/Reference").CreateAttr("URI", "#_elsewhere")
		}, "does not refer to it alone"},
	} {
		r := p.Honest(sp.EntityID, sp.ACSURL, reqID, now)
		r.Change = c.change
		if err := parse(r); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}

	// A refusal names the sub-status and the provider's message.
	r := p.Honest(sp.EntityID, sp.ACSURL, reqID, now)
	r.Status = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	r.Change = func(resp *etree.Element) {
		st := resp.FindElement("./Status")
		st.FindElement("./StatusCode").CreateElement("samlp:StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:RequestDenied")
		st.CreateElement("samlp:StatusMessage").SetText("not in the SOC group")
	}
	if err := parse(r); err == nil || !strings.Contains(err.Error(), "Requester / RequestDenied: not in the SOC group") {
		t.Errorf("denied = %v", err)
	}

	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for name, c := range map[string]struct {
		in   string
		idp  *saml.IdP
		want string
	}{
		"no provider":  {enc("<x/>"), nil, "no identity provider"},
		"no certs":     {enc("<x/>"), &saml.IdP{EntityID: "x"}, "no identity provider"},
		"too large":    {strings.Repeat("A", saml.MaxResponse+1), idp, "larger than"},
		"not XML":      {enc("<x"), idp, "not XML"},
		"empty":        {enc("<!-- nothing -->"), idp, "empty"},
		"not response": {enc(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`), idp, "not a SAML 2.0 Response"},
	} {
		if _, err := saml.ParseResponse(c.in, c.idp, sp, reqID, now); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestMetadataRefusals(t *testing.T) {
	p, _ := setup(t)
	md := string(p.Metadata())
	certText := base64.StdEncoding.EncodeToString(p.Cert.Raw)
	for name, c := range map[string]struct{ doc, want string }{
		"too large":    {strings.Repeat(" ", saml.MaxMetadata+1), "larger than"},
		"not XML":      {"<md:", "not XML"},
		"empty":        {"<!-- -->", "empty"},
		"entity space": {strings.Replace(md, `entityID="`+p.EntityID+`"`, `entityID="a b"`, 1), "entityID"},
		"cert element": {strings.Replace(md, certText, "<ds:X/>", 1), "where text belongs"},
		"cert base64":  {strings.Replace(md, certText, "***", 1), "not base64"},
		"cert junk":    {strings.Replace(md, certText, base64.StdEncoding.EncodeToString([]byte("junk")), 1), "cannot be read"},
		"no redirect":  {strings.Replace(md, saml.BindingRedirect, "urn:example:other", 1), "HTTP-Redirect"},
	} {
		if _, err := saml.ParseMetadata([]byte(c.doc)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// The same certificate twice is kept once.
	twiceCert := strings.Replace(md, "</ds:X509Data>", "<ds:X509Certificate>"+certText+"</ds:X509Certificate></ds:X509Data>", 1)
	if idp, err := saml.ParseMetadata([]byte(twiceCert)); err != nil || len(idp.Certs) != 1 {
		t.Errorf("twice = %+v %v", idp, err)
	}
	// An http address on this machine is allowed, for tests.
	local := strings.ReplaceAll(md, p.SSOURL, "http://127.0.0.1:8443/sso")
	if idp, err := saml.ParseMetadata([]byte(local)); err != nil || idp.SSOURL != "http://127.0.0.1:8443/sso" {
		t.Errorf("local = %+v %v", idp, err)
	}

	// Pasted metadata is parsed once; an answer is kept, errors too.
	a, err := saml.ParseMetadataCached([]byte(md))
	b, err2 := saml.ParseMetadataCached([]byte(md))
	if err != nil || err2 != nil || a != b {
		t.Errorf("cached = %p %p %v %v", a, b, err, err2)
	}
	if _, err := saml.ParseMetadataCached([]byte("<x/>")); err == nil {
		t.Error("bad metadata was taken")
	}
	if c, err := saml.ParseMetadataCached([]byte(md)); err != nil || c == a {
		t.Errorf("after another document = %p %v", c, err)
	}
}

func TestPresets(t *testing.T) {
	if saml.PresetFor(saml.Okta).ID != saml.Okta || saml.PresetFor("unknown").ID != saml.Other {
		t.Error("PresetFor")
	}
}

func TestReplaysFull(t *testing.T) {
	var r saml.Replays
	now := time.Now()
	for i := range 100_000 {
		if !r.Use(fmt.Sprint(i), now.Add(time.Minute), now) {
			t.Fatalf("refused %d", i)
		}
	}
	// Full of live entries: nothing more can be told apart.
	if r.Use("one more", now.Add(time.Minute), now) {
		t.Error("taken while full")
	}
	// Once they expire they make room.
	later := now.Add(2 * time.Minute)
	if !r.Use("one more", later.Add(time.Minute), later) {
		t.Error("refused after the others expired")
	}
	if r.Use("one more", later.Add(time.Minute), later) {
		t.Error("a replay after pruning was taken")
	}
}

func TestMetadataFetching(t *testing.T) {
	p := samltest.New(t, "https://idp.example.com/saml", "https://idp.example.com/sso")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/moved":
			http.Redirect(w, r, "/md", http.StatusFound)
		default:
			_, _ = w.Write(p.Metadata())
		}
	}))
	defer srv.Close()
	m := saml.NewMetadata()
	if _, err := m.Get(context.Background(), srv.URL+"/moved", false); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("redirect = %v", err)
	}
	if _, err := m.Fetch(context.Background(), "http://bad host/"); err == nil {
		t.Error("a bad address was fetched")
	}
	// fresh skips the cache and still stores what it read.
	first, err := m.Get(context.Background(), srv.URL+"/md", true)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := m.Get(context.Background(), srv.URL+"/md", false); err != nil || again != first {
		t.Errorf("after a fresh read = %p %v", again, err)
	}
}
