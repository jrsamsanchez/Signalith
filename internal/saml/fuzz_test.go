package saml_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/saml"
	"github.com/jrsamsanchez/signalith/internal/saml/samltest"
)

// FuzzParseMetadata feeds the metadata parser anything: it must refuse
// what it can't read, never panic.
func FuzzParseMetadata(f *testing.F) {
	p := samltest.New(f, "https://idp.example.com/saml", "https://idp.example.com/sso")
	f.Add(p.Metadata())
	f.Add([]byte(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:EntityDescriptor entityID="x"/></md:EntitiesDescriptor>`))
	f.Add([]byte(`<!DOCTYPE x>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = saml.ParseMetadata(data)
	})
}

// FuzzParseResponse feeds the response parser any XML, starting from a
// real signed response: nothing it makes may panic, or sign anyone in
// but the signed subject.
func FuzzParseResponse(f *testing.F) {
	p := samltest.New(f, "https://idp.example.com/saml", "https://idp.example.com/sso")
	idp, err := saml.ParseMetadata(p.Metadata())
	if err != nil {
		f.Fatal(err)
	}
	sp := saml.SP{EntityID: "https://siem.example.com/sp", ACSURL: "https://siem.example.com/acs"}
	now := time.Now()
	for _, both := range []bool{false, true} {
		r := p.Honest(sp.EntityID, sp.ACSURL, "_req", now)
		r.SignResponse = both
		raw, _ := base64.StdEncoding.DecodeString(p.Respond(f, r))
		f.Add(raw)
	}
	f.Add([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_a" Version="2.0" InResponseTo="_req"/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := saml.ParseResponse(base64.StdEncoding.EncodeToString(data), idp, sp, "_req", now)
		if err == nil && a.NameID != "alice@example.com" {
			t.Fatalf("signed in as %q", a.NameID)
		}
	})
}
