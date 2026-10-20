// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package scim

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestDecodeUserEntra(t *testing.T) {
	// What Entra ID sends to add a user.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
	"externalId":"0a21f0f2-8d2a-4f8e-bf98-7b2c5a8d5e1a","userName":"Alice@Contoso.com","active":true,
	"emails":[{"primary":true,"type":"work","value":"alice@contoso.com"}],"meta":{"resourceType":"User"},
	"name":{"formatted":"Alice Smith","familyName":"Smith","givenName":"Alice"},
	"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"SOC"}}`
	u, err := DecodeUser([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if u.UserName != "Alice@Contoso.com" || u.ExternalID != "0a21f0f2-8d2a-4f8e-bf98-7b2c5a8d5e1a" || !u.Active ||
		u.FullName() != "Alice Smith" || u.PrimaryEmail() != "alice@contoso.com" {
		t.Errorf("got %+v", u)
	}
}

func TestDecodeUserOkta(t *testing.T) {
	// Okta's, with the active flag as a string and no displayName.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bob@example.com",
	"name":{"givenName":"Bob","familyName":"Jones"},"emails":[{"value":"bob@home.example","type":"home"},{"value":"bob@example.com","type":"work"}],
	"displayName":"","locale":"en-US","groups":[],"password":"ignored","active":"False"}`
	u, err := DecodeUser([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if u.Active || u.FullName() != "Bob Jones" || u.PrimaryEmail() != "bob@example.com" {
		t.Errorf("got %+v", u)
	}
	if u, _ := DecodeUser([]byte(`{"userName":"x"}`)); !u.Active {
		t.Error("a user without active should be active")
	}
	for _, bad := range []string{`[]`, `{"userName":5}`, `{"active":"maybe"}`, `{"emails":"a@b"}`, `{"name":"Al"}`} {
		if _, err := DecodeUser([]byte(bad)); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

func TestParseFilter(t *testing.T) {
	for in, want := range map[string]Filter{
		`userName eq "alice@contoso.com"`: {"username", "alice@contoso.com"},
		`USERNAME  EQ "a\"b"`:             {"username", `a"b`},
		`externalId eq "0a21"`:            {"externalid", "0a21"},
		`emails.value eq "a@b.c"`:         {"emails.value", "a@b.c"},
		`emails eq "a@b.c"`:               {"emails.value", "a@b.c"},
		`id eq "alice"`:                   {"id", "alice"},
		UserSchema + `:userName eq "x"`:   {"username", "x"},
		"":                                {},
	} {
		got, err := ParseFilter(in)
		if err != nil || got != want {
			t.Errorf("%q: got %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{`userName`, `userName eq`, `userName co "a"`, `userName eq alice`, `title eq "x"`,
		`userName eq "a" and active eq true`, `userName eq "a" or userName eq "b"`} {
		if _, err := ParseFilter(bad); !errors.Is(err, ErrFilter) {
			t.Errorf("%q: got %v", bad, err)
		}
	}
	u := &User{ID: "alice", UserName: "Alice@x.com", ExternalID: "E1", Emails: []Email{{Value: "A@x.com"}}}
	for f, want := range map[Filter]bool{
		{"username", "alice@X.com"}: true, {"externalid", "E1"}: true, {"externalid", "e1"}: false,
		{"emails.value", "a@x.com"}: true, {"id", "alice"}: true, {"id", "bob"}: false, {}: true,
	} {
		if f.Match(u) != want {
			t.Errorf("%+v: got %v", f, !want)
		}
	}
}

func patch(t *testing.T, u *User, body string) error {
	t.Helper()
	ops, err := DecodePatch([]byte(body))
	if err != nil {
		return err
	}
	return Apply(u, ops)
}

func TestApplyEntra(t *testing.T) {
	u := &User{UserName: "alice@contoso.com", Active: true}
	err := patch(t, u, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
	{"op":"Add","path":"displayName","value":"Alice Smith"},
	{"op":"Replace","path":"emails[type eq \"work\"].value","value":"alice@contoso.com"},
	{"op":"Add","path":"name.givenName","value":"Alice"},
	{"op":"Replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"SOC"},
	{"op":"Replace","path":"externalId","value":"E1"},
	{"op":"Replace","path":"active","value":"False"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if u.Active || u.DisplayName != "Alice Smith" || u.PrimaryEmail() != "alice@contoso.com" || u.Name.GivenName != "Alice" || u.ExternalID != "E1" {
		t.Errorf("got %+v", u)
	}
}

func TestApplyOkta(t *testing.T) {
	u := &User{UserName: "bob@example.com", Active: true, DisplayName: "Bob"}
	if err := patch(t, u, `{"Operations":[{"op":"replace","value":{"active":false}}]}`); err != nil {
		t.Fatal(err)
	}
	if u.Active || u.DisplayName != "Bob" {
		t.Errorf("got %+v", u)
	}
	// Okta's no-path replace of several attributes.
	if err := patch(t, u, `{"Operations":[{"op":"replace","value":{"name":{"givenName":"Rob"},"name.familyName":"Jones",
		"urn:ietf:params:scim:schemas:core:2.0:User:displayName":"Rob Jones","active":true,
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":{"value":"x"}}}}]}`); err != nil {
		t.Fatal(err)
	}
	if !u.Active || u.Name.GivenName != "Rob" || u.Name.FamilyName != "Jones" || u.FullName() != "Rob Jones" {
		t.Errorf("got %+v", u)
	}
	if err := patch(t, u, `{"Operations":[{"op":"remove","path":"displayName"},{"op":"remove","path":"emails"}]}`); err != nil {
		t.Fatal(err)
	}
	if u.DisplayName != "" || u.FullName() != "Rob Jones" {
		t.Errorf("got %+v", u)
	}
}

func TestApplyRefuses(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"Operations":[]}`, `{"Operations":[{"op":"move","path":"active","value":true}]}`,
		`{"Operations":[{"op":"remove"}]}`, `{"Operations":[{"op":"remove","path":"userName"}]}`,
		`{"Operations":[{"op":"replace","path":"active"}]}`, `{"Operations":[{"op":"replace","value":"x"}]}`,
		`{"Operations":[{"op":"replace","path":"active","value":"yes"}]}`,
	} {
		u := &User{UserName: "a"}
		err := patch(t, u, body)
		var se *Error
		if !errors.As(err, &se) || se.Status != 400 {
			t.Errorf("%s: got %v", body, err)
		}
	}
}

func TestErrorJSON(t *testing.T) {
	b, _ := json.Marshal(&Error{Status: 409, ScimType: "uniqueness", Detail: "taken"})
	if string(b) != `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"409","scimType":"uniqueness","detail":"taken"}` {
		t.Error(string(b))
	}
}
