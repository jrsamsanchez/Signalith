package scim

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNamesAndEmails(t *testing.T) {
	u := &User{}
	if u.FullName() != "" || u.PrimaryEmail() != "" {
		t.Errorf("empty user = %q %q", u.FullName(), u.PrimaryEmail())
	}
	u.Emails = []Email{{Value: " first@example.com ", Type: "home"}, {Value: "second@example.com", Type: "other"}}
	if got := u.PrimaryEmail(); got != "first@example.com" {
		t.Errorf("first = %q", got)
	}
	u.Emails = append(u.Emails, Email{Value: "main@example.com", Primary: true})
	if got := u.PrimaryEmail(); got != "main@example.com" {
		t.Errorf("primary = %q", got)
	}
	u.SetEmail("  ")
	if u.Emails != nil {
		t.Errorf("emails = %+v", u.Emails)
	}
	u.SetEmail(" new@example.com ")
	if len(u.Emails) != 1 || u.PrimaryEmail() != "new@example.com" || u.Emails[0].Type != "work" {
		t.Errorf("set = %+v", u.Emails)
	}
	if err := (&Error{Status: 400, Detail: "bad"}); err.Error() != "bad" {
		t.Errorf("Error() = %q", err.Error())
	}
}

func TestPatchEdges(t *testing.T) {
	u := &User{UserName: "a", Active: true, Name: &Name{GivenName: "A"}, Emails: []Email{{Value: "a@example.com"}}}
	// Removing name, active (kept) and the work address.
	if err := patch(t, u, `{"Operations":[{"op":"remove","path":"name"},{"op":"remove","path":"active"},
		{"op":"remove","path":"emails[type eq \"work\"].value"}]}`); err != nil {
		t.Fatal(err)
	}
	if u.Name != nil || !u.Active || u.Emails != nil {
		t.Errorf("after remove = %+v", u)
	}
	// A null name clears it; a filter path not ending in .value is ignored;
	// a null string is empty.
	u.Name = &Name{GivenName: "B"}
	if err := patch(t, u, `{"Operations":[{"op":"replace","path":"name","value":null},
		{"op":"replace","path":"emails[type eq \"work\"].type","value":"home"},
		{"op":"replace","path":"displayName","value":null}]}`); err != nil {
		t.Fatal(err)
	}
	if u.Name != nil || u.Emails != nil || u.DisplayName != "" {
		t.Errorf("after nulls = %+v", u)
	}

	var many []string
	for range MaxOps + 1 {
		many = append(many, `{"op":"replace","path":"active","value":true}`)
	}
	for _, body := range []string{
		`not json`,
		`{"Operations":[` + strings.Join(many, ",") + `]}`,
		`{"Operations":[{"op":"replace","path":"name","value":{"givenName":5}}]}`,
		`{"Operations":[{"op":"replace","path":"emails[type eq \"work\"].value","value":5}]}`,
		`{"Operations":[{"op":"replace","path":"emails","value":[{"value":"x","primary":"maybe"}]}]}`,
		`{"Operations":[{"op":"replace","value":{"userName":5}}]}`,
	} {
		err := patch(t, &User{UserName: "a"}, body)
		var se *Error
		if !errors.As(err, &se) || se.Status != 400 {
			t.Errorf("%.80s: got %v", body, err)
		}
	}
}

func TestFilterEdges(t *testing.T) {
	if _, err := ParseFilter(fmt.Sprintf(`userName eq "%s"`, strings.Repeat("a", 1100))); !errors.Is(err, ErrFilter) {
		t.Errorf("long filter = %v", err)
	}
	f, err := ParseFilter(`emails eq "A@example.com"`)
	if err != nil || f.Attr != "emails.value" {
		t.Fatalf("emails = %+v %v", f, err)
	}
	if f.Match(&User{Emails: []Email{{Value: "b@example.com"}}}) {
		t.Error("another address matched")
	}
	if !f.Match(&User{Emails: []Email{{Value: "b@example.com"}, {Value: "a@EXAMPLE.com"}}}) {
		t.Error("the address did not match")
	}
	if (Filter{Attr: "title", Value: "x"}).Match(&User{}) {
		t.Error("an unknown attribute matched")
	}
}
