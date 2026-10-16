package users

import (
	"context"
	"errors"
	"testing"
)

func TestProvisionThenSignIn(t *testing.T) {
	s := NewMemory()
	s.BuiltinAdmin = "admin"
	ctx := context.Background()
	u, err := s.Provision(ctx, Provisioned{Username: "Alice@Contoso.com", Name: "Alice\x00 Smith", Email: "alice@contoso.com", ExternalID: "E1", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice@contoso.com" || u.Source != SourceSSO || !u.Pending() || u.Role != Viewer || u.Name != "Alice  Smith" || u.ExternalID != "E1" {
		t.Errorf("provisioned %+v", u)
	}
	if _, err := s.Provision(ctx, Provisioned{Username: "alice@contoso.com", Active: true}); !errors.Is(err, ErrExists) {
		t.Errorf("again: %v", err)
	}
	if _, err := s.Provision(ctx, Provisioned{Username: "ADMIN", Active: true}); !errors.Is(err, ErrNotSSO) {
		t.Errorf("built-in admin: %v", err)
	}
	if _, err := s.Create(ctx, NewUser{Username: "bob", Role: Analyst, Password: "a long password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Provision(ctx, Provisioned{Username: "bob", Active: true}); !errors.Is(err, ErrNotSSO) {
		t.Errorf("local user: %v", err)
	}

	// The first sign-in binds the identity, even with new users not
	// added, and keeps the provisioned name when the token has none.
	sub := SSOSubject("https://idp.example.com", "123")
	u, err = s.SeeSSOUser(ctx, SSOUser{Username: "alice@contoso.com", Role: Analyst, Subject: sub}, false)
	if err != nil {
		t.Fatal(err)
	}
	if u.Pending() || u.Subject != sub || u.Role != Analyst || u.Name != "Alice  Smith" || u.Email != "alice@contoso.com" {
		t.Errorf("signed in %+v", u)
	}
	// Then only that identity.
	if _, err := s.SeeSSOUser(ctx, SSOUser{Username: "alice@contoso.com", Role: Admin, Subject: SSOSubject("https://idp.example.com", "666")}, true); !errors.Is(err, ErrSSOOther) {
		t.Errorf("another identity: %v", err)
	}
}

func TestChangeProvisioned(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	if _, err := s.Provision(ctx, Provisioned{Username: "carol", Active: true}); err != nil {
		t.Fatal(err)
	}
	u, err := s.ChangeProvisioned(ctx, "carol", "", func(p *Provisioned) error {
		p.Username, p.Name, p.Active = "Carol", "Carol King", false
		return nil
	})
	if err != nil || u.Name != "Carol King" || !u.Disabled || u.SessionEpoch != 2 {
		t.Fatalf("changed %+v, %v", u, err)
	}
	// A disabled user stays out at sign-in.
	if u, err := s.SeeSSOUser(ctx, SSOUser{Username: "carol", Role: Admin, Subject: SSOSubject("https://idp.example.com", "1")}, true); err != nil || !u.Disabled {
		t.Errorf("sign-in of a disabled user: %+v, %v", u, err)
	}
	if _, err := s.ChangeProvisioned(ctx, "carol", "", func(p *Provisioned) error { p.Username = "caroline"; return nil }); !errors.Is(err, ErrRename) {
		t.Errorf("rename: %v", err)
	}
	if _, err := s.Create(ctx, NewUser{Username: "dave", Role: Admin, Password: "a long password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeProvisioned(ctx, "dave", "", func(p *Provisioned) error { p.Active = false; return nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("local user: %v", err)
	}
	if _, err := s.DeleteProvisioned(ctx, "dave", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete local user: %v", err)
	}
	if _, err := s.DeleteProvisioned(ctx, "carol", ""); err != nil {
		t.Errorf("delete: %v", err)
	}
	if n := len(s.SSOUsers()); n != 0 {
		t.Errorf("%d SSO users left", n)
	}
}
