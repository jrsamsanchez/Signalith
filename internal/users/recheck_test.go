package users

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users/ldaptest"
)

// Groups are found even when they live outside the user base DN, as in
// most Active Directories (users in OU=Staff, groups in OU=Groups), with
// nested groups and no group base DN.
func TestNestedGroupsOutsideTheUserBase(t *testing.T) {
	srv := startFake(t, ldaptest.Options{TLS: true, ActiveDirectory: true}, ldaptest.LoadActiveDirectory)
	s := adSettings(srv)
	s.UserBaseDN = "OU=Staff," + ldaptest.ADBase
	u, err := signIn(t, directory(t, s), "alice", ldaptest.Password)
	if err != nil || u.Role != Admin || !slices.Contains(u.Groups, ldaptest.ADAdmins) {
		t.Fatalf("alice = %+v, %v", u, err)
	}
	// OpenLDAP with no group base DN searches the whole directory too.
	ol := startFake(t, ldaptest.Options{}, ldaptest.LoadOpenLDAP)
	o := olSettings(ol)
	o.GroupBaseDN = ""
	u, err = signIn(t, directory(t, o), "bob", ldaptest.Password)
	if err != nil || u.Role != Analyst {
		t.Errorf("openldap bob = %+v, %v", u, err)
	}
}

func TestNamingContext(t *testing.T) {
	for dn, want := range map[string]string{
		"CN=Alice Admin,OU=Staff,DC=corp,DC=example,DC=com": "DC=corp,DC=example,DC=com",
		`CN=Smith\, John,OU=Staff,dc=corp,dc=example`:       "dc=corp,dc=example",
		"uid=bob,ou=people,o=example":                       "",
		"not a dn":                                          "",
	} {
		if got := namingContext(dn); got != want {
			t.Errorf("namingContext(%q) = %q, want %q", dn, got, want)
		}
	}
}

func TestSameConnection(t *testing.T) {
	base := Preset(TypeActiveDirectory)
	base.URL, base.BindDN, base.CACert = "ldaps://dc1.corp.example.com", "CN=svc,DC=corp,DC=example,DC=com", "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"
	same := base.Clone()
	same.URL = " LDAPS://DC1.corp.example.com "
	same.BindDN = "cn=svc, dc=corp, dc=example, dc=com"
	same.UserBaseDN, same.AdminGroups = "OU=Staff,DC=corp,DC=example,DC=com", []string{"CN=x"}
	if !SameConnection(base, same) {
		t.Error("spelling and unrelated settings should not matter")
	}
	for name, change := range map[string]func(*LDAPSettings){
		"url":        func(s *LDAPSettings) { s.URL = "ldaps://evil.example.com" },
		"failover":   func(s *LDAPSettings) { s.FailoverURL = "ldap://evil.example.com" },
		"bind dn":    func(s *LDAPSettings) { s.BindDN = "CN=other,DC=corp,DC=example,DC=com" },
		"start tls":  func(s *LDAPSettings) { s.StartTLS = true },
		"skip check": func(s *LDAPSettings) { s.TLSSkipVerify = true },
		"ca":         func(s *LDAPSettings) { s.CACert = "" },
	} {
		c := base.Clone()
		change(&c)
		if SameConnection(base, c) {
			t.Errorf("a changed %s counts as the same connection", name)
		}
	}
}

// The directory says when someone's access should end, but only in ways
// a wrong password cannot cause.
func TestDirectorySaysWhenAccessEnds(t *testing.T) {
	srv := startFake(t, ldaptest.Options{TLS: true, ActiveDirectory: true}, ldaptest.LoadActiveDirectory)
	d := directory(t, adSettings(srv))
	revoked := func(err error) bool {
		var se *SignInError
		return errors.As(err, &se) && se.Revoke != ""
	}
	for _, c := range []struct {
		user, pass string
		revoke     bool
	}{
		{"dave", ldaptest.Password, true},   // in no mapped group
		{"eve", ldaptest.Password, true},    // disabled: not found
		{"nobody", "whatever", true},        // not found
		{"pat", ldaptest.Password, true},    // two entries match
		{"bob", "wrong-password", false},    // a wrong password proves nothing
		{"frank", ldaptest.Password, false}, // must change the password: still allowed
	} {
		if _, err := signIn(t, d, c.user, c.pass); revoked(err) != c.revoke {
			t.Errorf("%s: err = %v, revoke = %v, want %v", c.user, err, revoked(err), c.revoke)
		}
	}
	// Lookup checks someone again without their password.
	u, err := d.Lookup(context.Background(), "bob")
	if err != nil || u.Role != Analyst || u.Username != "bob" {
		t.Errorf("lookup bob = %+v %v", u, err)
	}
	if _, err := d.Lookup(context.Background(), "dave"); !revoked(err) || !errors.Is(err, ErrNoRole) {
		t.Errorf("lookup dave = %v", err)
	}
}

func TestStoreRefusedDirectoryUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SeeDirectoryUser(context.Background(), DirectoryUser{Username: "bob", DN: "CN=Bob,DC=x", Role: Analyst}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RefuseDirectoryUser(context.Background(), "carol", "gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("refuse unknown = %v", err)
	}
	s.Create(context.Background(), newUser("lena", Viewer))
	if _, _, err := s.RefuseDirectoryUser(context.Background(), "lena", "gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("refuse a local user = %v", err)
	}
	u, changed, err := s.RefuseDirectoryUser(context.Background(), "BOB", "in no group mapped to a role")
	if err != nil || !changed || u.Refused == "" {
		t.Fatalf("refuse bob = %+v %v %v", u, changed, err)
	}
	if _, changed, _ := s.RefuseDirectoryUser(context.Background(), "bob", "in no group mapped to a role"); changed {
		t.Error("refusing again for the same reason counted as news")
	}
	// It is kept across restarts.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := s2.Get("bob"); u.Refused != "in no group mapped to a role" {
		t.Errorf("after reopening: %+v", u)
	}
	// A new look at the directory, or a sign-in, gives access back.
	u, changed, err = s2.RefreshDirectoryUser(context.Background(), "bob", DirectoryUser{Username: "bob", DN: "CN=Bob,DC=x", Role: Viewer})
	if err != nil || !changed || u.Refused != "" || u.Role != Viewer || u.LastSignIn == nil {
		t.Errorf("refresh = %+v %v %v", u, changed, err)
	}
	s2.RefuseDirectoryUser(context.Background(), "bob", "gone")
	if u, _ := s2.SeeDirectoryUser(context.Background(), DirectoryUser{Username: "bob", Role: Admin}); u.Refused != "" || u.Role != Admin {
		t.Errorf("sign-in after refusal = %+v", u)
	}
}
