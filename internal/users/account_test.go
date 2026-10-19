package users

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users/ldaptest"
)

func TestDomain(t *testing.T) {
	for in, want := range map[string]string{
		"OU=Staff,DC=corp,DC=example,DC=com": "corp.example.com",
		"dc=Example,dc=ORG":                  "example.org",
		"":                                   "",
		"OU=Staff":                           "",
	} {
		if got := Domain(in); got != want {
			t.Errorf("Domain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteProblem(t *testing.T) {
	ok := Preset(TypeActiveDirectory)
	ok.URL, ok.UserBaseDN = "ldaps://dc1.corp.example.com", ldaptest.ADBase
	if p := WriteProblem(ok); p != "" {
		t.Errorf("ldaps = %q", p)
	}
	for want, change := range map[string]func(*LDAPSettings){
		"Set up the directory first": func(s *LDAPSettings) { s.UserBaseDN = "" },
		"is not valid":               func(s *LDAPSettings) { s.URL = "ldaps://dc1\x7f" },
		"needs an encrypted":         func(s *LDAPSettings) { s.URL = "ldap://dc1.corp.example.com" },
		"certificate checked":        func(s *LDAPSettings) { s.TLSSkipVerify = true },
	} {
		s := ok
		change(&s)
		if p := WriteProblem(s); !strings.Contains(p, want) {
			t.Errorf("%s: %q", want, p)
		}
	}
	s := ok
	s.URL, s.StartTLS = "ldap://dc1.corp.example.com", true
	if p := WriteProblem(s); p != "" {
		t.Errorf("StartTLS = %q", p)
	}
}

func TestChangeActiveDirectoryAccount(t *testing.T) {
	ctx := context.Background()
	srv := startFake(t, ldaptest.Options{TLS: true, ActiveDirectory: true}, ldaptest.LoadActiveDirectory)
	srv.Add("CN=Odd Flags,OU=Staff,"+ldaptest.ADBase, map[string][]string{"objectClass": {"user"}, "objectCategory": {"person"},
		"sAMAccountName": {"odd"}, "userAccountControl": {"lots"}})
	s := adSettings(srv)

	// Without write rights the directory refuses, and the error says what
	// to delegate.
	_, err := ChangeAccount(ctx, s, AccountChange{Login: `CORP\bob`, Disable: true})
	var de *DirectoryError
	if !errors.As(err, &de) || de.Code != "write_refused" || !strings.Contains(de.Message, "Read/Write userAccountControl") {
		t.Fatalf("no write rights = %v", err)
	}
	srv.AllowWrite(ldaptest.ADService)

	// A dry run finds the account and changes nothing.
	r, err := ChangeAccount(ctx, s, AccountChange{Login: "bob@corp.example.com", Disable: true, DryRun: true})
	if err != nil || r.DN != ldaptest.ADBobDN || r.Before != "512" || r.After != "514" || !r.Changed || r.Username != "bob" {
		t.Fatalf("dry run = %+v, %v", r, err)
	}
	if got := srv.Attr(ldaptest.ADBobDN, "userAccountControl"); !slices.Equal(got, []string{"512"}) {
		t.Errorf("dry run changed it: %v", got)
	}
	r, err = ChangeAccount(ctx, s, AccountChange{Login: "bob", Disable: true})
	if err != nil || !r.Changed || r.Server != srv.URL {
		t.Fatalf("disable = %+v, %v", r, err)
	}
	if got := srv.Attr(ldaptest.ADBobDN, "userAccountControl"); !slices.Equal(got, []string{"514"}) {
		t.Errorf("after disable: %v", got)
	}
	if r, err := ChangeAccount(ctx, s, AccountChange{Login: "bob", Disable: true}); err != nil || r.Changed {
		t.Errorf("disable again = %+v, %v", r, err)
	}
	n := len(srv.Modifies())
	if r, err := ChangeAccount(ctx, s, AccountChange{Login: "eve"}); err != nil || !r.Changed || r.After != "512" {
		t.Errorf("enable eve = %+v, %v", r, err)
	}
	if got := srv.Modifies(); len(got) != n+1 || !strings.Contains(got[n], "userAccountControl=512") {
		t.Errorf("modifies = %v", got)
	}

	for want, ch := range map[string]AccountChange{
		"more than one account":    {Login: "pat", Disable: true},
		"no account named":         {Login: "nobody", Disable: true},
		"cannot change itself":     {Login: "alice", Disable: true, BindDN: ldaptest.ADAliceDN, BindPassword: ldaptest.Password},
		"is not an account name":   {Login: "a/b", Disable: true},
		"could not read":           {Login: "odd", Disable: true},
		"allowed to write":         {Login: "bob", BindDN: ldaptest.ADAliceDN},
		"invalid credentials|bind": {Login: "bob", BindDN: ldaptest.ADAliceDN, BindPassword: "wrong"},
	} {
		_, err := ChangeAccount(ctx, s, ch)
		if err == nil || !matchesAny(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
	plain := s
	plain.URL = strings.Replace(srv.URL, "ldaps://", "ldap://", 1)
	if _, err := ChangeAccount(ctx, plain, AccountChange{Login: "bob"}); err == nil || !strings.Contains(err.Error(), "encrypted connection") {
		t.Errorf("plain = %v", err)
	}
	if _, err := CheckWriteAccount(ctx, plain, AccountChange{}); err == nil {
		t.Error("plain check passed")
	}

	// The test of an action signs in and finds the account.
	steps, err := CheckWriteAccount(ctx, s, AccountChange{Login: "bob"})
	if err != nil || len(steps) != 3 || !strings.Contains(steps[0].Message, "over") || steps[1].Message != "Signed in as "+ldaptest.ADService+"." ||
		!strings.Contains(steps[2].Message, "it is disabled now") {
		t.Fatalf("check = %+v, %v", steps, err)
	}
	if steps, err := CheckWriteAccount(ctx, s, AccountChange{Login: "carol"}); err != nil || !strings.Contains(steps[2].Message, "it is enabled now") {
		t.Errorf("check carol = %+v, %v", steps, err)
	}
	if steps, err := CheckWriteAccount(ctx, s, AccountChange{}); err != nil || len(steps) != 2 {
		t.Errorf("check without a login = %+v, %v", steps, err)
	}
	if steps, err := CheckWriteAccount(ctx, s, AccountChange{Login: "nobody"}); err == nil || len(steps) != 2 {
		t.Errorf("check nobody = %+v, %v", steps, err)
	}
	if steps, err := CheckWriteAccount(ctx, s, AccountChange{BindDN: ldaptest.ADAliceDN, BindPassword: "wrong"}); err == nil || len(steps) != 1 {
		t.Errorf("check wrong password = %+v, %v", steps, err)
	}
	if _, err := CheckWriteAccount(ctx, s, AccountChange{BindDN: ldaptest.ADAliceDN}); err == nil || !strings.Contains(err.Error(), "allowed to write") {
		t.Errorf("check without password = %v", err)
	}
	down := s
	down.URL = "ldaps://127.0.0.1:1"
	if _, err := CheckWriteAccount(ctx, down, AccountChange{}); err == nil {
		t.Error("check against no server passed")
	}
	if _, err := ChangeAccount(ctx, down, AccountChange{Login: "bob"}); err == nil {
		t.Error("change against no server passed")
	}
}

func matchesAny(s, alternatives string) bool {
	for _, a := range strings.Split(alternatives, "|") {
		if strings.Contains(strings.ToLower(s), strings.ToLower(a)) {
			return true
		}
	}
	return false
}

func TestChangeOpenLDAPAccount(t *testing.T) {
	ctx := context.Background()
	srv := startFake(t, ldaptest.Options{StartTLS: true}, ldaptest.LoadOpenLDAP)
	srv.AllowWrite(ldaptest.OLService)
	s := olSettings(srv)
	s.StartTLS, s.CACert = true, srv.CACert

	for want, ch := range map[string]AccountChange{
		"not Active Directory":  {Login: "bob", Disable: true},
		"such as nsAccountLock": {Login: "bob", Disable: true, Attribute: "bad attr!"},
		"enter the value":       {Login: "bob", Disable: true, Attribute: "nsAccountLock"},
	} {
		if _, err := ChangeAccount(ctx, s, ch); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
	lock := AccountChange{Login: "bob", Disable: true, Attribute: "nsAccountLock", Value: "TRUE"}
	r, err := ChangeAccount(ctx, s, lock)
	if err != nil || !r.Changed || r.Before != "" || r.After != "TRUE" || r.Username != "bob" {
		t.Fatalf("lock = %+v, %v", r, err)
	}
	if got := srv.Attr(ldaptest.OLBobDN, "nsAccountLock"); !slices.Equal(got, []string{"TRUE"}) {
		t.Errorf("after lock: %v", got)
	}
	if steps, err := CheckWriteAccount(ctx, s, lock); err != nil || !strings.Contains(steps[2].Message, "switched off (TRUE)") {
		t.Errorf("check = %+v, %v", steps, err)
	}
	if r, err := ChangeAccount(ctx, s, lock); err != nil || r.Changed {
		t.Errorf("lock again = %+v, %v", r, err)
	}
	unlock := AccountChange{Login: "bob", Attribute: "nsAccountLock"}
	if r, err := ChangeAccount(ctx, s, unlock); err != nil || !r.Changed || r.Before != "TRUE" {
		t.Errorf("unlock = %+v, %v", r, err)
	}
	if got := srv.Attr(ldaptest.OLBobDN, "nsAccountLock"); got != nil {
		t.Errorf("after unlock: %v", got)
	}
	if r, err := ChangeAccount(ctx, s, unlock); err != nil || r.Changed {
		t.Errorf("unlock again = %+v, %v", r, err)
	}
}

func TestDirectoryOffAndFiles(t *testing.T) {
	ctx := context.Background()
	d, err := OpenDirectory("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Enabled() || d.Path() != "" {
		t.Errorf("in memory: enabled %v, path %q", d.Enabled(), d.Path())
	}
	if _, err := d.Authenticate(ctx, "bob", "pw"); !errors.Is(err, ErrDirectoryOff) {
		t.Errorf("authenticate while off = %v", err)
	}
	if _, err := d.Lookup(ctx, "bob"); !errors.Is(err, ErrDirectoryOff) {
		t.Errorf("lookup while off = %v", err)
	}

	cfg := Preset(TypeOpenLDAP)
	fromYAML, err := OpenDirectory("", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := fromYAML.Save(ctx, cfg); !errors.Is(err, ErrReadOnly) {
		t.Errorf("save over the config file = %v", err)
	}

	path := filepath.Join(t.TempDir(), "directory.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDirectory(path, nil); err == nil || !strings.Contains(err.Error(), "is damaged") {
		t.Errorf("damaged file = %v", err)
	}
	if _, err := OpenDirectory(t.TempDir(), nil); err == nil {
		t.Error("a folder opened as the settings file")
	}

	// An empty user name is a wrong sign-in, not a search.
	s := Preset(TypeActiveDirectory)
	if _, err := lookup(ctx, &s, `CORP\`, "pw", true); !errors.Is(err, ErrBadCredentials) || err.Error() != ErrBadCredentials.Error() {
		t.Errorf("empty name = %v", err)
	}
	if (&DirectoryError{Message: "m"}).Detail() != "" {
		t.Error("detail without an error")
	}
}
