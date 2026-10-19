package users

import (
	"encoding/pem"
	"strings"
	"testing"
)

func TestLDAPSettingsProblems(t *testing.T) {
	base := func() LDAPSettings {
		s := Preset(TypeActiveDirectory)
		s.Enabled = on()
		s.URL = "ldaps://dc1.corp.example.com"
		s.UserBaseDN = "DC=corp,DC=example,DC=com"
		s.AdminGroups = []string{"CN=Admins,OU=Groups,DC=corp,DC=example,DC=com"}
		return s
	}
	if p := func() []Problem { s := base(); return s.Problems() }(); len(p) != 0 {
		t.Fatalf("good settings: %v", p)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}))
	badCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}))
	for _, c := range []struct {
		field, want string
		change      func(*LDAPSettings)
	}{
		{"type", "choose ad", func(s *LDAPSettings) { s.Type = "" }},
		{"type", "must be ad", func(s *LDAPSettings) { s.Type = "novell" }},
		{"url", "with an optional :port", func(s *LDAPSettings) { s.URL = "ldaps://dc1/path" }},
		{"url", "with an optional :port", func(s *LDAPSettings) { s.URL = "https://dc1" }},
		{"failover_url", "port \"0\" must be 1-65535", func(s *LDAPSettings) { s.FailoverURL = "ldap://dc2:0" }},
		{"ca_cert", "holds a private key", func(s *LDAPSettings) { s.CACert = keyPEM }},
		{"ca_cert", "could not be read", func(s *LDAPSettings) { s.CACert = badCert }},
		{"connect_timeout_seconds", "1-120", func(s *LDAPSettings) { s.ConnectTimeout = 0 }},
		{"timeout_seconds", "1-300", func(s *LDAPSettings) { s.Timeout = 301 }},
		{"user_filter", "enter a search filter", func(s *LDAPSettings) { s.UserFilter = "" }},
		{"user_filter", "not valid LDAP filter", func(s *LDAPSettings) { s.UserFilter = "(uid={username}" }},
		{"username_attribute", "enter the attribute", func(s *LDAPSettings) { s.UsernameAttribute = "" }},
		{"email_attribute", "is not an attribute name", func(s *LDAPSettings) { s.EmailAttribute = "e mail" }},
		{"group_search", "must be memberof or search", func(s *LDAPSettings) { s.GroupSearch = "both" }},
		{"group_filter", "must contain {dn} or {username}", func(s *LDAPSettings) {
			s.GroupSearch, s.GroupFilter = GroupsSearch, "(objectClass=group)"
		}},
		{"viewer_groups", "is not a group DN", func(s *LDAPSettings) { s.ViewerGroups = []string{""} }},
		{"default_role", "must be none or viewer", func(s *LDAPSettings) { s.DefaultRole = "admin" }},
		{"admin_groups", "map at least one group", func(s *LDAPSettings) { s.AdminGroups = nil }},
	} {
		s := base()
		c.change(&s)
		found := false
		for _, p := range s.Problems() {
			if p.Field == c.field && strings.Contains(p.Message, c.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s %q: %v", c.field, c.want, s.Problems())
		}
	}
	// Switched off, missing values are not problems.
	s := LDAPSettings{ConnectTimeout: 5, Timeout: 10, DefaultRole: "none", GroupSearch: GroupsMemberOf}
	if p := s.Problems(); len(p) != 0 {
		t.Errorf("empty and off: %v", p)
	}
}

func TestLDAPSettingsHelpers(t *testing.T) {
	if got := Preset("novell"); got.Type != "" || got.URL != "" {
		t.Errorf("unknown preset = %+v", got)
	}
	s := LDAPSettings{Type: " ", UserBaseDN: "OU=People"}
	s.Normalize()
	if s.Type != TypeActiveDirectory {
		t.Errorf("type = %q", s.Type)
	}
	if got := s.groupBase("not a dn"); got != "OU=People" {
		t.Errorf("group base = %q", got)
	}
	if !sameDN("not=a=dn,,", " NOT=A=DN,, ") || sameDN("not=a=dn,,", "x") {
		t.Error("sameDN on text that is not a DN")
	}

	a := Preset(TypeActiveDirectory)
	a.URL, a.BindDN = "ldaps://DC1:636", "CN=svc, OU=Service,DC=corp"
	b := a
	b.URL, b.BindDN = "ldaps://dc1:636", "cn=SVC,ou=service,dc=corp"
	fa, fb := BindField(a), BindField(b)
	if fa != fb || !strings.HasPrefix(fa, BindPasswordField+"@ldaps://dc1:636,;") {
		t.Errorf("same connection: %q vs %q", fa, fb)
	}
	b.StartTLS = true
	if BindField(b) == fa {
		t.Error("StartTLS not in the field")
	}
	b.StartTLS, b.BindDN = false, "cn=other,dc=corp"
	if BindField(b) == fa {
		t.Error("bind DN not in the field")
	}
	if normDN(" Not A DN ") != "not a dn" || normDN("CN=B+CN=a, DC=X") != "cn=a+cn=b,dc=x" {
		t.Errorf("normDN = %q, %q", normDN(" Not A DN "), normDN("CN=B+CN=a, DC=X"))
	}

	w := LDAPSettings{URL: "ldaps://dc1", FailoverURL: "LDAP://dc2", TLSSkipVerify: true}
	if got := w.Warnings(); len(got) != 2 || !strings.Contains(got[0], "unencrypted") {
		t.Errorf("warnings = %v", got)
	}
	w.StartTLS, w.TLSSkipVerify = true, false
	if got := w.Warnings(); len(got) != 0 {
		t.Errorf("StartTLS warnings = %v", got)
	}
}
