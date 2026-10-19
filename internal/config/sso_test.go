package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/oidc"
	"github.com/jrsamsanchez/signalith/internal/saml"
)

// problemsHave checks that each want is in one of the problems, and that
// there are no others when exact is set.
func problemsHave(t *testing.T, name string, got []string, exact bool, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, w) }) {
			t.Errorf("%s: no problem %q in %q", name, w, got)
		}
	}
	if exact && len(got) != len(want) {
		t.Errorf("%s: problems %q, want %d", name, got, len(want))
	}
}

func TestOIDCProblems(t *testing.T) {
	for _, c := range []struct {
		name string
		o    OIDC
		want []string
	}{
		{"off and empty", OIDC{}, nil},
		{"on and empty", OIDC{Enabled: true}, []string{"auth.oidc.provider: choose", "auth.oidc.issuer: enter", "auth.oidc.client_id", "auth.oidc.admin_groups"}},
		{"bad values", OIDC{Provider: "facebook", Issuer: "ftp://idp", UsernameClaim: "a b", GroupsClaim: "x\"y", Scopes: []string{"", "a b"},
			DefaultRole: "admin", AllowedDomains: []string{"not a domain"}, ButtonLabel: strings.Repeat("x", 61)},
			[]string{"auth.oidc.provider: \"facebook\"", "auth.oidc.issuer:", "auth.oidc.username_claim", "auth.oidc.groups_claim",
				"auth.oidc.scopes: \"\"", "auth.oidc.scopes: \"a b\"", "auth.oidc.default_role", "auth.oidc.allowed_domains", "auth.oidc.button_label"}},
		{"google viewers from anywhere", OIDC{Enabled: true, Provider: oidc.Google, ClientID: "id", DefaultRole: "viewer"},
			[]string{"auth.oidc.allowed_domains: with Google"}},
		{"good", OIDC{Enabled: true, Provider: oidc.Entra, Issuer: "https://login.example.com/tenant/v2.0", ClientID: "id",
			AdminGroups: []string{"siem-admins"}, AllowedDomains: []string{"Example.com"}}, nil},
	} {
		cfg := &Config{}
		cfg.Auth.OIDC = c.o
		problemsHave(t, c.name, cfg.oidcProblems(), true, c.want...)
	}
}

func TestOIDCSettingsDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.Auth.OIDC = OIDC{Provider: oidc.Google, ClientID: " id "}
	s := cfg.OIDCSettings()
	if s.Issuer != oidc.GoogleIssuer || s.ClientID != "id" || len(s.Scopes) == 0 || s.UsernameClaim == "" || s.DefaultRole != "none" ||
		s.ButtonLabel != "Sign in with Google" || !s.NewUsers() {
		t.Errorf("google = %+v", s.OIDC)
	}
	no := false
	cfg.Auth.OIDC = OIDC{Provider: oidc.Other, Issuer: "https://idp.example.com", CreateUsers: &no, Scopes: []string{"email"}, ButtonLabel: "Go"}
	s = cfg.OIDCSettings()
	if s.ButtonLabel != "Go" || s.NewUsers() || !slices.Equal(s.Scopes, []string{"email"}) {
		t.Errorf("other = %+v", s.OIDC)
	}
	cfg.Auth.OIDC.ButtonLabel = ""
	if got := cfg.OIDCSettings().ButtonLabel; got != "Sign in with single sign-on" {
		t.Errorf("other's button %q", got)
	}
	if !(OIDCSettings{}).DomainAllowed("anyone@anywhere.example") {
		t.Error("no domains listed refuses an address")
	}
	s = OIDCSettings{OIDC: OIDC{AllowedDomains: []string{" Example.com "}}}
	for email, want := range map[string]bool{"sam@example.com": true, "sam@EXAMPLE.COM": true, "sam@other.com": false, "no-at-sign": false} {
		if s.DomainAllowed(email) != want {
			t.Errorf("DomainAllowed(%s) = %v", email, !want)
		}
	}
}

// The highest role any group or the email address maps to wins; people
// in no group get the default role, or none.
func TestRoleMapping(t *testing.T) {
	s := OIDCSettings{OIDC: OIDC{AdminGroups: []string{" Admins "}, AnalystGroups: []string{"soc", "admins"}, ViewerGroups: []string{"all", "sam@example.com"}}}
	for _, c := range []struct {
		groups      []string
		email, role string
		matched     []string
	}{
		{[]string{"all", "soc"}, "", "analyst", []string{"all", "soc"}},
		{[]string{"admins", "admins"}, "", "admin", []string{"admins"}},
		{nil, "sam@example.com", "viewer", []string{"sam@example.com"}},
		{[]string{"other"}, "", "", nil},
	} {
		role, matched := s.OIDCRole(c.groups, c.email)
		if role != c.role || !slices.Equal(matched, c.matched) {
			t.Errorf("%v %s: %q %v", c.groups, c.email, role, matched)
		}
	}
	s.DefaultRole = "viewer"
	if role, _ := s.OIDCRole([]string{"other"}, ""); role != "viewer" {
		t.Errorf("default role = %q", role)
	}
	ss := SAMLSettings{SAML: SAML{AnalystGroups: []string{"soc"}}}
	if role, _ := ss.SAMLRole([]string{"SOC"}, ""); role != "analyst" {
		t.Errorf("SAML role = %q", role)
	}
}

func TestSAMLProblems(t *testing.T) {
	for _, c := range []struct {
		name string
		s    SAML
		want []string
	}{
		{"off and empty", SAML{}, nil},
		{"on and empty", SAML{Enabled: true}, []string{"auth.saml.provider: choose", "auth.saml.metadata_url: enter", "auth.saml.admin_groups"}},
		{"bad values", SAML{Provider: "x", MetadataURL: "http://idp.example.com/metadata", UsernameAttribute: "a b", GroupsAttribute: "<g>",
			DefaultRole: "admin", ButtonLabel: strings.Repeat("x", 61)},
			[]string{"auth.saml.provider: \"x\"", "auth.saml.metadata_url: the metadata address must start with https://, so",
				"auth.saml.username_attribute", "auth.saml.groups_attribute", "auth.saml.default_role", "auth.saml.button_label"}},
		{"both", SAML{Provider: saml.Okta, MetadataURL: "https://idp.example.com/m", MetadataXML: "<x/>"}, []string{"not both"}},
		{"bad xml", SAML{Provider: saml.ADFS, MetadataXML: "<not metadata"}, []string{"auth.saml.metadata_xml:"}},
		{"huge xml", SAML{Provider: saml.ADFS, MetadataXML: strings.Repeat("x", MaxSAMLMetadataXML+1)}, []string{"larger than 256 KB"}},
		{"good", SAML{Enabled: true, Provider: saml.Entra, MetadataURL: "https://idp.example.com/m", DefaultRole: "viewer"}, nil},
	} {
		cfg := &Config{}
		cfg.Auth.SAML = c.s
		problemsHave(t, c.name, cfg.samlProblems(), true, c.want...)
	}
	for raw, ok := range map[string]bool{
		"https://idp.example.com/m": true, "http://localhost:8080/m": true, "http://127.0.0.1/m": true,
		"http://idp.example.com/m": false, "ftp://idp.example.com/m": false, "https://user:pw@idp.example.com/m": false, "not a url": false,
	} {
		if got := CheckSAMLMetadataURL(raw); (got == "") != ok {
			t.Errorf("CheckSAMLMetadataURL(%s) = %q", raw, got)
		}
	}
	if err := samlMetadataURL("ftp://x"); err == nil {
		t.Error("the page took an ftp metadata address")
	}
	if samlMetadataURL("") != nil || samlMetadataXML("") != nil {
		t.Error("an empty value was refused")
	}
	if samlMetadataXML("<nope") == nil {
		t.Error("the page took metadata that does not parse")
	}
}

func TestSAMLSettingsDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.Auth.SAML = SAML{Provider: saml.Entra, MetadataURL: " https://idp.example.com/m "}
	s := cfg.SAMLSettings()
	if s.MetadataURL != "https://idp.example.com/m" || s.UsernameAttribute == "" || s.DefaultRole != "none" || !strings.HasPrefix(s.ButtonLabel, "Sign in with ") || strings.Contains(s.ButtonLabel, "Microsoft") || !s.NewUsers() {
		t.Errorf("entra = %+v", s.SAML)
	}
	cfg.Auth.SAML = SAML{}
	if got := cfg.SAMLSettings().ButtonLabel; got != "Sign in with SAML single sign-on" {
		t.Errorf("no provider's button %q", got)
	}
	no := false
	cfg.Auth.SAML = SAML{Provider: saml.Okta, CreateUsers: &no, ButtonLabel: "Go", UsernameAttribute: "uid", GroupsAttribute: "g", DefaultRole: "viewer"}
	if s := cfg.SAMLSettings(); s.NewUsers() || s.ButtonLabel != "Go" || s.UsernameAttribute != "uid" || s.DefaultRole != "viewer" {
		t.Errorf("okta = %+v", s.SAML)
	}
}
