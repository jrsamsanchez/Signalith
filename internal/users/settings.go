package users

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// Directory types. The type picks sensible defaults; every default can be
// changed.
const (
	TypeActiveDirectory = "ad"
	TypeOpenLDAP        = "openldap"
)

// How a user's groups are found.
const (
	// GroupsMemberOf reads the user's memberOf attribute (Active Directory,
	// and OpenLDAP with the memberof overlay).
	GroupsMemberOf = "memberof"
	// GroupsSearch searches for groups with GroupFilter, which names the
	// user as {dn} or {username} (OpenLDAP groupOfNames or posixGroup).
	GroupsSearch = "search"
)

// inChain is Active Directory's LDAP_MATCHING_RULE_IN_CHAIN, which
// follows nested group membership on the server.
const inChain = "1.2.840.113556.1.4.1941"

// LDAPSettings is how Signalith signs users in with an LDAP or Active
// Directory server. The same settings come from auth.ldap in
// signalith.yaml or from the Users page.
type LDAPSettings struct {
	// Enabled turns directory sign-in on. In signalith.yaml it defaults to
	// true when auth.ldap is present.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled"`
	// Type is ad or openldap; it fills in the defaults below.
	Type string `yaml:"type" json:"type"`
	// URL is ldaps://host[:port] or ldap://host[:port].
	URL string `yaml:"url" json:"url"`
	// FailoverURL is tried when URL cannot be reached.
	FailoverURL string `yaml:"failover_url,omitempty" json:"failover_url"`
	// StartTLS encrypts an ldap:// connection before anything is sent.
	StartTLS bool `yaml:"start_tls,omitempty" json:"start_tls"`
	// CACert is the PEM certificate of the CA that signed the server's
	// certificate, when the system does not already trust it.
	CACert string `yaml:"ca_cert,omitempty" json:"ca_cert"`
	// CACertFile reads CACert from a file (signalith.yaml only).
	CACertFile string `yaml:"ca_cert_file,omitempty" json:"-"`
	// TLSSkipVerify accepts any certificate. Only for testing: anyone who
	// can intercept the connection can then read passwords.
	TLSSkipVerify bool `yaml:"tls_skip_verify,omitempty" json:"tls_skip_verify"`
	// ConnectTimeout and Timeout are in seconds. Defaults 5 and 10.
	ConnectTimeout int `yaml:"connect_timeout_seconds,omitempty" json:"connect_timeout_seconds"`
	Timeout        int `yaml:"timeout_seconds,omitempty" json:"timeout_seconds"`
	// BindDN and BindPassword are the service account that searches for
	// users. Empty BindDN searches anonymously.
	BindDN       string `yaml:"bind_dn,omitempty" json:"bind_dn"`
	BindPassword string `yaml:"bind_password,omitempty" json:"-"`
	// UserBaseDN is where users are searched for, with UserFilter; the
	// filter names the typed username as {username}.
	UserBaseDN string `yaml:"user_base_dn" json:"user_base_dn"`
	UserFilter string `yaml:"user_filter,omitempty" json:"user_filter"`
	// Attributes holding the username, display name and email address.
	UsernameAttribute string `yaml:"username_attribute,omitempty" json:"username_attribute"`
	NameAttribute     string `yaml:"name_attribute,omitempty" json:"name_attribute"`
	EmailAttribute    string `yaml:"email_attribute,omitempty" json:"email_attribute"`
	// GroupSearch is memberof or search.
	GroupSearch string `yaml:"group_search,omitempty" json:"group_search"`
	// NestedGroups also counts groups inside groups, for memberof on
	// Active Directory. Defaults to true for ad.
	NestedGroups *bool `yaml:"nested_groups,omitempty" json:"nested_groups"`
	// GroupBaseDN is where groups are searched for; empty searches the
	// whole directory (the DC= part of the user's DN, or of UserBaseDN).
	GroupBaseDN string `yaml:"group_base_dn,omitempty" json:"group_base_dn"`
	// GroupFilter finds a user's groups for group_search: search.
	GroupFilter string `yaml:"group_filter,omitempty" json:"group_filter"`
	// Groups whose members get each role, as full DNs. A user in several
	// gets the highest.
	AdminGroups   []string `yaml:"admin_groups,omitempty" json:"admin_groups"`
	AnalystGroups []string `yaml:"analyst_groups,omitempty" json:"analyst_groups"`
	ViewerGroups  []string `yaml:"viewer_groups,omitempty" json:"viewer_groups"`
	// DefaultRole is for users in no mapped group: none (refused, the
	// default) or viewer.
	DefaultRole string `yaml:"default_role,omitempty" json:"default_role"`
}

// Preset returns the defaults for a directory type.
func Preset(typ string) LDAPSettings {
	t, f := true, false
	switch typ {
	case TypeActiveDirectory:
		return LDAPSettings{
			Type: TypeActiveDirectory,
			// Matches the logon name or the user@domain form, and skips
			// disabled accounts (userAccountControl bit 2).
			UserFilter:        "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username}))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
			UsernameAttribute: "sAMAccountName",
			NameAttribute:     "displayName",
			EmailAttribute:    "mail",
			GroupSearch:       GroupsMemberOf,
			NestedGroups:      &t,
			ConnectTimeout:    5,
			Timeout:           10,
			DefaultRole:       "none",
		}
	case TypeOpenLDAP:
		return LDAPSettings{
			Type:              TypeOpenLDAP,
			UserFilter:        "(&(objectClass=inetOrgPerson)(uid={username}))",
			UsernameAttribute: "uid",
			NameAttribute:     "cn",
			EmailAttribute:    "mail",
			GroupSearch:       GroupsSearch,
			NestedGroups:      &f,
			// groupOfNames, groupOfUniqueNames and posixGroup cover most
			// OpenLDAP and 389 Directory Server setups.
			GroupFilter:    "(|(&(objectClass=groupOfNames)(member={dn}))(&(objectClass=groupOfUniqueNames)(uniqueMember={dn}))(&(objectClass=posixGroup)(memberUid={username})))",
			ConnectTimeout: 5,
			Timeout:        10,
			DefaultRole:    "none",
		}
	}
	return LDAPSettings{}
}

// groupBase is where to search for groups: GroupBaseDN, or else the
// domain the user is in (the DC= part of their DN or of the user base DN),
// so groups kept in another branch than the users, as in most Active
// Directories, are found.
func (s *LDAPSettings) groupBase(userDN string) string {
	if s.GroupBaseDN != "" {
		return s.GroupBaseDN
	}
	for _, dn := range []string{userDN, s.UserBaseDN} {
		if root := namingContext(dn); root != "" {
			return root
		}
	}
	return s.UserBaseDN
}

// namingContext returns the trailing DC= parts of a DN, such as
// DC=corp,DC=example,DC=com, or "" if it has none.
func namingContext(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || parsed == nil {
		return ""
	}
	start := len(parsed.RDNs)
	for start > 0 {
		rdn := parsed.RDNs[start-1]
		if len(rdn.Attributes) != 1 || !strings.EqualFold(rdn.Attributes[0].Type, "dc") {
			break
		}
		start--
	}
	if start == len(parsed.RDNs) {
		return ""
	}
	// Rebuilt from the parsed values, so escaped commas cannot confuse it.
	out := make([]string, 0, len(parsed.RDNs)-start)
	for _, rdn := range parsed.RDNs[start:] {
		a := rdn.Attributes[0]
		out = append(out, a.Type+"="+ldap.EscapeDN(a.Value))
	}
	return strings.Join(out, ",")
}

// SameConnection reports whether two settings talk to the same servers as
// the same service account with the same TLS protection. The saved bind
// password is only reused when they do; otherwise it must be typed again,
// or anyone who can change the settings could have it sent to a server
// they choose.
func SameConnection(a, b LDAPSettings) bool {
	a, b = a.Clone(), b.Clone()
	a.Normalize()
	b.Normalize()
	return strings.EqualFold(a.URL, b.URL) && strings.EqualFold(a.FailoverURL, b.FailoverURL) &&
		sameDN(a.BindDN, b.BindDN) && a.StartTLS == b.StartTLS && a.TLSSkipVerify == b.TLSSkipVerify &&
		a.CACert == b.CACert
}

// BindField is the setting the service account password of settings s is
// encrypted for in the shared settings of a cluster. It names everything
// SameConnection compares (the server addresses, the bind DN and the TLS
// settings), so a password moved to settings that would send it
// elsewhere cannot be opened:
// directory.bind_password@ldaps://dc1:636,;<16 hex digits>.
func BindField(s LDAPSettings) string {
	s = s.Clone()
	s.Normalize()
	h := sha256.New()
	for _, part := range []string{normDN(s.BindDN), strconv.FormatBool(s.StartTLS), strconv.FormatBool(s.TLSSkipVerify), s.CACert} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return BindPasswordField + "@" + strings.ToLower(s.URL) + "," + strings.ToLower(s.FailoverURL) + ";" + hex.EncodeToString(h.Sum(nil))[:16]
}

// normDN writes a DN the same way however it was spelled, as sameDN
// compares them: attribute names and values in lower case, without
// spacing around separators.
func normDN(dn string) string {
	d, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}
	rdns := make([]string, 0, len(d.RDNs))
	for _, r := range d.RDNs {
		parts := make([]string, 0, len(r.Attributes))
		for _, a := range r.Attributes {
			parts = append(parts, strings.ToLower(strings.TrimSpace(a.Type))+"="+ldap.EscapeDN(strings.ToLower(strings.TrimSpace(a.Value))))
		}
		slices.Sort(parts)
		rdns = append(rdns, strings.Join(parts, "+"))
	}
	return strings.Join(rdns, ",")
}

// IsEnabled reports whether directory sign-in is on.
func (s *LDAPSettings) IsEnabled() bool { return s.Enabled != nil && *s.Enabled }

// Nested reports whether nested groups count.
func (s *LDAPSettings) Nested() bool { return s.NestedGroups != nil && *s.NestedGroups }

// Clone returns a deep copy.
func (s LDAPSettings) Clone() LDAPSettings {
	c := s
	if s.Enabled != nil {
		v := *s.Enabled
		c.Enabled = &v
	}
	if s.NestedGroups != nil {
		v := *s.NestedGroups
		c.NestedGroups = &v
	}
	c.AdminGroups = slices.Clone(s.AdminGroups)
	c.AnalystGroups = slices.Clone(s.AnalystGroups)
	c.ViewerGroups = slices.Clone(s.ViewerGroups)
	return c
}

// Normalize trims every value and fills empty ones from the type's
// preset.
func (s *LDAPSettings) Normalize() {
	for _, p := range []*string{&s.Type, &s.URL, &s.FailoverURL, &s.BindDN, &s.UserBaseDN, &s.UserFilter,
		&s.UsernameAttribute, &s.NameAttribute, &s.EmailAttribute, &s.GroupSearch, &s.GroupBaseDN, &s.GroupFilter,
		&s.DefaultRole, &s.CACertFile} {
		*p = strings.TrimSpace(*p)
	}
	s.Type = strings.ToLower(s.Type)
	if s.Type == "" {
		s.Type = TypeActiveDirectory
	}
	s.GroupSearch = strings.ToLower(s.GroupSearch)
	s.DefaultRole = strings.ToLower(s.DefaultRole)
	s.CACert = strings.TrimSpace(s.CACert)
	if s.CACert != "" {
		s.CACert += "\n"
	}
	p := Preset(s.Type)
	fill := func(v *string, def string) {
		if *v == "" {
			*v = def
		}
	}
	fill(&s.UserFilter, p.UserFilter)
	fill(&s.UsernameAttribute, p.UsernameAttribute)
	fill(&s.NameAttribute, p.NameAttribute)
	fill(&s.EmailAttribute, p.EmailAttribute)
	fill(&s.GroupSearch, p.GroupSearch)
	if s.GroupSearch == GroupsSearch {
		fill(&s.GroupFilter, p.GroupFilter)
	}
	fill(&s.DefaultRole, "none")
	if s.NestedGroups == nil {
		v := p.Nested()
		s.NestedGroups = &v
	}
	if s.ConnectTimeout == 0 {
		s.ConnectTimeout = 5
	}
	if s.Timeout == 0 {
		s.Timeout = 10
	}
	s.AdminGroups = cleanDNs(s.AdminGroups)
	s.AnalystGroups = cleanDNs(s.AnalystGroups)
	s.ViewerGroups = cleanDNs(s.ViewerGroups)
}

// cleanDNs trims a group list and drops blanks and repeats.
func cleanDNs(list []string) []string {
	out := []string{}
	for _, g := range list {
		g = strings.TrimSpace(g)
		if g == "" || slices.ContainsFunc(out, func(o string) bool { return sameDN(o, g) }) {
			continue
		}
		out = append(out, g)
	}
	return out
}

// sameDN compares two DNs the way a directory does: attribute names and
// values ignore case, and spacing around separators does not matter.
func sameDN(a, b string) bool {
	da, errA := ldap.ParseDN(a)
	db, errB := ldap.ParseDN(b)
	if errA != nil || errB != nil {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return da.EqualFold(db)
}

// Problem is one setting that needs fixing. Field is the setting's key.
type Problem struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

var attrPattern = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*|[0-9]+(\.[0-9]+)+)$`)

// Problems lists every setting that needs fixing. Values that are empty
// are only required while directory sign-in is on, so half-finished
// settings can be saved switched off.
func (s *LDAPSettings) Problems() []Problem {
	var p []Problem
	add := func(field, format string, args ...any) {
		p = append(p, Problem{Field: field, Message: fmt.Sprintf(format, args...)})
	}
	on := s.IsEnabled()
	switch s.Type {
	case TypeActiveDirectory, TypeOpenLDAP:
	case "":
		if on {
			add("type", "choose ad (Active Directory) or openldap")
		}
	default:
		add("type", "type %q must be ad (Active Directory) or openldap", s.Type)
	}
	checkURL := func(field, v string, required bool) {
		if v == "" {
			if required {
				add(field, "enter the server address, like ldaps://dc1.corp.example.com")
			}
			return
		}
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Hostname() == "" ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			add(field, "%q must be ldaps://host or ldap://host, with an optional :port and nothing after it", v)
			return
		}
		if port := u.Port(); port != "" {
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				add(field, "port %q must be 1-65535", port)
			}
		}
		if u.Scheme == "ldaps" && s.StartTLS {
			add(field, "%s already uses TLS; StartTLS is only for ldap:// addresses. Turn StartTLS off or use ldap://", v)
		}
	}
	checkURL("url", s.URL, on)
	checkURL("failover_url", s.FailoverURL, false)
	if s.CACert != "" {
		if problem := checkPEM(s.CACert); problem != "" {
			add("ca_cert", "%s", problem)
		}
	}
	if s.ConnectTimeout < 1 || s.ConnectTimeout > 120 {
		add("connect_timeout_seconds", "the connect timeout must be 1-120 seconds")
	}
	if s.Timeout < 1 || s.Timeout > 300 {
		add("timeout_seconds", "the timeout must be 1-300 seconds")
	}
	checkDN := func(field, v, example string) {
		if v == "" {
			return
		}
		if _, err := ldap.ParseDN(v); err != nil {
			add(field, "%q is not a DN like %s", v, example)
		}
	}
	checkDN("bind_dn", s.BindDN, "CN=svc-signalith,OU=Service Accounts,DC=corp,DC=example,DC=com")
	if s.BindDN != "" && s.BindPassword == "" {
		add("bind_password", "enter the service account's password")
	}
	if secrets.IsSealed(s.BindPassword) {
		// It would be stored as it is, not encrypted.
		add("bind_password", "the password cannot start with enc:v and a number and a colon, which is how encrypted values look")
	}
	if s.UserBaseDN == "" && on {
		add("user_base_dn", "enter where to search for users, like DC=corp,DC=example,DC=com")
	}
	checkDN("user_base_dn", s.UserBaseDN, "DC=corp,DC=example,DC=com")
	checkFilter := func(field, v string, placeholders ...string) {
		if v == "" {
			if on {
				add(field, "enter a search filter")
			}
			return
		}
		has := false
		test := v
		for _, ph := range placeholders {
			has = has || strings.Contains(v, ph)
			test = strings.ReplaceAll(test, ph, "x")
		}
		if !has {
			add(field, "the filter must contain %s", strings.Join(placeholders, " or "))
			return
		}
		if _, err := ldap.CompileFilter(test); err != nil {
			add(field, "the filter is not valid LDAP filter syntax (%v)", err)
		}
	}
	checkFilter("user_filter", s.UserFilter, "{username}")
	for _, a := range []struct{ field, v string }{
		{"username_attribute", s.UsernameAttribute}, {"name_attribute", s.NameAttribute}, {"email_attribute", s.EmailAttribute},
	} {
		if a.v == "" {
			if a.field == "username_attribute" && on {
				add(a.field, "enter the attribute holding the username, like sAMAccountName or uid")
			}
			continue
		}
		if !attrPattern.MatchString(a.v) {
			add(a.field, "%q is not an attribute name", a.v)
		}
	}
	switch s.GroupSearch {
	case GroupsMemberOf:
	case GroupsSearch:
		checkFilter("group_filter", s.GroupFilter, "{dn}", "{username}")
	default:
		add("group_search", "group_search %q must be memberof or search", s.GroupSearch)
	}
	checkDN("group_base_dn", s.GroupBaseDN, "OU=Groups,DC=corp,DC=example,DC=com")
	for _, g := range []struct {
		field string
		list  []string
	}{{"admin_groups", s.AdminGroups}, {"analyst_groups", s.AnalystGroups}, {"viewer_groups", s.ViewerGroups}} {
		for _, dn := range g.list {
			if _, err := ldap.ParseDN(dn); err != nil || dn == "" {
				add(g.field, "%q is not a group DN like CN=SOC Analysts,OU=Groups,DC=corp,DC=example,DC=com", dn)
			}
		}
	}
	switch s.DefaultRole {
	case "none", string(Viewer):
	default:
		add("default_role", "default_role %q must be none or viewer", s.DefaultRole)
	}
	if on && s.DefaultRole != string(Viewer) && len(s.AdminGroups)+len(s.AnalystGroups)+len(s.ViewerGroups) == 0 {
		add("admin_groups", "map at least one group to a role, or let users in no mapped group in as viewers; otherwise nobody can sign in")
	}
	return p
}

// checkPEM reports what is wrong with a CA certificate, or "".
func checkPEM(text string) string {
	rest := []byte(text)
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return fmt.Sprintf("the CA certificate holds a %s; paste only certificates", strings.ToLower(b.Type))
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return "the CA certificate could not be read: " + err.Error()
		}
		n++
	}
	if n == 0 {
		return "paste the CA certificate in PEM form, starting with -----BEGIN CERTIFICATE-----"
	}
	return ""
}

// Warnings lists settings that work but weaken security.
func (s *LDAPSettings) Warnings() []string {
	var w []string
	plain := func(v string) bool { return strings.HasPrefix(strings.ToLower(v), "ldap://") && !s.StartTLS }
	if plain(s.URL) || plain(s.FailoverURL) {
		w = append(w, "Passwords cross the network unencrypted. Use ldaps:// or turn on StartTLS.")
	}
	if s.TLSSkipVerify {
		w = append(w, "Certificate checks are off, so anyone who can intercept the connection can read passwords. Add the CA certificate and turn this off.")
	}
	return w
}

// roleFor maps groups to the highest role they grant, and returns the
// groups that matched a mapping.
func (s *LDAPSettings) roleFor(groups []string) (Role, []string) {
	var role Role
	matched := []string{}
	for _, g := range groups {
		hit := false
		for _, m := range []struct {
			role Role
			list []string
		}{{Admin, s.AdminGroups}, {Analyst, s.AnalystGroups}, {Viewer, s.ViewerGroups}} {
			if slices.ContainsFunc(m.list, func(dn string) bool { return sameDN(dn, g) }) {
				role, hit = Highest(role, m.role), true
			}
		}
		if hit {
			matched = append(matched, g)
		}
	}
	if role == "" && s.DefaultRole == string(Viewer) {
		role = Viewer
	}
	return role, matched
}
