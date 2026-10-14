package users

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/users/ldaptest"
)

func on() *bool { t := true; return &t }

func startFake(t *testing.T, opts ldaptest.Options, load func(*ldaptest.Server)) *ldaptest.Server {
	t.Helper()
	srv, err := ldaptest.Start(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	load(srv)
	return srv
}

func adSettings(srv *ldaptest.Server) LDAPSettings {
	s := Preset(TypeActiveDirectory)
	s.Enabled = on()
	s.URL = srv.URL
	s.CACert = srv.CACert
	s.BindDN, s.BindPassword = ldaptest.ADService, ldaptest.ServicePassword
	s.UserBaseDN = ldaptest.ADBase
	s.AdminGroups = []string{ldaptest.ADAdmins}
	s.AnalystGroups = []string{ldaptest.ADAnalysts}
	s.ViewerGroups = []string{ldaptest.ADViewers}
	s.Normalize()
	return s
}

func olSettings(srv *ldaptest.Server) LDAPSettings {
	s := Preset(TypeOpenLDAP)
	s.Enabled = on()
	s.URL = srv.URL
	s.BindDN, s.BindPassword = ldaptest.OLService, ldaptest.ServicePassword
	s.UserBaseDN = "ou=people," + ldaptest.OLBase
	s.GroupBaseDN = "ou=groups," + ldaptest.OLBase
	// Spelled differently from the server on purpose: DNs compare as DNs.
	s.AdminGroups = []string{"CN=Signalith-Admins, OU=Groups, DC=example, DC=org"}
	s.AnalystGroups = []string{ldaptest.OLAnalysts}
	s.ViewerGroups = []string{ldaptest.OLViewers}
	s.Normalize()
	return s
}

func directory(t *testing.T, s LDAPSettings) *Directory {
	t.Helper()
	if p := s.Problems(); len(p) > 0 {
		t.Fatalf("settings problems: %v", p)
	}
	d, err := OpenDirectory("", &s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func signIn(t *testing.T, d *Directory, user, pass string) (*DirectoryUser, error) {
	t.Helper()
	return d.Authenticate(context.Background(), user, pass)
}

func TestActiveDirectorySignIn(t *testing.T) {
	srv := startFake(t, ldaptest.Options{TLS: true, ActiveDirectory: true}, ldaptest.LoadActiveDirectory)
	d := directory(t, adSettings(srv))

	// alice is an admin only through a group inside Signalith Admins.
	u, err := signIn(t, d, "alice", ldaptest.Password)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" || u.Role != Admin || u.DN != ldaptest.ADAliceDN || u.Name != "Alice Admin" || u.Email != "alice@corp.example.com" {
		t.Errorf("alice = %+v", u)
	}
	if !slices.Contains(u.Groups, ldaptest.ADAdmins) || !slices.Contains(u.Matched, ldaptest.ADAdmins) {
		t.Errorf("alice groups = %v matched %v", u.Groups, u.Matched)
	}
	// The user@domain form and DOMAIN\user both work, in any case.
	for _, login := range []string{"BOB@corp.example.com", `CORP\bob`} {
		if u, err := signIn(t, d, login, ldaptest.Password); err != nil || u.Role != Analyst || u.Username != "bob" {
			t.Errorf("%s = %+v %v", login, u, err)
		}
	}
	if u, err := signIn(t, d, "carol", ldaptest.Password); err != nil || u.Role != Viewer {
		t.Errorf("carol = %+v %v", u, err)
	}
	// A comma in the user's DN survives escaping in the group search.
	if u, err := signIn(t, d, "jsmith", ldaptest.Password); err != nil || u.Role != Analyst {
		t.Errorf("jsmith = %+v %v", u, err)
	}

	// Refusals.
	refused := func(user, pass string, want error, reason string) {
		t.Helper()
		_, err := signIn(t, d, user, pass)
		var se *SignInError
		if !errors.As(err, &se) || !errors.Is(err, want) || !strings.Contains(se.Reason, reason) {
			t.Errorf("%s: err = %v (%+v)", user, err, se)
		}
	}
	refused("alice", "wrong", ErrBadCredentials, "wrong password")
	refused("nobody", ldaptest.Password, ErrBadCredentials, "not found")
	refused("eve", ldaptest.Password, ErrBadCredentials, "not found") // disabled in AD
	refused("pat", ldaptest.Password, ErrBadCredentials, "more than one")
	refused("dave", ldaptest.Password, ErrNoRole, "no group")
	refused("frank", ldaptest.Password, ErrPasswordExpired, "must change password first")
	refused("frank", "wrong", ErrBadCredentials, "wrong password")

	// An empty password never reaches the server: it would be an
	// unauthenticated bind, which the server treats as success.
	before := srv.Connections()
	refused("alice", "", ErrBadCredentials, "empty password")
	if srv.Connections() != before {
		t.Error("empty password contacted the server")
	}

	// Filter metacharacters in the username are escaped.
	refused("*", ldaptest.Password, ErrBadCredentials, "not found")
	refused("alice)(sAMAccountName=*", ldaptest.Password, ErrBadCredentials, "not found")
	filters := strings.Join(srv.Filters(), "\n")
	if !strings.Contains(filters, `sAMAccountName=\2a`) || !strings.Contains(filters, `alice\29\28sAMAccountName=\2a`) {
		t.Errorf("filters not escaped:\n%s", filters)
	}
	// The nested group search used the in-chain rule with the escaped DN.
	if !strings.Contains(filters, `member:1.2.840.113556.1.4.1941:=CN=Smith\5c, John`) {
		t.Errorf("nested group filter:\n%s", filters)
	}

	// Users in no mapped group can be let in as viewers instead.
	s := adSettings(srv)
	s.DefaultRole = "viewer"
	if u, err := signIn(t, directory(t, s), "dave", ldaptest.Password); err != nil || u.Role != Viewer || len(u.Matched) != 0 {
		t.Errorf("dave as viewer = %+v %v", u, err)
	}
	// Without nested groups alice only has IT Leads, which maps to nothing.
	s = adSettings(srv)
	no := false
	s.NestedGroups = &no
	if _, err := signIn(t, directory(t, s), "alice", ldaptest.Password); !errors.Is(err, ErrNoRole) {
		t.Errorf("alice without nesting: %v", err)
	}
}

func TestOpenLDAPSignIn(t *testing.T) {
	srv := startFake(t, ldaptest.Options{StartTLS: true}, ldaptest.LoadOpenLDAP)
	s := olSettings(srv)
	d := directory(t, s)
	for user, role := range map[string]Role{"alice": Admin, "bob": Analyst, "carol": Viewer} {
		u, err := signIn(t, d, user, ldaptest.Password)
		if err != nil || u.Role != role || u.Username != user {
			t.Errorf("%s = %+v %v", user, u, err)
		}
	}
	if _, err := signIn(t, d, "dave", ldaptest.Password); !errors.Is(err, ErrNoRole) {
		t.Errorf("dave: %v", err)
	}
	filters := strings.Join(srv.Filters(), "\n")
	if !strings.Contains(filters, "(memberUid=bob)") || !strings.Contains(filters, "(member=uid=alice,ou=people,dc=example,dc=org)") {
		t.Errorf("group filters:\n%s", filters)
	}

	// StartTLS with the CA certificate encrypts the connection.
	s.StartTLS, s.CACert = true, srv.CACert
	if u, err := signIn(t, directory(t, s), "bob", ldaptest.Password); err != nil || u.Role != Analyst {
		t.Errorf("StartTLS: %+v %v", u, err)
	}
	rep := TestConnection(context.Background(), s)
	if !rep.OK || !strings.Contains(rep.Servers[0].Steps[0].Message, "over TLS") {
		t.Errorf("StartTLS test = %+v", rep)
	}
	// Without the CA the certificate is not trusted.
	s.CACert = ""
	_, err := signIn(t, directory(t, s), "bob", ldaptest.Password)
	var de *DirectoryError
	if !errors.As(err, &de) || de.Code != "tls_untrusted" {
		t.Errorf("untrusted StartTLS: %v", err)
	}
}

func TestConnectionReports(t *testing.T) {
	srv := startFake(t, ldaptest.Options{TLS: true, ActiveDirectory: true, CertHosts: []string{"ldap.corp.example.com"}}, ldaptest.LoadActiveDirectory)
	s := adSettings(srv)
	ctx := context.Background()

	code := func(s LDAPSettings) (string, string) {
		rep := TestConnection(ctx, s)
		if rep.OK || len(rep.Servers) == 0 {
			return "", rep.Message
		}
		return rep.Servers[0].Code, rep.Message
	}
	// The certificate names another host.
	if c, msg := code(s); c != "tls_hostname" || !strings.Contains(msg, "ldap.corp.example.com") {
		t.Errorf("hostname: %s %s", c, msg)
	}
	s.TLSSkipVerify = true
	if rep := TestConnection(ctx, s); !rep.OK || len(rep.Servers[0].Steps) != 3 {
		t.Errorf("skip verify = %+v", rep)
	}
	if len(s.Warnings()) == 0 {
		t.Error("skip verify has no warning")
	}
	// A certificate from a CA the system does not know.
	other := startFake(t, ldaptest.Options{TLS: true, ActiveDirectory: true}, ldaptest.LoadActiveDirectory)
	untrusted := adSettings(other)
	untrusted.CACert = ""
	if c, msg := code(untrusted); c != "tls_untrusted" || !strings.Contains(msg, "CA certificate") {
		t.Errorf("untrusted: %s %s", c, msg)
	}
	untrusted.CACert = srv.CACert // the wrong CA
	if c, msg := code(untrusted); c != "tls_untrusted" || !strings.Contains(msg, "not signed by the CA certificate you gave") {
		t.Errorf("wrong CA: %s %s", c, msg)
	}
	s.BindPassword = "wrong"
	if c, msg := code(s); c != "bind_refused" || !strings.Contains(msg, "wrong password") {
		t.Errorf("bind: %s %s", c, msg)
	}
	s.BindPassword = ldaptest.ServicePassword
	s.UserBaseDN = "OU=Nowhere," + ldaptest.ADBase
	if c, _ := code(s); c != "base_not_found" {
		t.Errorf("base: %s", c)
	}
	s.UserBaseDN = ldaptest.ADBase
	s.BindDN, s.BindPassword = "", ""
	if rep := LookupUser(ctx, s, "bob", ""); rep.Code != "bind_required" {
		t.Errorf("anonymous on AD: %+v", rep)
	}
	// ldaps:// to a port without TLS.
	plain := startFake(t, ldaptest.Options{}, ldaptest.LoadOpenLDAP)
	s2 := olSettings(plain)
	s2.URL = strings.Replace(plain.URL, "ldap://", "ldaps://", 1)
	if c, msg := code(s2); c != "tls_handshake" || !strings.Contains(msg, "did not answer with TLS") {
		t.Errorf("ldaps to plain: %s %s", c, msg)
	}
	// Nothing listening, then the failover server answers.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "ldap://" + ln.Addr().String()
	ln.Close()
	s2 = olSettings(plain)
	s2.URL, s2.FailoverURL = dead, plain.URL
	rep := TestConnection(ctx, s2)
	if rep.OK || rep.Servers[0].Code != "connect" || !rep.Servers[1].OK || !strings.Contains(rep.Servers[0].Message, "refused") {
		t.Errorf("failover test = %+v", rep)
	}
	if u, err := signIn(t, directory(t, s2), "alice", ldaptest.Password); err != nil || u.Role != Admin {
		t.Errorf("failover sign-in = %+v %v", u, err)
	}
	// A server that cannot be resolved.
	s2.URL, s2.FailoverURL = "ldap://no-such-host.invalid", ""
	if c, msg := code(s2); c != "connect" || !strings.Contains(msg, "could not be found") {
		t.Errorf("dns: %s %s", c, msg)
	}
}

func TestLookupUserReports(t *testing.T) {
	srv := startFake(t, ldaptest.Options{TLS: true, ActiveDirectory: true}, ldaptest.LoadActiveDirectory)
	s := adSettings(srv)
	ctx := context.Background()
	rep := LookupUser(ctx, s, "alice", "")
	if !rep.OK || rep.User.Role != Admin || rep.User.DN != ldaptest.ADAliceDN || rep.PasswordChecked || !strings.Contains(rep.Message, "not checked") {
		t.Errorf("alice = %+v", rep)
	}
	for _, c := range []struct{ user, pass, code string }{
		{"alice", ldaptest.Password, ""},
		{"alice", "wrong", "wrong_password"},
		{"nobody", "", "user_not_found"},
		{"pat", "", "multiple_matches"},
		{"dave", "", "no_role"},
		{"frank", ldaptest.Password, "password_expired"},
	} {
		rep := LookupUser(ctx, s, c.user, c.pass)
		if rep.Code != c.code || rep.OK != (c.code == "") || rep.Message == "" {
			t.Errorf("%s: %+v", c.user, rep)
		}
	}
	if rep := LookupUser(ctx, s, "dave", ""); len(rep.User.Groups) != 1 || rep.User.Groups[0] != ldaptest.ADEveryone {
		t.Errorf("dave's groups = %+v", rep.User)
	}
}

func TestSettingsChecksAndSaving(t *testing.T) {
	s := Preset(TypeActiveDirectory)
	s.Enabled = on()
	s.Normalize()
	fields := func(s LDAPSettings) string {
		var out []string
		for _, p := range s.Problems() {
			out = append(out, p.Field)
		}
		return strings.Join(out, ",")
	}
	if got := fields(s); got != "url,user_base_dn,admin_groups" {
		t.Errorf("empty AD settings problems = %s", got)
	}
	s.URL, s.StartTLS = "ldaps://dc1:636", true
	s.UserBaseDN = "not a dn"
	s.BindDN = "CN=svc,DC=x"
	s.UserFilter = "(uid=x)"
	s.AdminGroups = []string{"CN=Admins,DC=x", "cn=admins, dc=x", ""}
	s.CACert = "junk"
	s.Normalize()
	if len(s.AdminGroups) != 1 {
		t.Errorf("groups not cleaned: %v", s.AdminGroups)
	}
	if got := fields(s); got != "url,ca_cert,bind_password,user_base_dn,user_filter" {
		t.Errorf("problems = %s (%v)", got, s.Problems())
	}
	// Switched off, half-finished settings can be saved.
	off := Preset(TypeOpenLDAP)
	off.URL = "ldap://ldap.example.org"
	path := filepath.Join(t.TempDir(), "directory.json")
	d, err := OpenDirectory(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Save(context.Background(), off); err != nil {
		t.Fatalf("save switched off: %v", err)
	}
	if d.Enabled() || d.Revision() != 1 {
		t.Error("saved settings should be off")
	}
	off.Enabled = on()
	var se *SettingsError
	if err := d.Save(context.Background(), off); !errors.As(err, &se) {
		t.Errorf("enabling incomplete settings: %v", err)
	}
	off.UserBaseDN, off.BindDN, off.BindPassword = "dc=example,dc=org", "cn=svc,dc=example,dc=org", "secret-bind"
	off.ViewerGroups = []string{"cn=staff,dc=example,dc=org"}
	if err := d.Save(context.Background(), off); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "secret-bind") || !strings.Contains(string(raw), `"bind_password": "enc:v1:`) {
		t.Errorf("file = %s", raw)
	}
	again, err := OpenDirectory(path, nil)
	if err != nil || !again.Enabled() || again.Settings().BindPassword != "secret-bind" || again.Settings().GroupFilter == "" {
		t.Errorf("reloaded %+v %v", again.Settings(), err)
	}
	// Settings from signalith.yaml cannot be changed here.
	fromFile, _ := OpenDirectory(path, &off)
	if err := fromFile.Save(context.Background(), off); !errors.Is(err, ErrReadOnly) {
		t.Errorf("save over config: %v", err)
	}
}

// TestDirectoryBindPasswordEncrypted checks that directory.json keeps the
// service account password encrypted, still reads a plain one, rewrites a
// plain one encrypted through ResealDirectoryFile, and reports one that
// cannot be decrypted instead of failing.
func TestDirectoryBindPasswordEncrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "directory.json")
	plain := `{
  "version": 1,
  "settings": {"enabled": true, "type": "ad", "url": "ldaps://dc1.example.com", "bind_dn": "CN=svc,DC=example,DC=com",
    "user_base_dn": "DC=example,DC=com", "admin_groups": ["CN=Admins,DC=example,DC=com"]},
  "bind_password": "plain-bind-pw"
}
`
	if err := os.WriteFile(path, []byte(plain), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := OpenDirectory(path, nil)
	if err != nil || d.Settings().BindPassword != "plain-bind-pw" || d.Problem() != "" {
		t.Fatalf("plain file: %v %q", err, d.Problem())
	}

	// Migration encrypts it, and only it.
	seal := func(s secrets.Stored) (string, error) { return secrets.Seal(s.Field, s.Value) }
	out, n, err := ResealDirectoryFile([]byte(plain), seal)
	if err != nil || n != 1 || strings.Contains(string(out), "plain-bind-pw") || !strings.Contains(string(out), `"bind_password": "enc:v1:`) {
		t.Fatalf("reseal: n=%d err=%v\n%s", n, err, out)
	}
	if again, n, _ := ResealDirectoryFile(out, seal); n != 0 || string(again) != string(out) {
		t.Error("resealing an encrypted file should change nothing")
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err = OpenDirectory(path, nil)
	if err != nil || d.Settings().BindPassword != "plain-bind-pw" || !d.Enabled() {
		t.Fatalf("encrypted file: %v %+v", err, d.Settings())
	}

	// With another master key the password is left out and Problem says
	// why; the server still starts.
	other := secrets.NewKeyring(t.TempDir())
	if _, err := other.Seal("x", "make a key"); err != nil {
		t.Fatal(err)
	}
	prev := secrets.Default()
	secrets.SetDefault(other)
	defer secrets.SetDefault(prev)
	d, err = OpenDirectory(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Settings().BindPassword != "" || !strings.Contains(d.Problem(), "service account password is entered again") ||
		!strings.Contains(d.Problem(), "directory.bind_password is encrypted with master key") {
		t.Errorf("wrong key: password %q, problem %q", d.Settings().BindPassword, d.Problem())
	}
	// Entering it again clears the problem.
	set := d.Settings()
	set.BindPassword = "new-bind-pw"
	if err := d.Save(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if d.Problem() != "" {
		t.Errorf("problem after saving: %q", d.Problem())
	}
	if d, _ = OpenDirectory(path, nil); d.Settings().BindPassword != "new-bind-pw" {
		t.Errorf("reloaded %q", d.Settings().BindPassword)
	}
}

// A typed bind password that starts like an encrypted value would be
// stored as it is, so it is refused.
func TestBindPasswordLookingEncrypted(t *testing.T) {
	d, err := OpenDirectory(filepath.Join(t.TempDir(), "directory.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := Preset(TypeActiveDirectory)
	on := true
	s.Enabled = &on
	s.URL, s.BindDN, s.UserBaseDN = "ldaps://dc1.example.com", "CN=svc,DC=example,DC=com", "DC=example,DC=com"
	s.AdminGroups = []string{"CN=Admins,DC=example,DC=com"}
	s.BindPassword = "enc:v1:0011aabb:AAAA"
	var se *SettingsError
	if err := d.Save(context.Background(), s); !errors.As(err, &se) || !strings.Contains(err.Error(), "how encrypted values look") {
		t.Errorf("Save = %v", err)
	}
	s.BindPassword = "enc:plain-password"
	if err := d.Save(context.Background(), s); err != nil {
		t.Errorf("a password starting with enc: refused: %v", err)
	}
}
