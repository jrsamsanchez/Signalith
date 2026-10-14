package clustercfg

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
	"golang.org/x/crypto/bcrypt"
)

// authConfig loads a signalith.yaml in dir whose auth section has the
// built-in admin's password hash and authExtra (indented under auth:).
func authConfig(t *testing.T, dir, authExtra string) *config.Config {
	t.Helper()
	path := filepath.Join(dir, "signalith.yaml")
	body := "auth:\n  admin_password_hash: " + yamlHash() + "\n" + authExtra + "ingest:\n  tokens: [tok-0123456789abcdef]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// yamlHash is the built-in admin's password hash in every signalith.yaml
// here: the same on each load, as a file that did not change.
var yamlHash = sync.OnceValue(func() string {
	h, err := config.HashPassword("s3cret-pass")
	if err != nil {
		panic(err)
	}
	return h
})

// authMember is a member with the users' documents.
type authMember struct {
	*member
	auth  *clusterauth.Docs
	files Files
}

// newAuthMember starts a server whose configuration is c (prepare runs
// before, to write its files), with the users' documents.
func newAuthMember(t *testing.T, o *testOS, name string, dir string, c *config.Config, key *shared.ClusterKey) *authMember {
	t.Helper()
	m := &member{t: t, name: name, dir: dir, docs: NewDocs(), logs: &logBuffer{}}
	m.log = slog.New(slog.NewJSONHandler(m.logs, nil))
	m.master = secrets.NewKeyring(dir)
	m.cfg.Store(c)
	secrets.SetDefault(m.master)
	t.Cleanup(func() { secrets.SetDefault(nil) })
	if key != nil {
		if err := (shared.KeyStore{Dir: dir, Master: m.master}).SaveClusterKey(key); err != nil {
			t.Fatal(err)
		}
	}
	a := clusterauth.NewDocs()
	m.docs.UseAuth(a)
	am := &authMember{member: m, auth: a}
	am.files = Files{Config: func() *config.Config { return m.cfg.Load() }, Node: name, NodeID: "n_" + name,
		Client: func() (*store.Client, string) { return o.cl, testPrefix }, LeaseEpoch: func() int64 { return 1 },
		NodeCfg: func() *shared.Doc[shared.NodeCfg] { return m.rt.NodeCfg() }, Log: m.log}
	m.rt = shared.NewRuntime(shared.RuntimeOptions{StateDir: dir, Self: shared.Self{NodeID: "n_" + name, Name: name},
		Content: func(h *shared.Hub) { m.docs.Track(h); a.Track(h) }, Importers: Importers(m.docs, am.files), Log: m.log})
	a.Cluster = m.rt.Cluster
	m.rt.Use(o.cl, testPrefix, m.master)
	if key == nil {
		if err := m.rt.Found(context.Background(), "test"); err != nil {
			t.Fatal(err)
		}
	}
	if mode, why := m.rt.Mode(); mode != shared.ModeMember {
		t.Fatalf("%s: mode %s (%s)", name, mode, why)
	}
	if !m.rt.SharedUsers() {
		t.Fatalf("%s: users are not shared", name)
	}
	return am
}

func (m *authMember) apply() Applied {
	m.t.Helper()
	m.cycle()
	res, err := Apply(context.Background(), m.rt, m.docs, m.cfg.Load(), m.name, m.log)
	if err != nil {
		m.t.Fatal(err)
	}
	return res
}

func (m *authMember) importer(name string) shared.Importer {
	for _, im := range Importers(m.docs, m.files) {
		if im.Name == name {
			return im
		}
	}
	m.t.Fatalf("no importer %s", name)
	return shared.Importer{}
}

func matches(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// V19: the founder imports its users (local, directory and disabled ones,
// with their password hashes and last sign-ins), leaves out a user named
// like the built-in admin, and the built-in admin with the password
// signalith passwd wrote; running it again changes nothing, and a run
// stopped part way is finished by the next.
func TestImportUsers(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	c := authConfig(t, dir, "")
	ctx := users.WithActor(context.Background(), "sam")
	fileStore, err := users.Open(c.UsersFile())
	if err != nil {
		t.Fatal(err)
	}
	for _, nu := range []users.NewUser{{Username: "jlee", Role: users.Analyst, Password: "a-good-password"},
		{Username: "off", Role: users.Viewer, Password: "a-good-password"}, {Username: "admin", Role: users.Admin, Password: "a-good-password"}} {
		if _, err := fileStore.Create(ctx, nu); err != nil {
			t.Fatal(err)
		}
	}
	off := true
	if _, err := fileStore.Update(ctx, "off", users.Change{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := fileStore.SeeDirectoryUser(ctx, users.DirectoryUser{Username: "dora", DN: "CN=Dora,DC=corp", Name: "Dora", Role: users.Viewer}); err != nil {
		t.Fatal(err)
	}
	fileStore.RecordSignIn(ctx, "jlee")
	fileStore.RecordBuiltinSignIn(ctx)
	jleeHash := mustRecord(t, c.UsersFile(), "jlee").Hash
	passwd, _ := users.HashPassword("from-passwd")
	if err := os.WriteFile(c.AdminHashFile(), []byte(passwd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c = authConfig(t, dir, "")
	if c.AdminHashFromFile() != passwd {
		t.Fatal("the admin-password-hash file was not read")
	}

	a := newAuthMember(t, o, "siem-a", dir, c, nil)
	name, hash, ok := a.auth.Builtin()
	if !ok || name != "admin" || !matches(hash, "from-passwd") {
		t.Fatalf("built-in admin %q %v", name, ok)
	}
	ub := &clusterauth.UsersBackend{Docs: a.auth}
	recs, err := ub.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("imported %d users: %v", len(recs), recs)
	}
	if r := recs["jlee"]; r.Hash != jleeHash || r.Role != users.Analyst || r.Epoch != 1 || r.LastSignIn != nil {
		t.Errorf("jlee %+v", r)
	}
	if r := recs["off"]; !r.Disabled {
		t.Errorf("off %+v", r)
	}
	if r := recs["dora"]; r.Source != users.SourceDirectory || r.DN != "CN=Dora,DC=corp" {
		t.Errorf("dora %+v", r)
	}
	if !strings.Contains(a.logs.String(), "users.json has a user with the built-in admin's name") {
		t.Error("the user named like the built-in admin is not reported")
	}
	seen := &clusterauth.LastSeen{Client: func() (*store.Client, string) { return o.cl, testPrefix }, Node: "siem-a"}
	all, err := seen.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if all["jlee"].At.IsZero() || all["admin"].At.IsZero() || all["jlee"].Node != "siem-a" {
		t.Errorf("last sign-ins %+v", all)
	}
	nc, _ := a.rt.NodeCfg().Get()
	if nc.UsersApplied == "" {
		t.Error("the import did not record what the files say of auth.*")
	}

	// Again: nothing is written.
	im := a.importer(shared.ImportUsers)
	o.fake.Requests()
	if err := im.Run(ctx, "sam"); err != nil {
		t.Fatal(err)
	}
	for _, r := range o.fake.Requests() {
		if strings.Contains(r, "user%3A") || strings.Contains(r, "user:") {
			if !strings.HasPrefix(r, "GET") && !strings.Contains(r, "_search") {
				t.Errorf("a second run wrote %s", r)
			}
		}
	}

	// Stopped part way: a later user could not be written; the next run
	// finishes.
	if _, err := fileStore.Create(ctx, users.NewUser{Username: "zz", Role: users.Viewer, Password: "a-good-password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fileStore.Create(ctx, users.NewUser{Username: "aa", Role: users.Viewer, Password: "a-good-password"}); err != nil {
		t.Fatal(err)
	}
	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if method != "GET" && strings.Contains(path, "zz") {
			return &ostest.Fault{Status: 503, Type: "unavailable_shards_exception"}
		}
		return nil
	})
	if err := im.Run(ctx, "sam"); err == nil {
		t.Fatal("the run did not fail")
	}
	o.fake.SetFault(nil)
	if err := im.Run(ctx, "sam"); err != nil {
		t.Fatal(err)
	}
	if recs, _ := ub.Load(); recs["zz"].Username != "zz" || recs["aa"].Username != "aa" {
		t.Errorf("the second run did not finish: %v", recs)
	}
}

func mustRecord(t *testing.T, path, name string) users.Record {
	t.Helper()
	recs, _, err := users.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := recs[name]
	if !ok {
		t.Fatalf("no %s in %s", name, path)
	}
	return r
}

// The founder imports the directory sign-in settings saved on its Users
// page with the service account password sealed again for the cluster,
// or auth.ldap from signalith.yaml.
func TestImportDirectory(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	c := authConfig(t, dir, "")
	secrets.SetDefault(secrets.NewKeyring(dir))
	d, err := users.OpenDirectory(c.DirectoryFile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := users.Preset(users.TypeActiveDirectory)
	on := true
	s.Enabled, s.URL, s.BindDN, s.BindPassword = &on, "ldaps://dc1.corp.example.com", "CN=svc,DC=corp,DC=example,DC=com", "svc-pass"
	s.UserBaseDN = "DC=corp,DC=example,DC=com"
	s.AdminGroups = []string{"CN=Admins,DC=corp,DC=example,DC=com"}
	s.Normalize()
	if err := d.Save(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(c.DirectoryFile()); strings.Contains(string(raw), "svc-pass") {
		t.Fatal("directory.json holds the password in the clear")
	}
	a := newAuthMember(t, o, "siem-a", dir, c, nil)
	bk := &clusterauth.DirectoryBackend{Docs: a.auth}
	got, saved, problem := bk.Load()
	if !saved || problem != "" || got.URL != s.URL || got.BindPassword != "svc-pass" || bk.From().Source != clusterauth.FromImport {
		t.Fatalf("imported %+v %v %q %+v", got, saved, problem, bk.From())
	}

	// From signalith.yaml.
	o2 := newOS(t)
	dir2 := t.TempDir()
	c2 := authConfig(t, dir2, "  ldap:\n    type: openldap\n    url: ldaps://ldap.example.org\n    bind_dn: cn=svc,dc=example,dc=org\n    bind_password: yaml-pass\n    user_base_dn: ou=people,dc=example,dc=org\n    admin_groups: [\"cn=admins,dc=example,dc=org\"]\n")
	b := newAuthMember(t, o2, "siem-b", dir2, c2, nil)
	bk = &clusterauth.DirectoryBackend{Docs: b.auth}
	if got, _, problem := bk.Load(); got.URL != "ldaps://ldap.example.org" || got.BindPassword != "yaml-pass" || problem != "" {
		t.Fatalf("imported from yaml %+v %q", got, problem)
	}
	if res := b.apply(); len(res.Applied) != 0 || len(res.Drift) != 0 {
		t.Errorf("the founder's first apply after the import: %+v", res)
	}
}

// V21: the built-in admin's password and the directory sign-in settings
// of a server's files apply only when they change: an unchanged
// SIGNALITH_ADMIN_PASSWORD does not undo signalith passwd, a changed one
// applies once, ending the built-in admin's sessions, and is audited; an
// unchanged auth.ldap does not undo a change made on the Users page.
func TestAuthAppliedWhenChanged(t *testing.T) {
	o := newOS(t)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "first-env-pass")
	dirA := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, ""), nil)
	if _, h, _ := a.auth.Builtin(); !matches(h, "first-env-pass") {
		t.Fatal("the environment's password was not imported")
	}
	if res := a.apply(); len(res.Applied) != 0 {
		t.Fatalf("first apply %+v", res)
	}
	ctx := context.Background()
	np, _ := users.HashPassword("from-passwd")
	if err := a.auth.SetBuiltinHash(ctx, "sam", np); err != nil {
		t.Fatal(err)
	}
	if res := a.apply(); len(res.Applied) != 0 {
		t.Fatalf("an unchanged environment applied %v", res.Applied)
	}
	u, _, _ := a.auth.BuiltinUser()
	if !matches(u.PasswordHash, "from-passwd") {
		t.Fatal("an unchanged environment undid signalith passwd")
	}
	epoch := u.SessionEpoch

	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "second-env-pass")
	a.cfg.Store(authConfig(t, dirA, ""))
	res := a.apply()
	if len(res.Applied) != 1 || res.Applied[0] != "auth.admin_password_hash" {
		t.Fatalf("a changed environment %+v", res)
	}
	a.cycle()
	u, _, _ = a.auth.BuiltinUser()
	if !matches(u.PasswordHash, "second-env-pass") || u.SessionEpoch <= epoch {
		t.Errorf("after the change: epoch %d -> %d", epoch, u.SessionEpoch)
	}
	if !strings.Contains(a.logs.String(), "auth.admin_password_hash applied from") {
		t.Errorf("not audited:\n%s", a.logs.String())
	}
	if res := a.apply(); len(res.Applied) != 0 {
		t.Fatalf("applied twice: %v", res.Applied)
	}

	// B joins with auth.ldap in its file: its first start only records it
	// (and adds its agent tokens to the shared ones).
	ldap := func(url string) string {
		return "  ldap:\n    type: openldap\n    url: " + url + "\n    bind_dn: cn=svc,dc=example,dc=org\n    bind_password: yaml-pass\n    user_base_dn: ou=people,dc=example,dc=org\n    admin_groups: [\"cn=admins,dc=example,dc=org\"]\n"
	}
	dirB := t.TempDir()
	b := newAuthMember(t, o, "siem-b", dirB, authConfig(t, dirB, ldap("ldaps://ldap.example.org")), a.key())
	if res := b.apply(); !slices.Equal(res.Applied, []string{"ingest.tokens"}) {
		t.Fatalf("B's first apply %+v", res)
	}
	if _, ok := b.auth.Directory().Get(); ok {
		t.Fatal("B's first start wrote the directory settings")
	}
	// Edited on the page.
	page := &clusterauth.DirectoryBackend{Docs: a.auth, Node: "siem-a"}
	s := users.Preset(users.TypeOpenLDAP)
	on := true
	s.Enabled, s.URL, s.BindDN, s.BindPassword, s.UserBaseDN = &on, "ldaps://page.example.org", "cn=svc,dc=example,dc=org", "page-pass", "ou=people,dc=example,dc=org"
	s.Normalize()
	if err := page.Save(ctx, "alice", "", s); err != nil {
		t.Fatal(err)
	}
	if res := b.apply(); len(res.Applied) != 0 {
		t.Fatalf("an unchanged auth.ldap applied %v", res.Applied)
	}
	bk := &clusterauth.DirectoryBackend{Docs: b.auth}
	if got, _, _ := bk.Load(); got.URL != "ldaps://page.example.org" {
		t.Fatalf("the page's change was undone: %s", got.URL)
	}
	if !contains(b.apply().Drift, "auth.ldap") {
		t.Error("auth.ldap differing from the shared settings is not drift")
	}
	// Changed in B's file: applied once.
	b.cfg.Store(authConfig(t, dirB, ldap("ldaps://new.example.org")))
	if res := b.apply(); len(res.Applied) != 1 || res.Applied[0] != "auth.ldap" {
		t.Fatalf("a changed auth.ldap %+v", res)
	}
	b.cycle()
	got, _, problem := bk.Load()
	if got.URL != "ldaps://new.example.org" || got.BindPassword != "yaml-pass" || problem != "" || bk.From().Source != clusterauth.FromYAML || bk.From().Node != "siem-b" {
		t.Fatalf("after the change %+v %q %+v", got, problem, bk.From())
	}
	// The service account password from the environment: applied once.
	t.Setenv("SIGNALITH_LDAP_BIND_PASSWORD", "env-pass")
	b.cfg.Store(authConfig(t, dirB, ldap("ldaps://new.example.org")))
	if res := b.apply(); len(res.Applied) != 1 || res.Applied[0] != "auth.ldap.bind_password" {
		t.Fatalf("a new environment password %+v", res)
	}
	b.cycle()
	if got, _, _ := bk.Load(); got.BindPassword != "env-pass" || bk.From().Source != clusterauth.FromEnv {
		t.Fatalf("the environment's password %q", got.BindPassword)
	}
	if res := b.apply(); len(res.Applied) != 0 {
		t.Fatalf("applied twice: %v", res.Applied)
	}

	// The page points the settings at another server; the environment's
	// password then changes: it is not sealed for that server.
	evil := s
	evil.URL, evil.BindPassword = "ldaps://evil.example.net", "whatever"
	if err := page.Save(ctx, "mallory", "", evil); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	t.Setenv("SIGNALITH_LDAP_BIND_PASSWORD", "rotated-pass")
	b.cfg.Store(authConfig(t, dirB, ldap("ldaps://new.example.org")))
	if res := b.apply(); len(res.Applied) != 0 {
		t.Fatalf("a password for another connection applied %v", res.Applied)
	}
	b.cycle()
	if got, _, _ := bk.Load(); got.URL != "ldaps://evil.example.net" || got.BindPassword != "whatever" {
		t.Fatalf("the environment's password reached the page's server: %+v", got)
	}
	if !strings.Contains(b.logs.String(), "no longer connect as auth.ldap") {
		t.Errorf("not logged:\n%s", b.logs.String())
	}
	// Without auth.ldap in signalith.yaml the environment's password is
	// not used at all.
	t.Setenv("SIGNALITH_LDAP_BIND_PASSWORD", "another-pass")
	b.cfg.Store(authConfig(t, dirB, ""))
	if vals := fileValues(b.cfg.Load()); slices.ContainsFunc(vals, func(fv fileValue) bool { return fv.password != "" }) {
		t.Error("the environment's password is a value without auth.ldap")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
