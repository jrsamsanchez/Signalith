package respond

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
	"github.com/jrsamsanchez/signalith/internal/users/ldaptest"
)

func fakeAD(t *testing.T, opts ldaptest.Options) (*ldaptest.Server, users.LDAPSettings) {
	t.Helper()
	opts.ActiveDirectory = true
	srv, err := ldaptest.Start(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ldaptest.LoadActiveDirectory(srv)
	s := users.Preset(users.TypeActiveDirectory)
	s.URL, s.CACert, s.StartTLS = srv.URL, srv.CACert, opts.StartTLS
	s.BindDN, s.BindPassword = ldaptest.ADService, ldaptest.ServicePassword
	s.UserBaseDN = ldaptest.ADBase
	s.Normalize()
	return srv, s
}

func TestDisableAndEnableADUser(t *testing.T) {
	srv, s := fakeAD(t, ldaptest.Options{TLS: true})
	srv.AllowWrite(ldaptest.ADService)
	r, mem := runnerWith(t,
		Connector{Name: "disable", Label: "Disable AD user", Kind: KindDisableUser},
		Connector{Name: "enable", Label: "Enable AD user", Kind: KindDisableUser, Operation: OpEnable})
	r.Directory = func() users.LDAPSettings { return s }
	if got := r.Describe(Connector{Kind: KindDisableUser, Operation: OpDisable}, "bob"); got != "Disable the AD account of bob in corp.example.com." {
		t.Errorf("Describe = %q", got)
	}
	run, err := r.Run(t.Context(), Request{Action: "disable", Target: `CORP\bob`, Reason: "phished", Actor: Actor{Name: "ann"}})
	if err != nil || run.Status != StatusSucceeded || run.Summary != "bob is now disabled." {
		t.Fatalf("disable: %+v %v", run, err)
	}
	if v := srv.Attr(ldaptest.ADBobDN, "userAccountControl"); len(v) != 1 || v[0] != "514" {
		t.Errorf("userAccountControl after disable = %v", v)
	}
	// Again: nothing to change.
	run, _ = r.Run(t.Context(), Request{Action: "disable", Target: "bob@corp.example.com", Reason: "again", Actor: Actor{Name: "ann"}})
	if run.Status != StatusSucceeded || !strings.Contains(run.Summary, "already disabled") {
		t.Errorf("twice: %+v", run)
	}
	// Enable needs no reason, and finds the disabled account.
	run, err = r.Run(t.Context(), Request{Action: "enable", Target: "bob", Actor: Actor{Name: "ann"}})
	if err != nil || run.Status != StatusSucceeded {
		t.Fatalf("enable: %+v %v", run, err)
	}
	if v := srv.Attr(ldaptest.ADBobDN, "userAccountControl"); v[0] != "512" {
		t.Errorf("userAccountControl after enable = %v", v)
	}
	// Signalith's own account is never changed.
	srv.Add(ldaptest.ADService, map[string][]string{"objectClass": {"top", "person", "user"}, "objectCategory": {"CN=Person,CN=Schema,CN=Configuration," + ldaptest.ADBase},
		"sAMAccountName": {"svc-signalith"}, "userAccountControl": {"66048"}})
	run, _ = r.Run(t.Context(), Request{Action: "disable", Target: "svc-signalith", Reason: "x", Actor: Actor{Name: "ann"}})
	if run.Status != StatusFailed || !strings.Contains(run.Error, "cannot change itself") {
		t.Errorf("self: %+v", run)
	}
	run, _ = r.Run(t.Context(), Request{Action: "disable", Target: "pat", Reason: "x", Actor: Actor{Name: "ann"}})
	if run.Status != StatusFailed || !strings.Contains(run.Error, "more than one") {
		t.Errorf("ambiguous: %+v", run)
	}
	runs, _ := mem.List(t.Context(), Filter{Action: "disable"})
	if len(runs) != 4 {
		t.Errorf("audit has %d disable runs", len(runs))
	}
}

func TestDisableUserNeedsRightsAndEncryption(t *testing.T) {
	srv, s := fakeAD(t, ldaptest.Options{TLS: true})
	r, _ := runnerWith(t, Connector{Name: "disable", Kind: KindDisableUser})
	r.Directory = func() users.LDAPSettings { return s }
	run, _ := r.Run(t.Context(), Request{Action: "disable", Target: "bob", Reason: "x", Actor: Actor{Name: "ann"}})
	if run.Status != StatusFailed || !strings.Contains(run.Error, `Delegate "Read/Write userAccountControl"`) {
		t.Errorf("no rights: %+v", run)
	}
	if v := srv.Attr(ldaptest.ADBobDN, "userAccountControl"); v[0] != "512" {
		t.Errorf("changed without rights: %v", v)
	}
	// A plain ldap:// directory is refused before connecting.
	plain, ps := fakeAD(t, ldaptest.Options{})
	plain.AllowWrite(ldaptest.ADService)
	r.Directory = func() users.LDAPSettings { return ps }
	run, _ = r.Run(t.Context(), Request{Action: "disable", Target: "bob", Reason: "x", Actor: Actor{Name: "ann"}})
	if run.Status != StatusFailed || !strings.Contains(run.Error, "encrypted connection") || len(plain.Modifies()) != 0 {
		t.Errorf("plain: %+v", run)
	}
	if p := r.problemOf(Connector{Kind: KindDisableUser}); !strings.Contains(p, "ldaps://") {
		t.Errorf("problem %q", p)
	}
	// StartTLS works, with the action's own write account.
	st, ss := fakeAD(t, ldaptest.Options{StartTLS: true})
	st.Add("CN=svc-respond,OU=Service Accounts,"+ldaptest.ADBase, map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"svc-respond"}})
	st.SetPassword("CN=svc-respond,OU=Service Accounts,"+ldaptest.ADBase, "respond-pass")
	st.AllowWrite("CN=svc-respond,OU=Service Accounts," + ldaptest.ADBase)
	r, _ = runnerWith(t, Connector{Name: "disable", Kind: KindDisableUser, BindDN: "CN=svc-respond,OU=Service Accounts," + ldaptest.ADBase, BindPassword: "respond-pass"})
	r.Directory = func() users.LDAPSettings { return ss }
	run, _ = r.Run(t.Context(), Request{Action: "disable", Target: "carol", Reason: "x", Actor: Actor{Name: "ann"}})
	if run.Status != StatusSucceeded || st.Attr(ldaptest.ADCarolDN, "userAccountControl")[0] != "514" {
		t.Errorf("starttls: %+v", run)
	}
	// The test connects and finds the account without changing it.
	c, _, _ := r.Actions.Get("disable")
	rep := r.Test(t.Context(), c, "dave", false, "admin")
	if !rep.OK || len(st.Modifies()) != 1 || !strings.Contains(rep.Steps[len(rep.Steps)-1].Message, "enabled now") {
		t.Errorf("test: %+v, modifies %v", rep, st.Modifies())
	}
}

func TestDisableUserOnOpenLDAP(t *testing.T) {
	srv, err := ldaptest.Start(ldaptest.Options{TLS: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ldaptest.LoadOpenLDAP(srv)
	srv.AllowWrite(ldaptest.OLService)
	s := users.Preset(users.TypeOpenLDAP)
	s.URL, s.CACert = srv.URL, srv.CACert
	s.BindDN, s.BindPassword = ldaptest.OLService, ldaptest.ServicePassword
	s.UserBaseDN = "ou=people," + ldaptest.OLBase
	r, _ := runnerWith(t,
		Connector{Name: "lock", Kind: KindDisableUser},
		Connector{Name: "lock2", Kind: KindDisableUser, DisableAttribute: "nsAccountLock", DisableValue: "TRUE"},
		Connector{Name: "unlock", Kind: KindDisableUser, Operation: OpEnable, DisableAttribute: "nsAccountLock"})
	r.Directory = func() users.LDAPSettings { return s }
	if p := r.problemOf(Connector{Kind: KindDisableUser}); !strings.Contains(p, "not Active Directory") {
		t.Errorf("problem %q", p)
	}
	run, _ := r.Run(t.Context(), Request{Action: "lock", Target: "bob", Reason: "x", Actor: Actor{Name: "ann"}})
	if run.Status != StatusFailed || !strings.Contains(run.Error, "nsAccountLock") {
		t.Errorf("no attribute: %+v", run)
	}
	run, _ = r.Run(t.Context(), Request{Action: "lock2", Target: "bob", Reason: "x", Actor: Actor{Name: "ann"}})
	if run.Status != StatusSucceeded || strings.Join(srv.Attr(ldaptest.OLBobDN, "nsAccountLock"), ",") != "TRUE" {
		t.Errorf("lock: %+v %v", run, srv.Attr(ldaptest.OLBobDN, "nsAccountLock"))
	}
	run, _ = r.Run(t.Context(), Request{Action: "unlock", Target: "bob", Actor: Actor{Name: "ann"}})
	if run.Status != StatusSucceeded || srv.Attr(ldaptest.OLBobDN, "nsAccountLock") != nil {
		t.Errorf("unlock: %+v", run)
	}
}
