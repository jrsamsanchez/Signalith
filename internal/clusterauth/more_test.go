package clusterauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/users"
	"github.com/jrsamsanchez/signalith/internal/users/ldaptest"
)

// V17: while OpenSearch cannot be used, the built-in admin can sign in,
// a local admin only with a copy of the shared settings at most 24 hours
// old, and directory users not at all; once OpenSearch is back, sessions
// made meanwhile are written through only for users still allowed.
func TestDegradedSignIn(t *testing.T) {
	o, a, _, clk := pair(t)
	ctx := context.Background()
	boss := a.addUser("boss", users.Admin)
	viewer := a.addUser("vic", users.Viewer)
	a.degraded.Store(true)
	o.fake.Requests()

	builtin, err := a.sessions.Create(ctx, auth.NewSession{User: "Admin", Epoch: 1, Method: users.SourceBuiltin})
	if err != nil {
		t.Fatalf("built-in admin while degraded: %v", err)
	}
	if !a.valid(builtin) {
		t.Fatal("the built-in admin's degraded session does not work")
	}
	confirmed := clk.Now().Add(-23 * time.Hour)
	a.confirmed.Store(&confirmed)
	local, err := a.sessions.Create(ctx, auth.NewSession{User: "boss", Epoch: boss.SessionEpoch, Method: users.SourceLocal})
	if err != nil {
		t.Fatalf("local admin with a 23 hour old copy: %v", err)
	}
	old := clk.Now().Add(-25 * time.Hour)
	a.confirmed.Store(&old)
	if _, err := a.sessions.Create(ctx, auth.NewSession{User: "boss", Epoch: boss.SessionEpoch, Method: users.SourceLocal}); !errors.Is(err, ErrDegraded) {
		t.Errorf("local admin with a 25 hour old copy: %v", err)
	}
	a.confirmed.Store(&confirmed)
	if _, err := a.sessions.Create(ctx, auth.NewSession{User: "vic", Epoch: viewer.SessionEpoch, Method: users.SourceLocal}); !errors.Is(err, ErrDegraded) {
		t.Errorf("a viewer while degraded: %v", err)
	}
	if _, err := a.sessions.Create(ctx, auth.NewSession{User: "dora", Epoch: 1, Method: users.SourceDirectory}); !errors.Is(err, ErrDegraded) {
		t.Errorf("a directory user while degraded: %v", err)
	}
	if reqs := requestsTo(o.fake.Requests(), "_sessions"); len(reqs) != 0 {
		t.Errorf("degraded sign-ins asked OpenSearch: %v", reqs)
	}
	if !strings.Contains(a.logs.String(), "signed in while OpenSearch cannot be written") {
		t.Error("degraded sign-ins are not audited")
	}
	s, ok := a.sessions.Lookup(ctx, local, false)
	if !ok || !s.Degraded {
		t.Errorf("the degraded session: %+v %v", s, ok)
	}

	// Back: boss was disabled meanwhile (on another server).
	a.degraded.Store(false)
	off := true
	if _, err := a.store.Update(users.WithActor(ctx, "admin"), "boss", users.Change{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	a.sessions.Recover(ctx)
	if o.sessionDocs(t, "admin") != 1 {
		t.Error("the built-in admin's session was not written through")
	}
	if o.sessionDocs(t, "boss") != 0 || a.valid(local) {
		t.Error("the disabled admin's degraded session was kept")
	}
	if !a.valid(builtin) {
		t.Error("the built-in admin's session ended when written through")
	}

	// A degraded session lasts an hour at most.
	a.degraded.Store(true)
	again, err := a.sessions.Create(ctx, auth.NewSession{User: "admin", Epoch: 1, Method: users.SourceBuiltin})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(DegradedSession + time.Second)
	if a.valid(again) {
		t.Error("a degraded session outlived an hour")
	}
}

// V20: the service account password is sealed for the connection the
// settings make: B opens it; settings moved to another server by a write
// that does not seal it again leave it out, with a problem saying to
// enter it again.
func TestDirectoryPasswordBound(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	ab := &DirectoryBackend{Docs: a.docs, Node: "siem-a"}
	bb := &DirectoryBackend{Docs: b.docs, Node: "siem-b"}
	if _, saved, _ := bb.Load(); saved {
		t.Fatal("settings before any were saved")
	}
	s := users.Preset(users.TypeActiveDirectory)
	on := true
	s.Enabled, s.URL, s.BindDN, s.BindPassword = &on, "ldaps://dc1.corp.example.com", "CN=svc,DC=corp,DC=example,DC=com", "svc-pass"
	s.UserBaseDN = "DC=corp,DC=example,DC=com"
	s.Normalize()
	if err := ab.SaveFrom(ctx, "admin", s, FromYAML); err != nil {
		t.Fatal(err)
	}
	body, _ := a.docs.Directory().Get()
	if strings.Contains(body.BindPassword, "svc-pass") || body.Settings.BindPassword != "" {
		t.Fatal("the password is stored in the clear")
	}
	b.cycle()
	got, saved, problem := bb.Load()
	if !saved || problem != "" || got.BindPassword != "svc-pass" || got.URL != s.URL {
		t.Fatalf("B's settings: %+v %v %q", got, saved, problem)
	}
	if f := bb.From(); f.Source != FromYAML || f.Node != "siem-a" || f.At.IsZero() {
		t.Errorf("from: %+v", f)
	}
	if bb.Revision() == 0 || bb.ETag() == "" {
		t.Error("no revision or etag")
	}

	// Spelling does not matter.
	if _, err := a.docs.Directory().Mutate(ctx, "x", func(cur *DirectoryBody) error {
		cur.Settings.URL = " LDAPS://DC1.corp.example.com "
		cur.Settings.BindDN = "cn=svc, dc=corp, dc=example, dc=com"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if got, _, problem := bb.Load(); got.BindPassword != "svc-pass" || problem != "" {
		t.Errorf("a respelled connection lost the password: %q", problem)
	}
	for name, change := range map[string]func(*users.LDAPSettings){
		"url":     func(s *users.LDAPSettings) { s.URL = "ldaps://evil.example.com" },
		"bind dn": func(s *users.LDAPSettings) { s.BindDN = "CN=other,DC=corp,DC=example,DC=com" },
		"tls":     func(s *users.LDAPSettings) { s.TLSSkipVerify = true },
	} {
		if err := ab.SaveFrom(ctx, "admin", s, FromPage); err != nil {
			t.Fatal(err)
		}
		if _, err := a.docs.Directory().Mutate(ctx, "x", func(cur *DirectoryBody) error {
			change(&cur.Settings)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		b.cycle()
		got, _, problem := bb.Load()
		if got.BindPassword != "" || !strings.Contains(problem, "entered again") {
			t.Errorf("%s moved: password %q, problem %q", name, got.BindPassword, problem)
		}
	}

	// SetBindPassword seals a new one for the settings as they are, when
	// they connect as the caller expects.
	cur, _ := a.docs.Directory().Get()
	if err := ab.SetBindPassword(ctx, "admin", "new-pass", FromEnv, s); !errors.Is(err, ErrOtherConnection) {
		t.Fatalf("a password for another connection: %v", err)
	}
	if err := ab.SetBindPassword(ctx, "admin", "new-pass", FromEnv, cur.Settings); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if got, _, problem := bb.Load(); got.BindPassword != "new-pass" || problem != "" || bb.From().Source != FromEnv {
		t.Errorf("after SetBindPassword: %q %q", got.BindPassword, problem)
	}
	// A save based on an old version is refused.
	etag := bb.ETag()
	if err := ab.Save(ctx, "alice", "", s); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if err := bb.Save(ctx, "bob", etag, s); err == nil {
		t.Error("a save based on an old version was made")
	}
}

// V23: one server checks the signed-in directory users with the
// directory: a user taken out of their group is refused, which ends
// their sessions everywhere; a changed role is written; a change of the
// settings starts a check at once.
func TestRecheckDirectoryUsers(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	srv, err := ldaptest.Start(ldaptest.Options{TLS: true, ActiveDirectory: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ldaptest.LoadActiveDirectory(srv)
	s := users.Preset(users.TypeActiveDirectory)
	on := true
	s.Enabled, s.URL, s.CACert = &on, srv.URL, srv.CACert
	s.BindDN, s.BindPassword = ldaptest.ADService, ldaptest.ServicePassword
	s.UserBaseDN = ldaptest.ADBase
	s.AdminGroups = []string{ldaptest.ADAdmins}
	s.AnalystGroups = []string{ldaptest.ADAnalysts}
	s.ViewerGroups = []string{ldaptest.ADViewers}
	s.Normalize()
	ab := &DirectoryBackend{Docs: a.docs, Node: "siem-a"}
	if err := ab.SaveFrom(ctx, "admin", s, FromPage); err != nil {
		t.Fatal(err)
	}
	dir := users.NewDirectory(ab)
	cookies := map[string]string{}
	for _, name := range []string{"alice", "bob", "carol", "jsmith"} {
		du, err := dir.Authenticate(ctx, name, ldaptest.Password)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := a.store.SeeDirectoryUser(ctx, *du); err != nil {
			t.Fatal(err)
		}
		if name != "jsmith" {
			cookies[name] = a.signIn(name, false)
		}
	}
	b.cycle()
	for name, c := range cookies {
		if !b.valid(c) {
			t.Fatalf("%s's session does not work on B", name)
		}
	}
	srv.Add(ldaptest.ADAnalysts, map[string][]string{"objectClass": {"top", "group"}, "member": {ldaptest.ADSmithDN, ldaptest.ADFrankDN, ldaptest.ADCarolDN}})
	r := &Recheck{Docs: a.docs, Store: a.store, Users: a.ub, Directory: dir, Sessions: a.sessions, Log: a.log}
	if n := r.Run(ctx); n != 3 {
		t.Errorf("looked up %d users, want the 3 with a session", n)
	}
	if u, _ := a.store.Get("bob"); u.Refused == "" {
		t.Errorf("bob was not refused: %+v", u)
	}
	if u, _ := a.store.Get("carol"); u.Role != users.Analyst {
		t.Errorf("carol's role: %s", u.Role)
	}
	b.cycle()
	if b.valid(cookies["bob"]) {
		t.Error("bob's session still works on B")
	}
	if !b.valid(cookies["carol"]) || !b.valid(cookies["alice"]) {
		t.Error("a user still allowed lost their session")
	}
	logs := a.logs.String()
	if !strings.Contains(logs, "directory user lost access") || !strings.Contains(logs, "directory user's role changed") {
		t.Error("the changes are not audited")
	}

	// A change of the settings on B starts a check on A at once.
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go r.Loop(lctx)
	deadline := time.Now().Add(10 * time.Second)
	for {
		r.mu.Lock()
		n := len(r.checked)
		r.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first check did not run")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	bb := &DirectoryBackend{Docs: b.docs, Node: "siem-b"}
	ns, _, _ := bb.Load()
	ns.AdminGroups = []string{"CN=Nobody,OU=Groups," + ldaptest.ADBase}
	if err := bb.Save(ctx, "carol", "", ns); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	deadline = time.Now().Add(10 * time.Second)
	for {
		if u, _ := a.store.Get("alice"); u.Refused != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a change of the settings did not start a check")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Lockouts: a lock tripped on A is written once and refused on B, until
// it ends; housekeeping deletes it then.
func TestLocksShared(t *testing.T) {
	o, a, b, clk := pair(t)
	ctx := context.Background()
	limiter := func() *auth.Limiter {
		l := auth.NewLimiter()
		l.Now, l.Divisor = clk.Now, func() int { return 2 }
		return l
	}
	la, lb := limiter(), limiter()
	locksA := &Locks{Docs: a.docs, Client: o.client, Node: "n_siem-a", Limiter: la, Log: a.log, Now: clk.Now}
	locksB := &Locks{Docs: b.docs, Client: o.client, Node: "n_siem-b", Limiter: lb, Log: b.log, Now: clk.Now}
	locksA.Listen()
	locksB.Listen()
	c := auth.Client{Address: "10.0.0.1"}
	try := func(l *auth.Limiter) (bool, auth.Failure) {
		at, err := l.Begin(c, "jlee")
		if err != nil {
			return false, auth.Failure{}
		}
		return true, at.Fail()
	}
	for i := 1; i <= 5; i++ {
		ok, f := try(la)
		if !ok {
			t.Fatalf("refused on try %d", i)
		}
		if f.Locked != (i == 5) {
			t.Fatalf("try %d: locked %v (limits halved for 2 servers: 5)", i, f.Locked)
		}
	}
	secret := a.key().LockKey()
	id := LockID(a.docs.ClusterID(), auth.ScopeAddressAccount, auth.LockKey(secret, "p\x0010.0.0.1\x00jlee"))
	deadline := time.Now().Add(5 * time.Second)
	for o.fake.Source(runtimeIndex(testPrefix), id) == nil {
		if time.Now().After(deadline) {
			t.Fatal("the lock was not written")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if src := o.fake.Source(runtimeIndex(testPrefix), id); strings.Contains(src["key"].(string), "10.0.0.1") {
		t.Error("the lock names the address")
	}
	b.cycle()
	for {
		if ok, _ := try(lb); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("B does not refuse what A locked")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !locksB.Due() {
		// Reloaded just now through watch:locks.
		clk.Advance(ReloadEvery)
		if !locksB.Due() {
			t.Error("Due after ReloadEvery")
		}
	}
	// An earlier end does not replace a later one.
	if err := locksB.Write(ctx, auth.ScopeAddressAccount, auth.LockKey(secret, "p\x0010.0.0.1\x00jlee"), clk.Now()); err != nil {
		t.Fatal(err)
	}
	if err := locksB.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, _ := try(lb); ok {
		t.Error("an earlier end replaced the lock")
	}
	clk.Advance(16 * time.Minute)
	if err := locksB.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, _ := try(lb); !ok {
		t.Error("B still refuses after the lock ended")
	}
	if n, err := locksA.Housekeep(ctx); err != nil || n != 1 {
		t.Errorf("housekeeping deleted %d: %v", n, err)
	}
}

// Lock documents written without the cluster key are ignored, and a
// signed lock counts for no longer than the limiter's own longest.
func TestLocksForged(t *testing.T) {
	o, a, b, clk := pair(t)
	ctx := context.Background()
	lb := auth.NewLimiter()
	lb.Now = clk.Now
	locksB := &Locks{Docs: b.docs, Client: o.client, Node: "n_siem-b", Limiter: lb, Log: b.log, Now: clk.Now}
	locksB.Listen()
	c := auth.Client{Address: "10.0.0.7"}
	refused := func() bool {
		_, err := lb.Begin(c, "admin")
		return err != nil
	}
	cid := a.docs.ClusterID()
	key := auth.LockKey(a.key().LockKey(), "a\x0010.0.0.7")
	id := LockID(cid, auth.ScopeAddress, key)
	o.fake.Put(runtimeIndex(testPrefix), id, map[string]any{"kind": "lock", "scope": auth.ScopeAddress, "key": key,
		"until": "2100-01-01T00:00:00Z", "node": "n_x", "at": clk.Now().UTC().Format(time.RFC3339Nano)})
	if err := locksB.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if refused() {
		t.Fatal("an unsigned lock document locked an address")
	}
	// The same, signed with the cluster key (written over the unsigned
	// one, whose later end does not count): it counts, for at most the
	// longest lock.
	locksA := &Locks{Docs: a.docs, Client: o.client, Node: "n_siem-a", Limiter: auth.NewLimiter(), Now: clk.Now}
	if err := locksA.Write(ctx, auth.ScopeAddress, key, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err := locksB.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if !refused() {
		t.Fatal("a signed lock is not refused")
	}
	clk.Advance(16 * time.Minute)
	if refused() {
		t.Error("a lock reported for years lasts longer than the longest lock")
	}
}

// V29: last sign-ins are written at most once a minute per server, and
// the newest wins, with its server.
func TestLastSeen(t *testing.T) {
	o, _, _, clk := pair(t)
	ctx := context.Background()
	la := &LastSeen{Client: o.client, Node: "siem-a", Now: clk.Now}
	lb := &LastSeen{Client: o.client, Node: "siem-b", Now: clk.Now}
	o.fake.Requests()
	for range 3 {
		if err := la.Record(ctx, "JLee", MethodSession); err != nil {
			t.Fatal(err)
		}
		clk.Advance(20 * time.Second)
	}
	if n := len(requestsTo(o.fake.Requests(), "lastseen")); n != 1 {
		t.Errorf("%d writes in 40 seconds, want 1", n)
	}
	if err := la.Record(ctx, "jlee", MethodSession); err != nil {
		t.Fatal(err)
	}
	if n := len(requestsTo(o.fake.Requests(), "lastseen")); n != 1 {
		t.Errorf("no write after a minute: %d", n)
	}
	clk.Advance(time.Minute)
	if err := lb.Record(ctx, "jlee", MethodBasic); err != nil {
		t.Fatal(err)
	}
	// An imported older sign-in changes nothing.
	if err := la.Import(ctx, Seen{User: "jlee", At: clk.Now().Add(-48 * time.Hour), Node: "siem-a", Method: MethodSession}); err != nil {
		t.Fatal(err)
	}
	if err := la.Import(ctx, Seen{User: "ann", At: clk.Now().Add(-48 * time.Hour), Node: "old", Method: MethodSession}); err != nil {
		t.Fatal(err)
	}
	all, err := la.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s := all["jlee"]; s.Node != "siem-b" || s.Method != MethodBasic || !s.At.Equal(clk.Now()) {
		t.Errorf("jlee: %+v", s)
	}
	if s := all["ann"]; s.Node != "old" {
		t.Errorf("ann: %+v", s)
	}
	// A server that cannot write records nothing.
	lc := &LastSeen{Client: o.client, Node: "siem-c", Now: clk.Now, Writable: func() bool { return false }}
	o.fake.Requests()
	_ = lc.Record(ctx, "jlee", MethodSession)
	if n := len(o.fake.Requests()); n != 0 {
		t.Errorf("a read-only server wrote: %d", n)
	}
	// Housekeeping deletes the last sign-ins of users who are gone.
	if n, err := la.Housekeep(ctx, []string{"admin", "jlee"}); err != nil || n != 1 {
		t.Fatalf("housekeeping deleted %d: %v", n, err)
	}
	all, err = la.All(ctx)
	if _, ok := all["ann"]; err != nil || ok || all["jlee"].Node != "siem-b" {
		t.Errorf("after housekeeping: %v %v", all, err)
	}
}
