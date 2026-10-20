// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterauth

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tenants"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// sessionKeyIDs returns the key id of each session document's MAC.
func sessionKeyIDs(t *testing.T, o *testOS) map[string]string {
	t.Helper()
	docs, err := o.cl.SearchDocs(context.Background(), shared.SessionsIndex(testPrefix), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, d := range docs {
		var sd sessionDoc
		if err := json.Unmarshal(d.Source, &sd); err != nil {
			t.Fatal(err)
		}
		out[d.ID] = macKeyID(sd.MAC)
	}
	return out
}

// A key rotation signs every session again and seals the authenticator
// keys again, so once the old key is retired everyone stays signed in
// and two-step sign-in still opens.
func TestResealerAfterKeyRotation(t *testing.T) {
	o, a, _, _ := pair(t)
	ctx := context.Background()
	old := a.key()
	a.addUser("bob", users.Analyst)
	bob := a.signIn("bob", false)
	admin := a.signIn("admin", true)
	dirB := &DirectoryBackend{Docs: a.docs, Node: "siem-a"}
	ds := users.Preset(users.TypeActiveDirectory)
	on := true
	ds.Enabled, ds.URL, ds.BindDN, ds.BindPassword = &on, "ldaps://dc1.corp.example.com", "CN=svc,DC=corp,DC=example,DC=com", "svc-pass"
	ds.UserBaseDN = "DC=corp,DC=example,DC=com"
	ds.Normalize()
	if err := dirB.SaveFrom(ctx, "admin", ds, FromYAML); err != nil {
		t.Fatal(err)
	}

	if a.ub.BuiltinMFA() != nil {
		t.Fatal("the built-in admin has two-step sign-in before it was set up")
	}
	secret := users.NewMFASecret()
	if err := a.ub.ChangeBuiltinMFA(ctx, "admin", func(cur *users.MFA) (*users.MFA, bool, error) {
		return &users.MFA{Secret: secret, Since: time.Now().UTC()}, true, nil
	}); err != nil {
		t.Fatal(err)
	}
	// No change is no write.
	if err := a.ub.ChangeBuiltinMFA(ctx, "admin", func(*users.MFA) (*users.MFA, bool, error) { return nil, false, users.ErrNoChange }); err != nil {
		t.Errorf("no change: %v", err)
	}
	wantErr := errors.New("refused")
	if err := a.ub.ChangeBuiltinMFA(ctx, "admin", func(*users.MFA) (*users.MFA, bool, error) { return nil, false, wantErr }); !errors.Is(err, wantErr) {
		t.Errorf("a refused change: %v", err)
	}
	// The change ended the admin's sessions (endSessions true): sign in again.
	if a.valid(admin) {
		t.Error("the admin's session outlived the change to two-step sign-in")
	}
	admin = a.signIn("admin", true)
	if m := a.ub.BuiltinMFA(); m == nil || m.Secret != secret || m.Problem != "" {
		t.Fatalf("BuiltinMFA = %+v", m)
	}

	for id, kid := range sessionKeyIDs(t, o) {
		if kid != old.ID() {
			t.Fatalf("session %s signed with %q before the rotation", id, kid)
		}
	}

	// The rotation's switch: the new key signs, the old one still opens.
	k2, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	h := a.rt.Hub()
	h.SetKeys(shared.NewKeySet(k2, old))
	if err := Resealer(a.docs, o.client)(ctx); err != nil {
		t.Fatal(err)
	}
	ids := sessionKeyIDs(t, o)
	if len(ids) != 3 { // bob, and the admin before and after the change
		t.Fatalf("%d sessions", len(ids))
	}
	for id, kid := range ids {
		if kid != k2.ID() {
			t.Errorf("session %s still signed with %q", id, kid)
		}
	}
	v, _, _ := a.docs.BuiltinUser()
	if secrets.KeyID(v.MFA.Secret) != k2.ID() {
		t.Errorf("the authenticator key is sealed with %q", secrets.KeyID(v.MFA.Secret))
	}

	// The new key alone opens and verifies everything (the rotation
	// signs the shared documents again itself before it retires the old
	// key).
	newOnly := shared.NewKeySet(k2)
	docs, err := o.cl.SearchDocs(ctx, shared.SessionsIndex(testPrefix), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		var sd sessionDoc
		if json.Unmarshal(d.Source, &sd) != nil || !sd.verify(newOnly, d.ID) {
			t.Errorf("session %s does not verify with the new key alone", d.ID)
		}
	}
	if got, err := (mfaKeys{newOnly}).Open(users.BuiltinMFAField, v.MFA.Secret); err != nil || got != secret {
		t.Errorf("the new key opens the authenticator key as %q, %v", got, err)
	}
	dir, _ := a.docs.Directory().Get()
	if secrets.KeyID(dir.BindPassword) != k2.ID() {
		t.Errorf("the directory password is sealed with %q", secrets.KeyID(dir.BindPassword))
	}
	if got, _, problem := dirB.Load(); got.BindPassword != "svc-pass" || problem != "" {
		t.Errorf("the directory password after the reseal: %q, %q", got.BindPassword, problem)
	}
	a.sessions.Cache = NewSessionCache()
	if !a.valid(bob) || !a.valid(admin) {
		t.Error("a session ended with the rotation")
	}
	if m := a.ub.BuiltinMFA(); m == nil || m.Secret != secret {
		t.Errorf("BuiltinMFA after the rotation = %+v", m)
	}
	// Run again: nothing is left to do, nothing is written.
	_ = o.fake.Requests()
	if err := Resealer(a.docs, o.client)(ctx); err != nil {
		t.Fatal(err)
	}
	// (The directory document is written again as it is; the sessions
	// and the users are left alone.)
	for _, r := range o.fake.Requests() {
		write := r[:3] == "PUT" || r[:4] == "POST" && !contains(r, "_search") && !contains(r, "_mget")
		if write && (contains(r, "_sessions") || contains(r, "user:")) {
			t.Errorf("a second reseal wrote: %s", r)
		}
	}
}

func contains(s, part string) bool { return len(requestsTo([]string{s}, part)) > 0 }

func TestResealerWithoutParts(t *testing.T) {
	ctx := context.Background()
	if err := Resealer(NewDocs(), nil)(ctx); err != nil {
		t.Errorf("without a hub: %v", err)
	}
	k, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := resignSessions(ctx, nil, shared.NewKeySet(k)); err != nil {
		t.Errorf("without a client: %v", err)
	}
	if err := resignSessions(ctx, func() (*store.Client, string) { return nil, "" }, shared.NewKeySet(k)); err != nil {
		t.Errorf("with no client now: %v", err)
	}
	for mac, want := range map[string]string{"m1:abc:sum": "abc", "m1:abc": "", "m2:abc:x": "", "": ""} {
		if got := macKeyID(mac); got != want {
			t.Errorf("macKeyID(%q) = %q, want %q", mac, got, want)
		}
	}
}

func TestChangeBuiltinMFAWithoutBuiltin(t *testing.T) {
	ub := &UsersBackend{Docs: NewDocs()}
	if ub.BuiltinMFA() != nil {
		t.Error("an MFA without a built-in admin")
	}
	err := ub.ChangeBuiltinMFA(context.Background(), "x", func(*users.MFA) (*users.MFA, bool, error) { return nil, false, nil })
	if err == nil {
		t.Error("changed the MFA of a built-in admin that is not there")
	}
}

func TestMFAKeysWithoutClusterKey(t *testing.T) {
	var k mfaKeys
	if _, err := k.Seal("f", "plain"); err == nil {
		t.Error("sealed without a cluster key")
	}
	if k.Current("enc:v1:x") {
		t.Error("a value is current without a cluster key")
	}
	ck, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	k = mfaKeys{shared.NewKeySet(ck)}
	sealed, err := k.Seal("f", "plain")
	if err != nil || !k.Current(sealed) {
		t.Fatalf("Seal = %q, %v", sealed, err)
	}
	if got, err := k.Open("f", sealed); err != nil || got != "plain" {
		t.Errorf("Open = %q, %v", got, err)
	}
	if _, err := k.Open("other-field", sealed); err == nil {
		t.Error("opened under another field")
	}
}

// EndSessions moves a user's session epoch on: their sessions end on
// every server, and EndUser counts the ones in OpenSearch.
func TestEndSessions(t *testing.T) {
	o, a, b, _ := pair(t)
	ctx := context.Background()
	a.addUser("carol", users.Analyst)
	b.cycle()
	c1 := a.signIn("carol", false)
	c2 := b.signIn("carol", true)
	if n := a.sessions.EndUser(ctx, "Carol", c1); n != 1 {
		t.Errorf("EndUser counts %d other sessions, want 1", n)
	}
	if n := a.sessions.EndUser(ctx, "carol", ""); n != 2 {
		t.Errorf("EndUser counts %d sessions, want 2", n)
	}
	if err := a.ub.EndSessions(ctx, "admin", "carol"); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	a.sessions.Cache, b.sessions.Cache = NewSessionCache(), NewSessionCache()
	if a.valid(c1) || b.valid(c2) {
		t.Error("a session outlived EndSessions")
	}
	if o.sessionDocs(t, "carol") != 2 {
		t.Error("EndSessions deleted the documents rather than ending them by epoch")
	}
	if err := a.ub.EndSessions(ctx, "admin", "nobody"); err == nil {
		t.Error("ended the sessions of a user that does not exist")
	}
}

func TestSessionsSmallParts(t *testing.T) {
	_, a, _, _ := pair(t)
	s := a.sessions
	if s.Idle() != 12*time.Hour {
		t.Errorf("Idle = %v", s.Idle())
	}
	s.SetIdle(0)
	if s.Idle() != DefaultIdle {
		t.Errorf("default Idle = %v", s.Idle())
	}
	s.SetVersion(context.Background(), "x", "y") // nothing to do

	for _, c := range []struct {
		err  error
		want bool
	}{
		{errors.New("connection refused"), true},
		{&store.Error{Status: 503}, true},
		{&store.Error{Status: 400}, false},
		{&store.Error{Status: 409}, false},
	} {
		if got := unusable(c.err); got != c.want {
			t.Errorf("unusable(%v) = %v", c.err, got)
		}
	}

	if MethodOf(context.Background()) != MethodSession {
		t.Error("MethodOf without a method")
	}
	if MethodOf(WithMethod(context.Background(), MethodBasic)) != MethodBasic {
		t.Error("MethodOf lost the method")
	}

	a.docs.Reset()
	if a.docs.sessions != nil || len(a.docs.subs) != 0 {
		t.Error("Reset kept subscribers")
	}
}

func TestTenantsKept(t *testing.T) {
	ctx := context.Background()
	off := NewDocs()
	if _, ok := off.TenantsKept(); ok {
		t.Error("a list without a hub")
	}
	l := off.TenantList()
	if l.On() {
		t.Error("tenants on without the shared settings")
	}
	if _, err := l.List(); err == nil {
		t.Error("a list before the shared settings were read")
	}
	if err := l.Mutate(ctx, "x", func(ts []tenants.Tenant) ([]tenants.Tenant, error) { return ts, nil }); !errors.Is(err, tenants.ErrNotShared) {
		t.Errorf("Mutate without the shared settings: %v", err)
	}
	if err := off.ImportTenants(ctx, "x", nil); err == nil {
		t.Error("imported without the shared settings")
	}
	_, a, _, _ := pair(t)
	if _, ok := a.docs.TenantsKept(); ok {
		t.Error("a list before one was written")
	}
}

// The hook records each sign-in in the background with the method its
// context names.
func TestLastSeenHook(t *testing.T) {
	o := newOS(t)
	clk := newClock()
	ls := &LastSeen{Client: o.client, Node: "siem-a", Now: clk.Now}
	hook := ls.Hook(nil)
	hook(WithMethod(context.Background(), MethodBasic), "Dave", false)
	deadline := time.Now().Add(10 * time.Second)
	for {
		all, err := ls.All(context.Background())
		if err == nil {
			if s, ok := all["dave"]; ok {
				if s.Method != MethodBasic || s.Node != "siem-a" {
					t.Errorf("seen = %+v", s)
				}
				// Read again at once: from memory, even when OpenSearch fails.
				o.fake.SetFault(func(string, string) *ostest.Fault { return &ostest.Fault{Status: 500, Type: "x"} })
				if again, err := ls.All(context.Background()); err != nil || again["dave"] != s {
					t.Errorf("cached All = %v, %v", again, err)
				}
				ls.mu.Lock()
				ls.allAt = time.Time{}
				ls.mu.Unlock()
				if _, err := ls.All(context.Background()); err == nil {
					t.Error("a failed read ignored")
				}
				o.fake.SetFault(nil)
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sign-in was not recorded: %v %v", all, err)
		}
		ls.mu.Lock()
		ls.allAt = time.Time{} // read again
		ls.mu.Unlock()
		runtimeYield()
	}
}

// resignSessions leaves sessions it cannot verify alone, and reports
// OpenSearch's errors.
func TestResignSessionsFaults(t *testing.T) {
	o, a, _, _ := pair(t)
	ctx := context.Background()
	old := a.key()
	k2, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	both := shared.NewKeySet(k2, old)
	// No sessions index yet: nothing to do.
	if err := resignSessions(ctx, o.client, both); err != nil {
		t.Errorf("no sessions: %v", err)
	}
	a.addUser("una", users.Viewer)
	cookie := a.signIn("una", false)
	index := shared.SessionsIndex(testPrefix)
	id := SessionID(cookie)

	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if strings.Contains(path, "_sessions/_search") {
			return &ostest.Fault{Status: 500, Type: "internal_error"}
		}
		return nil
	})
	if err := resignSessions(ctx, o.client, both); err == nil {
		t.Error("a failed search ignored")
	}
	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if method == "PUT" && strings.Contains(path, "_sessions/_doc/") {
			return &ostest.Fault{Status: 500, Type: "internal_error"}
		}
		return nil
	})
	if err := resignSessions(ctx, o.client, both); err == nil {
		t.Error("a failed write ignored")
	}
	o.fake.SetFault(nil)

	// A session with a MAC no key verifies is not signed again.
	forged := maps.Clone(o.fake.Source(index, id))
	forged["epoch"] = 99
	o.fake.Put(index, id, forged)
	if err := resignSessions(ctx, o.client, both); err != nil {
		t.Fatal(err)
	}
	var sd sessionDoc
	raw, _ := json.Marshal(o.fake.Source(index, id))
	_ = json.Unmarshal(raw, &sd)
	if macKeyID(sd.MAC) != old.ID() {
		t.Errorf("a forged session was signed again with %q", macKeyID(sd.MAC))
	}
}

// Run reads the locks at once, and stops when its context ends.
func TestLocksRunStops(t *testing.T) {
	o := newOS(t)
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	l := &Locks{Docs: NewDocs(), Limiter: auth.NewLimiter(), Client: func() (*store.Client, string) {
		calls++
		cancel()
		return o.cl, testPrefix
	}}
	done := make(chan struct{})
	go func() { l.Run(ctx); close(done) }()
	<-done
	if calls != 1 {
		t.Errorf("the locks were read %d times", calls)
	}
	if l.log() == nil {
		t.Error("no logger")
	}

	// A server that may not write now writes nothing.
	calls = 0
	no := func() bool { return false }
	l.Writable = no
	if n, err := l.Housekeep(context.Background()); n != 0 || err != nil || calls != 0 {
		t.Errorf("Housekeep while not writable: %d %v (%d calls)", n, err, calls)
	}
	ls := &LastSeen{Client: l.Client, Writable: no}
	if err := ls.Record(context.Background(), "x", MethodSession); err != nil || calls != 0 {
		t.Errorf("Record while not writable: %v (%d calls)", err, calls)
	}
	if n, err := ls.Housekeep(context.Background(), nil); n != 0 || err != nil || calls != 0 {
		t.Errorf("LastSeen.Housekeep while not writable: %d %v (%d calls)", n, err, calls)
	}
	if time.Since(ls.now()) > time.Minute || time.Since(l.now()) > time.Minute {
		t.Error("the default clocks")
	}
}

// runtimeYield lets the hook's goroutine run between polls.
func runtimeYield() { <-time.After(5 * time.Millisecond) }
