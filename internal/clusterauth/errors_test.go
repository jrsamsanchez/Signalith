// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

func cancelledCtx() context.Context {
	c, cancel := context.WithCancel(context.Background())
	cancel()
	return c
}

func TestParseCookieRefusesForms(t *testing.T) {
	_, a, _, _ := pair(t)
	keys, cid := a.rt.Hub().Keys(), a.docs.ClusterID()
	good := NewCookie(a.key(), cid)
	parts := strings.Split(good, ".")
	for name, v := range map[string]string{
		"too long":       strings.Repeat("x", 201),
		"three parts":    strings.Join(parts[:3], "."),
		"other version":  "v9." + strings.Join(parts[1:], "."),
		"unknown key":    parts[0] + ".nokey." + parts[2] + "." + parts[3],
		"short random":   parts[0] + "." + parts[1] + ".abc." + parts[3],
		"random not b64": parts[0] + "." + parts[1] + ".!!!." + parts[3],
		"tag not b64":    parts[0] + "." + parts[1] + "." + parts[2] + ".!!!",
	} {
		if err := ParseCookie(keys, cid, v); !errors.Is(err, ErrBadCookie) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := ParseCookie(keys, "", good); !errors.Is(err, ErrBadCookie) {
		t.Errorf("no cluster id: %v", err)
	}
	if err := ParseCookie(keys, cid, good); err != nil {
		t.Errorf("a good cookie: %v", err)
	}
}

func TestAPITokenShapes(t *testing.T) {
	tok, err := newAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	upper := tok[:len(tok)-1] + "A"
	if !IsAPIToken(tok) || IsAPIToken(upper) || IsAPIToken(tok[:len(tok)-1]+"1") {
		t.Fatalf("IsAPIToken: %q %q", tok, upper)
	}
	for id, ok := range map[string]bool{"0123456789ab": true, "0123456789AB": false, "0123456789a": false, "0123456789zz": false} {
		if validAPITokenID(id) != ok {
			t.Errorf("validAPITokenID(%q) != %v", id, ok)
		}
	}
	var nilDocs *Docs
	if nilDocs.TokensMadeBy("bob", time.Now()) != nil {
		t.Fatal("tokens of no settings")
	}
	attrs := TokensKeptAttrs("bob", []APITokenBody{{Name: "one"}, {Name: "two"}})
	want := []any{"user", "bob", "tokens", "one,two", "count", 2}
	if len(attrs) != len(want) {
		t.Fatalf("attrs %v", attrs)
	}
	for i := range want {
		if attrs[i] != want[i] {
			t.Fatalf("attrs %v, want %v", attrs, want)
		}
	}
}

// A session changed while it is signed again is read again; one that
// keeps changing is left for the next pass.
func TestResignSessionsConflicts(t *testing.T) {
	o, a, _, _ := pair(t)
	ctx := context.Background()
	old := a.key()
	k2, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	both := shared.NewKeySet(k2, old)
	a.addUser("una", users.Viewer)
	cookie := a.signIn("una", false)
	index := shared.SessionsIndex(testPrefix)
	id := SessionID(cookie)
	kidOf := func() string {
		raw, _ := json.Marshal(o.fake.Source(index, id))
		var sd sessionDoc
		if err := json.Unmarshal(raw, &sd); err != nil {
			t.Fatal(err)
		}
		return macKeyID(sd.MAC)
	}
	o.fake.FailN(100, "PUT", "_sessions/_doc/", 409, "version_conflict_engine_exception")
	if err := resignSessions(ctx, o.client, both); err != nil {
		t.Errorf("a session that kept changing: %v", err)
	}
	if kidOf() == k2.ID() {
		t.Fatal("signed again though every write conflicted")
	}
	o.fake.FailN(1, "PUT", "_sessions/_doc/", 409, "version_conflict_engine_exception")
	if err := resignSessions(ctx, o.client, both); err != nil {
		t.Fatal(err)
	}
	if kidOf() != k2.ID() {
		t.Error("not signed again after one conflict")
	}
}

// The resealer reports a directory password it cannot write again.
func TestResealerCannotWrite(t *testing.T) {
	o, a, _, _ := pair(t)
	s := users.Preset(users.TypeActiveDirectory)
	on := true
	s.Enabled, s.URL = &on, "ldaps://dc.example.com:636"
	s.BindDN, s.BindPassword = "CN=svc,DC=corp,DC=example,DC=com", "a-bind-password"
	s.UserBaseDN = "DC=corp,DC=example,DC=com"
	s.AdminGroups = []string{"CN=Admins,DC=corp,DC=example,DC=com"}
	s.Normalize()
	if err := (&DirectoryBackend{Docs: a.docs, Node: "siem-a"}).SaveFrom(context.Background(), "admin", s, FromPage); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Resealer(a.docs, o.client)(ctx); err == nil {
		t.Error("a directory password that could not be written again was no error")
	}
	if err := Resealer(a.docs, o.client)(context.Background()); err != nil {
		t.Errorf("reseal: %v", err)
	}
}

// The tenants' list is not used before it is read.
func TestTenantListBeforeRead(t *testing.T) {
	d := NewDocs()
	if _, err := d.TenantList().List(); err == nil {
		t.Error("a list of no document")
	}
	d.Track(shared.NewHub(shared.Options{NodeName: "siem-a"}))
	if _, err := d.TenantList().List(); !errors.Is(err, errNotRead) {
		t.Errorf("a list not read yet: %v", err)
	}
}

// A lock signed with a key this server does not have is not trusted, and
// a watch with no built-in admin to look at does nothing.
func TestUnknownLockKeyAndNoBuiltin(t *testing.T) {
	k, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	d := &lockDoc{Scope: "user", Key: "bob", Until: time.Now().UTC().Format(time.RFC3339Nano), MAC: "m1:no-such-key:AAAA"}
	if d.verify(shared.NewKeySet(k), "lock:user:bob") {
		t.Error("a lock of an unknown key verified")
	}
	w := &BuiltinWatch{Docs: NewDocs()}
	w.Check()
	if _, _, ok := w.Docs.BuiltinUser(); ok {
		t.Error("a built-in admin with no shared settings")
	}
	if _, err := (&UsersBackend{Docs: w.Docs}).ChangeBuiltinDisabled(context.Background(), "admin", true, nil); err == nil ||
		!strings.Contains(err.Error(), "not in the shared settings yet") {
		t.Errorf("turned off a built-in admin that is not there: %v", err)
	}
	// A cluster document not there, or not read yet.
	cdocs := NewDocs()
	cdocs.Cluster = func() *shared.Doc[shared.ClusterBody] { return nil }
	if _, _, ok := cdocs.BuiltinUser(); ok {
		t.Error("a built-in admin with no cluster document")
	}
	cd := shared.NewDoc[shared.ClusterBody](shared.NewHub(shared.Options{NodeName: "siem-a"}), shared.ClusterDocID, "cluster", 1)
	cdocs.Cluster = func() *shared.Doc[shared.ClusterBody] { return cd }
	if _, err := cdocs.RenameBuiltin(context.Background(), "admin", "root"); err == nil || !strings.Contains(err.Error(), "not in the shared settings yet") {
		t.Errorf("renamed a built-in admin not read yet: %v", err)
	}
}

// Directory settings: none to set a password of or say where they came
// from, and none saved without a cluster key.
func TestDirectoryBackendWithoutSettingsOrKey(t *testing.T) {
	_, a, _, _ := pair(t)
	ctx := context.Background()
	b := &DirectoryBackend{Docs: a.docs, Node: "siem-a"}
	if f := b.From(); f.Source != "" || !f.At.IsZero() {
		t.Errorf("From with no settings: %+v", f)
	}
	s := users.Preset(users.TypeActiveDirectory)
	s.URL = "ldaps://dc.example.com:636"
	if err := b.SetBindPassword(ctx, "admin", "pw", FromYAML, s); err == nil || !strings.Contains(err.Error(), "no directory sign-in settings") {
		t.Errorf("a password for no settings: %v", err)
	}
	a.docs.Hub().SetKeys(shared.NewKeySet(nil))
	s.BindPassword = "pw"
	if err := b.SaveFrom(ctx, "admin", s, FromPage); err == nil || !strings.Contains(err.Error(), "no cluster key") {
		t.Errorf("settings saved with no cluster key: %v", err)
	}
}

// A token that cannot be written is not made; a server without the
// tokens' document knows none.
func TestAPITokenCreateFailsAndLookupWithoutTokens(t *testing.T) {
	_, a, _, clk := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, secret, err := a.docs.CreateAPIToken(ctx, "admin", "ci", users.Viewer, 0, clk.Now()); err == nil || secret != "" {
		t.Fatalf("a token made without OpenSearch: %q %v", secret, err)
	}
	_, secret, err := a.docs.CreateAPIToken(context.Background(), "admin", "ci", users.Viewer, 0, clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.docs.LookupAPIToken(secret, clk.Now()); !ok {
		t.Fatal("the token made is unknown")
	}
	if got, ok := (&Docs{}).LookupAPIToken(secret, clk.Now()); ok || got.ID != "" {
		t.Errorf("a token known with no tokens' document: %+v", got)
	}
}

func TestAPITokensMadeByAndUse(t *testing.T) {
	_, a, _, clk := pair(t)
	ctx := context.Background()
	tok, _, err := a.docs.CreateAPIToken(ctx, "Bob", "Bob's", users.Viewer, 0, clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.docs.CreateAPIToken(ctx, "carol", "Carol's", users.Viewer, 0, clk.Now()); err != nil {
		t.Fatal(err)
	}
	if a.docs.TokensMadeBy("", clk.Now()) != nil {
		t.Fatal("tokens of no user")
	}
	got := a.docs.TokensMadeBy("bob", clk.Now())
	if len(got) != 1 || got[0].ID != tok.ID {
		t.Fatalf("TokensMadeBy = %+v", got)
	}
	// Used a moment ago: not due again.
	used := clk.Now().Add(-time.Minute)
	tok.LastUsed = &used
	if a.docs.APITokenUseDue(&tok, clk.Now()) {
		t.Fatal("a token used a minute ago is due")
	}
	// A write that fails is an error.
	if _, err := a.docs.NoteAPITokenUse(cancelledCtx(), tok.ID, clk.Now()); err == nil {
		t.Fatal("a failed write was no error")
	}
}

func TestAPITokensAtMost(t *testing.T) {
	_, a, _, clk := pair(t)
	ctx := context.Background()
	for i := range MaxAPITokens {
		if _, _, err := a.docs.CreateAPIToken(ctx, "admin", "t"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26)), users.Viewer, 0, clk.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := a.docs.CreateAPIToken(ctx, "admin", "one too many", users.Viewer, 0, clk.Now()); !errors.Is(err, ErrAPITokenMany) {
		t.Fatalf("token %d: %v", MaxAPITokens+1, err)
	}
}

func TestUsersBackendDeleteStaleOnThisServer(t *testing.T) {
	_, a, _, _ := pair(t)
	ctx := context.Background()
	r, err := a.ub.Create(ctx, "admin", newRecord("ned"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ub.Change(ctx, "admin", "ned", "", func(r *users.Record) error { r.Name = "Ned"; return nil }); err != nil {
		t.Fatal(err)
	}
	// The etag is older than this server's copy: read again, then refused
	// with who changed it.
	err = a.ub.Delete(ctx, "admin", "ned", r.ETag, nil)
	var stale *shared.StaleError
	if !errors.As(err, &stale) {
		t.Fatalf("a delete of an old version: %v", err)
	}
	if _, _, ok := a.docs.Users().Get("ned"); !ok {
		t.Fatal("deleted at an old version")
	}
	if err := a.ub.Delete(cancelledCtx(), "admin", "ned", r.ETag, nil); err == nil {
		t.Fatal("a delete that could not read the latest copy was no error")
	}
}

func TestLocksWriteRefusals(t *testing.T) {
	o, a, _, clk := pair(t)
	ctx := context.Background()
	until := clk.Now().Add(time.Hour)
	ro := &Locks{Docs: a.docs, Client: o.client, Node: "n_siem-a", Limiter: auth.NewLimiter(), Now: clk.Now, Writable: func() bool { return false }}
	if err := ro.Write(ctx, "user", "bob", until); err != nil {
		t.Fatalf("a read-only server: %v", err)
	}
	none := &Locks{Docs: NewDocs(), Client: o.client, Limiter: auth.NewLimiter()}
	if err := none.Write(ctx, "user", "bob", until); err == nil || !strings.Contains(err.Error(), "not a member") {
		t.Fatalf("a server that is not a member: %v", err)
	}
	if none.log() == nil {
		t.Fatal("no logger")
	}
	l := &Locks{Docs: a.docs, Client: o.client, Node: "n_siem-a", Limiter: auth.NewLimiter(), Now: clk.Now}
	if err := l.Write(cancelledCtx(), "user", "bob", until); err == nil {
		t.Fatal("a write that could not read the lock was no error")
	}
	if err := l.Write(ctx, "user", "bob", until); err != nil {
		t.Fatal(err)
	}
	// An earlier end does not replace a later one.
	if err := l.Write(ctx, "user", "bob", until.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	// A write that meets another is tried again; a refused one fails.
	o.fake.FailN(1, "PUT", "", 409, "version_conflict_engine_exception")
	if err := l.Write(ctx, "user", "bob", until.Add(time.Minute)); err != nil {
		t.Fatalf("after a conflict: %v", err)
	}
	o.fake.FailN(1, "PUT", "", 400, "mapper_parsing_exception")
	if err := l.Write(ctx, "user", "bob", until.Add(2*time.Minute)); err == nil {
		t.Fatal("a refused write was no error")
	}
	o.fake.SetFault(nil)
}

// Sessions made while OpenSearch could not be written are listed, ended
// one by one or all at once, like stored ones.
func TestDegradedSessionsListedAndEnded(t *testing.T) {
	o, a, _, _ := pair(t)
	ctx := context.Background()
	a.degraded.Store(true)
	first, err := a.sessions.Create(ctx, auth.NewSession{User: "admin", Epoch: 1, Method: users.SourceBuiltin})
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.sessions.Create(ctx, auth.NewSession{User: "admin", Epoch: 1, Method: users.SourceBuiltin})
	if err != nil {
		t.Fatal(err)
	}
	third, err := a.sessions.Create(ctx, auth.NewSession{User: "admin", Epoch: 1, Method: users.SourceBuiltin})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := a.sessions.List(ctx, "Admin", first)
	if len(list) != 3 {
		t.Fatalf("listed %+v", list)
	}
	current := 0
	for _, s := range list {
		if s.Current {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("%d current sessions in %+v", current, list)
	}
	if got := a.sessions.Users(ctx); len(got) != 1 || got[0] != "admin" {
		t.Fatalf("Users = %v", got)
	}
	secondID := auth.ListID(SessionID(second))
	if ended, err := a.sessions.End(ctx, "admin", secondID); !ended || err != nil {
		t.Fatalf("End = %v %v", ended, err)
	}
	if a.valid(second) || !a.valid(first) {
		t.Fatal("End ended the wrong session")
	}
	if n := a.sessions.EndUser(ctx, "admin", first); n != 1 || a.valid(third) || !a.valid(first) {
		t.Fatalf("EndUser ended %d; third valid %v, first valid %v", n, a.valid(third), a.valid(first))
	}

	// The stored sessions cannot be read: what is kept here is still said.
	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if strings.Contains(path, "_search") {
			return &ostest.Fault{Status: 400, Type: "illegal_argument_exception"}
		}
		return nil
	})
	if list, err := a.sessions.List(ctx, "admin", ""); err == nil || len(list) != 1 {
		t.Fatalf("List without OpenSearch: %+v %v", list, err)
	}
	if _, err := a.sessions.End(ctx, "admin", "nope"); err == nil {
		t.Fatal("End without OpenSearch was no error")
	}
	if n := a.sessions.EndUser(ctx, "admin", ""); n != 1 || a.valid(first) {
		t.Fatalf("EndUser without OpenSearch ended %d", n)
	}
}

// Sessions on a server that is not a member, or whose OpenSearch refuses
// the write, are not made.
func TestSessionsRefusedWrites(t *testing.T) {
	o, a, _, _ := pair(t)
	ctx := context.Background()
	none := &Sessions{Docs: NewDocs(), Client: o.client, Cache: NewSessionCache()}
	if _, err := none.Create(ctx, auth.NewSession{User: "admin", Epoch: 1, Method: users.SourceBuiltin}); err == nil {
		t.Fatal("a session made by a server that is not a member")
	}
	if carried, dropped := none.Carry(ctx, []Carried{{Role: users.Admin}}); carried != 0 || dropped != 1 {
		t.Fatalf("Carry by a server that is not a member: %d %d", carried, dropped)
	}
	if none.log() == nil || none.now().IsZero() {
		t.Fatal("no logger or clock")
	}
	// While degraded, housekeeping waits.
	a.degraded.Store(true)
	if n, err := a.sessions.Housekeep(ctx); n != 0 || err != nil {
		t.Fatalf("Housekeep while degraded: %d %v", n, err)
	}
	a.degraded.Store(false)
	// A write OpenSearch refuses for good is an error, not a degraded
	// session.
	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if strings.Contains(path, "_create") && strings.Contains(path, "sessions") {
			return &ostest.Fault{Status: 400, Type: "mapper_parsing_exception"}
		}
		return nil
	})
	if _, err := a.sessions.Create(ctx, auth.NewSession{User: "admin", Epoch: 1, Method: users.SourceBuiltin}); err == nil {
		t.Fatal("a session OpenSearch refused was made")
	}
}

func TestMergeChanged(t *testing.T) {
	mfa := &users.StoredMFA{Secret: "enc:new"}
	for _, tc := range []struct {
		name          string
		v, base, prev UserBody
		changed       bool
		check         func(v *UserBody) bool
	}{
		{"nothing", UserBody{}, UserBody{}, UserBody{}, false, nil},
		{"must change password", UserBody{}, UserBody{}, UserBody{MustChangePassword: true}, true,
			func(v *UserBody) bool { return v.MustChangePassword }},
		{"two-step sign-in", UserBody{SessionEpoch: 3}, UserBody{}, UserBody{MFA: mfa}, true,
			func(v *UserBody) bool { return v.MFA == mfa && v.SessionEpoch == 4 }},
		{"a newer version's field", UserBody{}, UserBody{Extra: shared.Extra{"x": json.RawMessage(`1`)}},
			UserBody{Extra: shared.Extra{"x": json.RawMessage(`2`)}}, true,
			func(v *UserBody) bool { return string(v.Extra["x"]) == "2" }},
		{"a field changed on both", UserBody{Extra: shared.Extra{"x": json.RawMessage(`2`)}}, UserBody{},
			UserBody{Extra: shared.Extra{"x": json.RawMessage(`2`)}}, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.v
			if got := mergeChanged(&v, &tc.base, &tc.prev); got != tc.changed {
				t.Fatalf("changed = %v", got)
			}
			if tc.check != nil && !tc.check(&v) {
				t.Fatalf("merged %+v", v)
			}
		})
	}
}

// A rename cut short and then asked for to another name finishes the
// first one, and a turning off of the old name since is carried over.
func TestRenameBuiltinResumedElsewhere(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	// Another admin, so the built-in one may stay off.
	a.addUser("kim", users.Admin)
	b.cycle()
	t.Cleanup(func() { renameStep = nil })
	crash := errors.New("crash")
	renameStep = func(n int) error {
		if n == 3 {
			return crash
		}
		return nil
	}
	if _, err := a.docs.RenameBuiltin(ctx, "test", "root"); !errors.Is(err, crash) {
		t.Fatalf("stop after the copy: %v", err)
	}
	renameStep = nil
	// The old name is turned off meanwhile.
	if _, err := a.docs.Users().Mutate(ctx, "test", "admin", func(v *UserBody) error { v.Disabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	prev, err := a.docs.RenameBuiltin(ctx, "test", "ops")
	if err != nil || prev != "root" {
		t.Fatalf("rename after one cut short: %q %v", prev, err)
	}
	b.cycle()
	v, _, ok := b.docs.BuiltinUser()
	if !ok || v.Username != "ops" || !v.Disabled {
		t.Fatalf("built-in admin %+v %v", v, ok)
	}
	for _, old := range []string{"admin", "root"} {
		if _, _, ok := b.docs.Users().Get(old); ok {
			t.Errorf("%s is still there", old)
		}
	}
	// Turning it off or on, or giving it a password, is refused for a
	// user that is not the built-in admin.
	if err := (&Docs{}).SetBuiltinHash(ctx, "test", "x"); err == nil {
		t.Error("a password for no built-in admin")
	}
}

// A tenant switch that meets another write tries again, gives up when
// the session keeps changing, and fails when OpenSearch refuses it.
func TestSetTenantWriteConflicts(t *testing.T) {
	o, a, _, _ := pair(t)
	ctx := context.Background()
	a.addUser("pat", users.Analyst)
	cookie := a.signIn("pat", false)
	o.fake.FailN(1, "PUT", "_sessions/_doc/", 409, "version_conflict_engine_exception")
	if err := a.sessions.SetTenant(ctx, cookie, "acme"); err != nil {
		t.Fatalf("one conflict: %v", err)
	}
	if got, ok := a.sessions.Lookup(ctx, cookie, false); !ok || got.Tenant != "acme" {
		t.Fatalf("after a conflict: %+v %v", got, ok)
	}
	o.fake.FailN(100, "PUT", "_sessions/_doc/", 409, "version_conflict_engine_exception")
	if err := a.sessions.SetTenant(ctx, cookie, ""); err == nil || !strings.Contains(err.Error(), "changed while switching") {
		t.Errorf("conflicts every time: %v", err)
	}
	o.fake.FailN(1, "PUT", "_sessions/_doc/", 400, "mapper_parsing_exception")
	if err := a.sessions.SetTenant(ctx, cookie, ""); err == nil || strings.Contains(err.Error(), "changed while switching") {
		t.Errorf("a refused write: %v", err)
	}
	o.fake.SetFault(nil)
}

// Sessions OpenSearch will not delete are not ended, and not counted.
func TestEndUserWhenDeletesFail(t *testing.T) {
	o, a, _, _ := pair(t)
	ctx := context.Background()
	a.addUser("pat", users.Analyst)
	cookie := a.signIn("pat", false)
	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if method == "DELETE" && strings.Contains(path, "_sessions/_doc/") {
			return &ostest.Fault{Status: 500, Type: "internal_error"}
		}
		return nil
	})
	if n := a.sessions.EndUser(ctx, "pat", ""); n != 0 {
		t.Errorf("ended %d sessions that could not be deleted", n)
	}
	o.fake.SetFault(nil)
	if !a.valid(cookie) {
		t.Error("a session that could not be deleted no longer works")
	}
}
