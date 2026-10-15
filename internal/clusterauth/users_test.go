package clusterauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// A users.Store over the shared backend: a user added on A is on B after
// one poll; a change made on B without a version is made on top of one
// made on A meanwhile; with the version read before, it is refused,
// naming who changed it where; the rules hold on the shared copy.
func TestStoreOverSharedUsers(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := users.WithActor(context.Background(), "alice")
	a.addUser("jlee", users.Viewer)
	b.cycle()
	u, ok := b.store.Get("jlee")
	if !ok || u.Role != users.Viewer || u.Source != users.SourceLocal || u.SessionEpoch != 1 {
		t.Fatalf("B's jlee: %+v %v", u, ok)
	}
	if !b.store.CheckPassword("jlee", "a-good-password") {
		t.Error("B does not take jlee's password")
	}
	etag := b.store.ETag("jlee")
	name := "J. Lee"
	if _, err := a.store.Update(ctx, "jlee", users.Change{Name: &name}); err != nil {
		t.Fatal(err)
	}
	role := users.Analyst
	if _, err := b.store.UpdateIf(ctx, "jlee", etag, users.Change{Role: &role}); err == nil {
		t.Fatal("a change based on an old version was made")
	} else {
		var se *shared.StaleError
		if !errors.As(err, &se) || se.By != "alice" || se.Node != "siem-a" {
			t.Fatalf("stale change: %v", err)
		}
	}
	if _, err := b.store.Update(ctx, "jlee", users.Change{Role: &role}); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	if u, _ := a.store.Get("jlee"); u.Name != name || u.Role != users.Analyst {
		t.Fatalf("both changes are not kept: %+v", u)
	}

	// The built-in admin's name is reserved, it counts as an enabled
	// admin, and the store does not list it.
	if _, err := b.store.Create(ctx, users.NewUser{Username: "ADMIN", Role: users.Viewer, Password: "a-good-password"}); !errors.Is(err, users.ErrReserved) {
		t.Errorf("creating the built-in admin's name: %v", err)
	}
	for _, u := range a.store.List() {
		if u.Username == "admin" {
			t.Error("the store lists the built-in admin")
		}
	}
	a.addUser("boss", users.Admin)
	off := true
	if _, err := a.store.Update(ctx, "boss", users.Change{Disabled: &off}); err != nil {
		t.Errorf("disabling an admin while the built-in admin is there: %v", err)
	}
	if _, err := a.store.Delete(ctx, "jlee"); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if _, ok := b.store.Get("jlee"); ok {
		t.Error("B still has a deleted user")
	}
	if _, err := b.store.Delete(ctx, "jlee"); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("deleting a deleted user: %v", err)
	}
}

// The built-in admin's password is one for every server: changing it
// moves its session epoch on, so its sessions end everywhere.
func TestBuiltinPassword(t *testing.T) {
	_, a, b, _ := pair(t)
	name, hash, ok := b.docs.Builtin()
	if !ok || name != "admin" || hash != builtinHash() {
		t.Fatalf("B's built-in admin: %q %v", name, ok)
	}
	cookie := b.signIn("admin", false)
	if !a.valid(cookie) {
		t.Fatal("the built-in admin's session does not work on A")
	}
	nh, _ := users.HashPassword("another-pass")
	if err := a.docs.SetBuiltinHash(context.Background(), "admin", nh); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if _, h, _ := b.docs.Builtin(); h != nh {
		t.Error("B does not have the new password")
	}
	if a.valid(cookie) || b.valid(cookie) {
		t.Error("the built-in admin's session outlived a new password")
	}
	if a.docs.BuiltinName() != "admin" {
		t.Error("BuiltinName")
	}
}

// V12, users: a user document granting admin written into OpenSearch
// with a wrong MAC is refused and audited; one with a valid MAC (a
// confused or compromised writer with the key) that claims to be a second
// built-in admin is refused by its checks.
func TestForgedUsersRefused(t *testing.T) {
	o, a, b, _ := pair(t)
	ctx := context.Background()
	a.addUser("jlee", users.Viewer)
	b.cycle()
	cfg := shared.ConfigIndex(testPrefix)
	src := o.fake.Source(cfg, "user:jlee")
	var body UserBody
	if err := json.Unmarshal([]byte(src["body"].(string)), &body); err != nil {
		t.Fatal(err)
	}
	body.Role = users.Admin
	raw, _ := json.Marshal(body)
	src["body"] = string(raw)
	o.fake.Put(cfg, "user:jlee", src)
	if _, err := a.rt.Hub().Bump(ctx, UsersWatch); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if u, _ := b.store.Get("jlee"); u.Role != users.Viewer {
		t.Fatalf("a forged role was taken: %+v", u)
	}
	if !strings.Contains(b.logs.String(), "config.tamper") || !strings.Contains(strings.Join(b.rt.Hub().Tamper(), ","), "user:jlee") {
		t.Error("the forged user was not reported")
	}

	// A second built-in admin, signed with the cluster key.
	k := a.key()
	evil, _ := json.Marshal(UserBody{Username: "eve", Role: users.Admin, Source: users.SourceBuiltin, PasswordHash: builtinHash(), SessionEpoch: 1,
		Created: time.Now().UTC(), Updated: time.Now().UTC()})
	env := shared.Envelope{Kind: UserKind, ID: "user:eve", Format: 1, Rev: 1000, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		UpdatedBy: shared.By{User: "x", Node: "siem-a"}, Body: string(evil)}
	if err := shared.Sign(k, env.ID, &env); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	raw, _ = json.Marshal(env)
	_ = json.Unmarshal(raw, &m)
	o.fake.Put(cfg, env.ID, m)
	if _, err := a.rt.Hub().Bump(ctx, UsersWatch); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if _, _, ok := b.docs.Users().Get("eve"); ok {
		t.Fatal("a second built-in admin was taken")
	}
	found := false
	for _, p := range b.rt.Hub().Problems() {
		found = found || p.ID == "user:eve" && p.Kind == shared.ProblemInvalid
	}
	if !found {
		t.Errorf("the second built-in admin is not reported: %+v", b.rt.Hub().Problems())
	}
	// Writing one is refused as well.
	if _, err := a.docs.Users().Create(ctx, "x", "mallory", &UserBody{Username: "mallory", Role: users.Admin, Source: users.SourceBuiltin}); err == nil {
		t.Error("made a second built-in admin")
	}
	if _, err := a.docs.Users().Create(ctx, "x", "mallory", &UserBody{Username: "other", Role: users.Admin, Source: users.SourceLocal}); err == nil {
		t.Error("made a user whose body names another")
	}
}

// V22: the first directory sign-in of one person on A and B at the same
// moment makes one user document, and both sign in.
func TestFirstDirectorySignInRace(t *testing.T) {
	o, a, b, _ := pair(t)
	du := users.DirectoryUser{Username: "dora", DN: "CN=Dora,DC=corp", Name: "Dora", Role: users.Analyst}
	var wg sync.WaitGroup
	results := make([]users.User, 2)
	errs := make([]error, 2)
	for i, s := range []*server{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = s.store.SeeDirectoryUser(context.Background(), du)
		}()
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil || results[i].Username != "dora" || results[i].Role != users.Analyst {
			t.Fatalf("server %d: %+v %v", i, results[i], errs[i])
		}
	}
	docs, err := o.cl.SearchDocs(context.Background(), shared.ConfigIndex(testPrefix), map[string]any{"term": map[string]any{"kind": UserKind}})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range docs {
		if d.ID == "user:dora" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d documents for dora", n)
	}
	// Signing in again changes nothing stored: sign-ins are kept apart.
	o.fake.Requests()
	if _, err := a.store.SeeDirectoryUser(context.Background(), du); err != nil {
		t.Fatal(err)
	}
	if puts := requestsTo(o.fake.Requests(), "user:dora"); len(puts) != 0 {
		t.Errorf("a second sign-in wrote the user: %v", puts)
	}
}

// While the built-in admin is renamed (signalith cluster apply), the user
// documents of both names may be the built-in admin; any other is still
// refused, and once the rename ends the old name no longer may be.
func TestBuiltinRenameAcceptsBothNames(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	if _, err := a.rt.Cluster().Mutate(ctx, "test", func(c *shared.ClusterBody) error {
		c.BuiltinPrev, c.Builtin = c.Builtin, "root"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	old, _, ok := a.docs.Users().Get("admin")
	if !ok {
		t.Fatal("no built-in admin")
	}
	builtin := func(name string) *UserBody {
		return &UserBody{Username: name, Role: users.Admin, Source: users.SourceBuiltin, PasswordHash: old.PasswordHash, SessionEpoch: 1,
			Created: time.Now().UTC(), Updated: time.Now().UTC()}
	}
	if _, err := a.docs.Users().Create(ctx, "test", "root", builtin("root")); err != nil {
		t.Fatalf("the new name was refused during the rename: %v", err)
	}
	if _, err := a.docs.Users().Mutate(ctx, "test", "admin", func(v *UserBody) error { v.SessionEpoch++; return nil }); err != nil {
		t.Fatalf("the old name was refused during the rename: %v", err)
	}
	b.cycle()
	for _, n := range []string{"admin", "root"} {
		if v, _, ok := b.docs.Users().Get(n); !ok || v.Source != users.SourceBuiltin {
			t.Errorf("%s during the rename: %+v %v", n, v, ok)
		}
	}
	if _, err := a.docs.Users().Create(ctx, "test", "mallory", builtin("mallory")); err == nil {
		t.Error("made a third built-in admin during the rename")
	}

	if _, err := a.rt.Cluster().Mutate(ctx, "test", func(c *shared.ClusterBody) error {
		c.BuiltinPrev = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.docs.Users().Mutate(ctx, "test", "admin", func(v *UserBody) error { v.SessionEpoch++; return nil }); err == nil {
		t.Error("the old name is still a built-in admin after the rename")
	}
	if a.docs.BuiltinName() != "root" {
		t.Errorf("built-in admin = %q", a.docs.BuiltinName())
	}
}
