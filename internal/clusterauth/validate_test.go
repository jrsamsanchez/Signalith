package clusterauth

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

func TestValidateAPIToken(t *testing.T) {
	d := NewDocs()
	now := time.Now().UTC()
	before := now.Add(-time.Hour)
	good := func() *APITokenBody {
		return &APITokenBody{ID: "0123456789ab", Name: "ci runner", Role: users.Viewer, Hash: strings.Repeat("a", 64), Created: now}
	}
	if err := d.validateAPIToken("0123456789ab", good()); err != nil {
		t.Fatalf("a good token: %v", err)
	}
	for _, c := range []struct {
		name   string
		id     string
		change func(*APITokenBody)
		want   string
	}{
		{"other id", "0123456789ac", func(*APITokenBody) {}, "it holds the token"},
		{"bad id", "XYZ", func(b *APITokenBody) { b.ID = "XYZ" }, "it holds the token"},
		{"admin role", "0123456789ab", func(b *APITokenBody) { b.Role = users.Admin }, "is not one an API token may have"},
		{"no hash", "0123456789ab", func(b *APITokenBody) { b.Hash = "abc" }, "no token fingerprint"},
		{"bad name", "0123456789ab", func(b *APITokenBody) { b.Name = " padded " }, "is not one a token may have"},
		{"expires early", "0123456789ab", func(b *APITokenBody) { b.Expires = &before }, "expires before it was made"},
	} {
		b := good()
		c.change(b)
		if err := d.validateAPIToken(c.id, b); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	later := now.Add(time.Hour)
	b := good()
	b.Expires = &later
	b.Role = users.Analyst
	if err := d.validateAPIToken(b.ID, b); err != nil {
		t.Errorf("an analyst token that expires: %v", err)
	}
	if d.APITokens() != nil {
		t.Error("tokens without the shared settings")
	}
}

func TestAPITokensOffAndRefusals(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	off := NewDocs()
	if _, _, err := off.CreateAPIToken(ctx, "admin", "x", users.Viewer, 0, now); !errors.Is(err, ErrAPITokensOff) {
		t.Errorf("create without the shared settings: %v", err)
	}
	if _, err := off.RevokeAPIToken(ctx, "admin", "0123456789ab", now); !errors.Is(err, ErrAPITokensOff) {
		t.Errorf("revoke without the shared settings: %v", err)
	}
	if _, err := off.NoteAPITokenUse(ctx, "0123456789ab", now); !errors.Is(err, ErrAPITokensOff) {
		t.Errorf("note without the shared settings: %v", err)
	}
	if _, ok := off.LookupAPIToken("not-a-token", now); ok {
		t.Error("a lookup of no token")
	}

	_, a, _, _ := pair(t)
	d := a.docs
	if _, _, err := d.CreateAPIToken(ctx, "admin", " bad", users.Viewer, 0, now); !errors.Is(err, ErrAPITokenName) {
		t.Errorf("a bad name: %v", err)
	}
	if _, _, err := d.CreateAPIToken(ctx, "admin", "ok", users.Admin, 0, now); !errors.Is(err, ErrAPITokenRole) {
		t.Errorf("an admin token: %v", err)
	}
	if _, err := d.RevokeAPIToken(ctx, "admin", "nope", now); !errors.Is(err, ErrAPITokenMissing) {
		t.Errorf("revoke of a bad id: %v", err)
	}
	if _, err := d.RevokeAPIToken(ctx, "admin", "0123456789ab", now); !errors.Is(err, ErrAPITokenMissing) {
		t.Errorf("revoke of a missing token: %v", err)
	}
	if _, err := d.NoteAPITokenUse(ctx, "nope", now); !errors.Is(err, ErrAPITokenMissing) {
		t.Errorf("note of a bad id: %v", err)
	}
	if _, err := d.NoteAPITokenUse(ctx, "0123456789ab", now); !errors.Is(err, ErrAPITokenMissing) {
		t.Errorf("note of a missing token: %v", err)
	}
	// A revoked token is not used.
	tok, _, err := d.CreateAPIToken(ctx, "admin", "short", users.Viewer, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RevokeAPIToken(ctx, "admin", tok.ID, now); err != nil {
		t.Fatal(err)
	}
	if wrote, err := d.NoteAPITokenUse(ctx, tok.ID, now.Add(time.Hour)); wrote || err != nil {
		t.Errorf("note of a revoked token: %v %v", wrote, err)
	}
}

func TestValidateUser(t *testing.T) {
	_, a, _, _ := pair(t)
	d := a.docs
	ok := func(name string, b *UserBody) {
		t.Helper()
		if err := d.validateUser(name, b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := func(name string, b *UserBody, want string) {
		t.Helper()
		if err := d.validateUser(name, b); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s %+v: %v, want %q", name, b, err, want)
		}
	}
	ok("bob", &UserBody{Username: "bob", Role: users.Analyst, Source: users.SourceLocal})
	ok("dir", &UserBody{Username: "dir", Role: users.Viewer, Source: users.SourceDirectory})
	ok("sso", &UserBody{Username: "sso", Role: users.Viewer, Source: users.SourceSSO})
	ok("t1", &UserBody{Username: "t1", Role: users.Viewer, Source: users.SourceLocal, Tenant: "acme"})
	ok("admin", &UserBody{Username: "admin", Role: users.Admin, Source: users.SourceBuiltin})
	bad("bob", &UserBody{Username: "eve", Role: users.Analyst, Source: users.SourceLocal}, "it holds the user")
	bad("bob", &UserBody{Username: "bob", Role: "root", Source: users.SourceLocal}, "its role")
	bad("bob", &UserBody{Username: "bob", Role: users.Viewer, Source: "magic"}, "its source")
	bad("t2", &UserBody{Username: "t2", Role: users.Viewer, Source: users.SourceDirectory, Tenant: "acme"}, "its tenant")
	bad("t3", &UserBody{Username: "t3", Role: users.Viewer, Source: users.SourceLocal, Tenant: "Not A Tenant"}, "its tenant")
	bad("root", &UserBody{Username: "root", Role: users.Admin, Source: users.SourceBuiltin}, "the cluster document does not name")
	bad("admin", &UserBody{Username: "admin", Role: users.Viewer, Source: users.SourceBuiltin}, "must be an enabled admin")
	bad("admin", &UserBody{Username: "admin", Role: users.Admin, Source: users.SourceBuiltin, Disabled: true}, "must be an enabled admin")
}

// A sign-out made while OpenSearch cannot be written ends the session at
// once here, and deletes its document once OpenSearch takes writes.
func TestSignOutWhileDegraded(t *testing.T) {
	o, a, _, _ := pair(t)
	ctx := context.Background()
	a.addUser("kim", users.Viewer)
	cookie := a.signIn("kim", false)
	a.degraded.Store(true)
	a.sessions.Delete(ctx, cookie)
	if a.valid(cookie) {
		t.Fatal("the session works after sign-out")
	}
	if n := o.sessionDocs(t, "kim"); n != 1 {
		t.Fatalf("%d session documents while degraded, want 1 kept for later", n)
	}
	// Signing out twice keeps one pending delete.
	a.sessions.Delete(ctx, cookie)
	if n := len(a.sessions.Cache.pending); n != 1 {
		t.Errorf("%d pending deletes", n)
	}
	// Degraded still: Recover waits.
	a.sessions.Recover(ctx)
	if n := o.sessionDocs(t, "kim"); n != 1 {
		t.Fatalf("Recover deleted while degraded")
	}
	a.degraded.Store(false)
	a.sessions.Recover(ctx)
	if n := o.sessionDocs(t, "kim"); n != 0 {
		t.Errorf("%d session documents after recovery", n)
	}
	if n := len(a.sessions.Cache.pending); n != 0 {
		t.Errorf("%d pending deletes after recovery", n)
	}
}

// A sign-out whose delete fails is kept and written later too.
func TestSignOutDeleteFails(t *testing.T) {
	o, a, _, _ := pair(t)
	ctx := context.Background()
	a.addUser("lee", users.Viewer)
	cookie := a.signIn("lee", false)
	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if method == "DELETE" && strings.Contains(path, "_sessions") {
			return &ostest.Fault{Status: 503, Type: "unavailable_shards_exception"}
		}
		return nil
	})
	a.sessions.Delete(ctx, cookie)
	if a.valid(cookie) {
		t.Fatal("the session works after sign-out")
	}
	if n := len(a.sessions.Cache.pending); n != 1 {
		t.Fatalf("%d pending deletes", n)
	}
	o.fake.SetFault(nil)
	a.sessions.Recover(ctx)
	if n := o.sessionDocs(t, "lee"); n != 0 {
		t.Errorf("%d session documents after recovery", n)
	}
	// An unknown cookie is nothing to sign out.
	a.sessions.Delete(ctx, "not-a-cookie")
}

// A tenant switch is refused for a session that ended, while degraded,
// for a forged session, and when OpenSearch fails.
func TestSetTenantRefusals(t *testing.T) {
	o, a, _, _ := pair(t)
	ctx := context.Background()
	a.addUser("pat", users.Analyst)
	cookie := a.signIn("pat", false)
	if err := a.sessions.SetTenant(ctx, "not-a-cookie", "acme"); !errors.Is(err, errSessionEnded) {
		t.Errorf("an unknown cookie: %v", err)
	}
	a.degraded.Store(true)
	if err := a.sessions.SetTenant(ctx, cookie, "acme"); err == nil || !strings.Contains(err.Error(), "cannot use OpenSearch") {
		t.Errorf("degraded: %v", err)
	}
	a.degraded.Store(false)

	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if method == "GET" && strings.Contains(path, "_sessions/_doc/") {
			return &ostest.Fault{Status: 500, Type: "internal_error"}
		}
		return nil
	})
	if err := a.sessions.SetTenant(ctx, cookie, "acme"); err == nil {
		t.Error("switched though the session could not be read")
	}
	o.fake.SetFault(nil)

	// A forged session (its MAC broken) is not switched.
	index := shared.SessionsIndex(testPrefix)
	id := SessionID(cookie)
	forged := maps.Clone(o.fake.Source(index, id))
	forged["user"] = "admin"
	o.fake.Put(index, id, forged)
	if err := a.sessions.SetTenant(ctx, cookie, "acme"); !errors.Is(err, errSessionEnded) {
		t.Errorf("a forged session: %v", err)
	}
	// Gone from OpenSearch: ended.
	o.fake.Delete(index, id)
	if err := a.sessions.SetTenant(ctx, cookie, "acme"); !errors.Is(err, errSessionEnded) {
		t.Errorf("a deleted session: %v", err)
	}
}
