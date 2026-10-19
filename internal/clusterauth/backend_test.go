package clusterauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

func newRecord(name string) users.Record {
	now := time.Now().UTC()
	return users.Record{User: users.User{Username: name, Role: users.Viewer, Source: users.SourceLocal, Created: now, Updated: now},
		Hash: "test-hash-placeholder"}
}

func TestUsersBackendCreate(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	r, err := a.ub.Create(ctx, "admin", newRecord("mia"))
	if err != nil || r.Username != "mia" || r.ETag == "" || r.Hash == "" {
		t.Fatalf("Create = %+v, %v", r, err)
	}
	if _, err := a.ub.Create(ctx, "admin", newRecord("mia")); !errors.Is(err, users.ErrExists) {
		t.Errorf("a second Create: %v", err)
	}
	// The other server's create of the same name, before it read the
	// first, loses too.
	if _, err := b.ub.Create(ctx, "admin", newRecord("mia")); !errors.Is(err, users.ErrExists) {
		t.Errorf("Create on the other server: %v", err)
	}
	bi := newRecord("root")
	bi.Source = users.SourceBuiltin
	if _, err := a.ub.Create(ctx, "admin", bi); !errors.Is(err, users.ErrReserved) {
		t.Errorf("a built-in admin created: %v", err)
	}
}

func TestUsersBackendDelete(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	if err := a.ub.Delete(ctx, "admin", "nobody", "", nil); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("delete of nobody: %v", err)
	}
	if err := a.ub.Delete(ctx, "admin", "admin", "", nil); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("delete of the built-in admin: %v", err)
	}
	r, err := a.ub.Create(ctx, "admin", newRecord("ned"))
	if err != nil {
		t.Fatal(err)
	}
	// check refuses: nothing is deleted.
	refused := errors.New("the last admin")
	if err := a.ub.Delete(ctx, "admin", "ned", "", func(users.Record) error { return refused }); !errors.Is(err, refused) {
		t.Errorf("a refused delete: %v", err)
	}
	if _, _, ok := a.docs.Users().Get("ned"); !ok {
		t.Fatal("deleted though check refused")
	}

	// Changed on the other server since the etag was read: refused with
	// who changed it.
	b.cycle()
	if _, err := b.ub.Change(ctx, "bob", "ned", "", func(r *users.Record) error { r.Name = "Ned"; return nil }); err != nil {
		t.Fatal(err)
	}
	err = a.ub.Delete(ctx, "admin", "ned", r.ETag, nil)
	var stale *shared.StaleError
	if !errors.As(err, &stale) {
		t.Fatalf("a delete of an old version: %v", err)
	}
	// With the etag as it is now, it goes.
	_, cur, _ := a.docs.Users().Get("ned")
	var checked users.Record
	if err := a.ub.Delete(ctx, "admin", "ned", cur, func(r users.Record) error { checked = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if checked.Name != "Ned" {
		t.Errorf("checked %+v, want the latest copy", checked)
	}
	if _, _, ok := a.docs.Users().Get("ned"); ok {
		t.Error("not deleted")
	}
	b.cycle()
	if _, _, ok := b.docs.Users().Get("ned"); ok {
		t.Error("the other server still has the user")
	}
	// Deleted already, by an old etag: not found.
	if err := b.ub.Delete(ctx, "admin", "ned", cur, nil); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("delete of a deleted user: %v", err)
	}
}

func TestBuiltinWithoutSharedSettings(t *testing.T) {
	ctx := context.Background()
	d := NewDocs()
	if d.BuiltinName() != "" {
		t.Error("a name without the shared settings")
	}
	if _, _, ok := d.BuiltinUser(); ok {
		t.Error("a user without the shared settings")
	}
	if _, _, ok := d.Builtin(); ok {
		t.Error("a built-in admin without the shared settings")
	}
	if err := d.SetBuiltinHash(ctx, "x", "h"); err == nil {
		t.Error("a hash set without the shared settings")
	}
	if _, err := d.CreateBuiltin(ctx, "x", "root", "h", time.Now()); err == nil {
		t.Error("created without the cluster document")
	}
	if _, err := d.RenameBuiltin(ctx, "x", "root"); err == nil {
		t.Error("renamed without the cluster document")
	}
}

func TestBuiltinPasswordAndCreateAgain(t *testing.T) {
	_, a, b, clk := pair(t)
	ctx := context.Background()
	if _, err := a.docs.RenameBuiltin(ctx, "x", "  "); err == nil {
		t.Error("renamed to no name")
	}
	cookie := a.signIn("admin", false)
	v, _, _ := a.docs.BuiltinUser()
	epoch := v.SessionEpoch
	if err := a.docs.SetBuiltinHash(ctx, "admin", "new-test-hash"); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if name, hash, ok := b.docs.Builtin(); !ok || name != "admin" || hash != "new-test-hash" {
		t.Errorf("B's built-in admin: %q %q %v", name, hash, ok)
	}
	if v, _, _ := b.docs.BuiltinUser(); v.SessionEpoch != epoch+1 {
		t.Errorf("epoch %d, want %d", v.SessionEpoch, epoch+1)
	}
	a.sessions.Cache = NewSessionCache()
	if a.valid(cookie) {
		t.Error("the admin's session outlived the new password")
	}
	// Made again (an import cut short): the name recorded stays, and the
	// password is not replaced.
	name, err := a.docs.CreateBuiltin(ctx, "x", "other", "older-hash", clk.Now())
	if err != nil || name != "admin" {
		t.Errorf("CreateBuiltin again = %q, %v", name, err)
	}
	if _, hash, _ := a.docs.Builtin(); hash != "new-test-hash" {
		t.Errorf("hash = %q", hash)
	}
}

func TestUsersBackendChangeNothing(t *testing.T) {
	_, a, _, _ := pair(t)
	ctx := context.Background()
	if _, err := a.ub.Create(ctx, "admin", newRecord("ola")); err != nil {
		t.Fatal(err)
	}
	r, err := a.ub.Change(ctx, "admin", "ola", "", func(*users.Record) error { return users.ErrNoChange })
	if err != nil || r.Username != "ola" || r.ETag == "" {
		t.Errorf("no change: %+v, %v", r, err)
	}
	// Same values: no write either.
	_, before, _ := a.docs.Users().Get("ola")
	r, err = a.ub.Change(ctx, "admin", "ola", "", func(*users.Record) error { return nil })
	if err != nil || r.ETag != before {
		t.Errorf("same values: %+v, %v (etag %s)", r, err, before)
	}
	if _, err := a.ub.Change(ctx, "admin", "nobody", "", func(*users.Record) error { return nil }); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("change of nobody: %v", err)
	}
	if _, err := a.ub.Change(ctx, "admin", "admin", "", func(*users.Record) error { return nil }); !errors.Is(err, users.ErrNotFound) {
		t.Errorf("change of the built-in admin: %v", err)
	}
}
