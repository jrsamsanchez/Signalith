package clusterauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// W23: signalith cluster apply renames the built-in admin. A crash after
// any step leaves a rename the same call finishes; the old name's
// sessions end on every server, its password carries over, and a user
// who has the new name already refuses it.
func TestRenameBuiltin(t *testing.T) {
	_, a, b, _ := pair(t)
	ctx := context.Background()
	old := a.signIn("admin", false)
	if !b.valid(old) {
		t.Fatal("the built-in admin's session does not work on B")
	}
	a.addUser("ops", users.Analyst)
	b.cycle()
	if _, err := b.docs.RenameBuiltin(ctx, "test", "ops"); err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Fatalf("a rename to a user's name: %v", err)
	}

	crash := errors.New("crash")
	for stop := 1; stop <= 4; stop++ {
		renameStep = func(n int) error {
			if n == stop {
				return crash
			}
			return nil
		}
		if _, err := a.docs.RenameBuiltin(ctx, "test", "root"); !errors.Is(err, crash) {
			t.Fatalf("stop after step %d: %v", stop, err)
		}
		b.cycle()
		// The built-in admin signs in throughout, under one of its names.
		name, hash, ok := b.docs.Builtin()
		if !ok || hash != builtinHash() || name != "admin" && name != "root" {
			t.Fatalf("after step %d B sees the built-in admin %q %v", stop, name, ok)
		}
	}
	renameStep = nil
	t.Cleanup(func() { renameStep = nil })
	prev, err := a.docs.RenameBuiltin(ctx, "test", "root")
	if err != nil || prev != "admin" {
		t.Fatalf("resumed rename: %q %v", prev, err)
	}
	b.cycle()
	c, _ := b.docs.clusterBody()
	if c.Builtin != "root" || c.BuiltinPrev != "" {
		t.Fatalf("cluster document: builtin %q prev %q", c.Builtin, c.BuiltinPrev)
	}
	if _, _, ok := b.docs.Users().Get("admin"); ok {
		t.Error("the old name's document is still there")
	}
	name, hash, ok := b.docs.Builtin()
	if !ok || name != "root" || hash != builtinHash() {
		t.Fatalf("B's built-in admin %q %v", name, ok)
	}
	if b.valid(old) || a.valid(old) {
		t.Error("the old name's session still works")
	}
	if prev, err := a.docs.RenameBuiltin(ctx, "test", "root"); err != nil || prev != "" {
		t.Errorf("a rename to the same name: %q %v", prev, err)
	}
}
