package clusterauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// The built-in admin of a cluster is the user document of the name the
// cluster document records (ClusterBody.Builtin), with source builtin: one
// password for every server, which signalith passwd changes without a
// restart. Each server's auth.admin_user only names it at import; a
// server whose own differs uses the shared name.

// builtinName returns the built-in admin's name, or "" before it was
// imported.
func (d *Docs) builtinName() string {
	b, ok := d.clusterBody()
	if !ok {
		return ""
	}
	return b.Builtin
}

// BuiltinName returns the built-in admin's name, or "" before it was
// imported.
func (d *Docs) BuiltinName() string { return d.builtinName() }

// BuiltinUser returns the built-in admin's user document and its ETag.
// While it is renamed (RenameBuiltin), that is the old name's until the
// new name's is made.
func (d *Docs) BuiltinUser() (*UserBody, string, bool) {
	b, ok := d.clusterBody()
	if !ok || b.Builtin == "" {
		return nil, "", false
	}
	for _, name := range []string{b.Builtin, b.BuiltinPrev} {
		if name == "" {
			continue
		}
		if v, etag, ok := d.Users().Get(name); ok && v.Source == users.SourceBuiltin {
			return v, etag, true
		}
	}
	return nil, "", false
}

// Builtin returns the built-in admin's name and password hash, for
// users.Store.Builtin; ok is false before it was imported.
func (d *Docs) Builtin() (name, hash string, ok bool) {
	v, _, ok := d.BuiltinUser()
	if !ok {
		return "", "", false
	}
	return v.Username, v.PasswordHash, true
}

// SetBuiltinHash gives the built-in admin a new password hash, and moves
// its session epoch on so its sessions end on every server.
func (d *Docs) SetBuiltinHash(ctx context.Context, by, hash string) error {
	name := d.builtinName()
	if name == "" {
		return errors.New("the built-in admin is not in the shared settings yet")
	}
	_, err := d.Users().Mutate(ctx, by, name, func(v *UserBody) error {
		if v.Source != users.SourceBuiltin {
			return errors.New(name + " is not the built-in admin")
		}
		v.PasswordHash = hash
		v.SessionEpoch++
		v.Updated = time.Now().UTC()
		return nil
	})
	return err
}

// CreateBuiltin makes the built-in admin name with password hash, as the
// import does: the cluster document records its name first, then its
// user document is made. A built-in admin already there (from an import
// cut short, or another server's) counts as done; one recorded under
// another name keeps that name.
func (d *Docs) CreateBuiltin(ctx context.Context, by, name, hash string, now time.Time) (string, error) {
	if d.Cluster == nil || d.Cluster() == nil {
		return "", errors.New("the cluster document cannot be read")
	}
	name = users.NormalizeUsername(name)
	_, err := d.Cluster().Mutate(ctx, by, func(b *shared.ClusterBody) error {
		if b.Builtin == "" {
			b.Builtin = name
		}
		name = b.Builtin
		return nil
	})
	if err != nil {
		return "", err
	}
	now = now.UTC()
	_, err = d.Users().Create(ctx, by, name, &UserBody{Username: name, Role: users.Admin, Source: users.SourceBuiltin,
		PasswordHash: hash, SessionEpoch: 1, Created: now, Updated: now})
	if errors.Is(err, store.ErrExists) {
		err = nil
	}
	return name, err
}

// renameStep, set by tests, hears of each step of RenameBuiltin once it
// is done; an error stops the rename there, as a crash would.
var renameStep func(step int) error

// RenameBuiltin renames the built-in admin to name (signalith cluster
// apply with another auth.admin_user), in steps a crash between any two
// leaves to resume with the same command: (1) a user of the new name
// that is not the built-in admin refuses it; (2) the cluster document
// records the new name, and the old one as BuiltinPrev, so both names'
// documents are the built-in admin meanwhile; (3) the new name's
// document is made with the old one's password; (4) the old one's is
// deleted, which ends its sessions on every server; (5) BuiltinPrev is
// cleared. A rename under way to another name is finished first. It
// returns the name before, "" when it was the name already.
func (d *Docs) RenameBuiltin(ctx context.Context, by, name string) (string, error) {
	if d.Cluster == nil || d.Cluster() == nil {
		return "", errors.New("the cluster document cannot be read")
	}
	name = users.NormalizeUsername(name)
	if name == "" {
		return "", errors.New("the built-in admin needs a name")
	}
	step := func(n int) error {
		if renameStep != nil {
			return renameStep(n)
		}
		return nil
	}
	cur, ok := d.clusterBody()
	if !ok || cur.Builtin == "" {
		return "", errors.New("the built-in admin is not in the shared settings yet")
	}
	if cur.BuiltinPrev != "" && cur.Builtin != name {
		// A rename cut short: finish it, then rename again.
		if _, err := d.finishRename(ctx, by, cur.BuiltinPrev, cur.Builtin, step); err != nil {
			return "", err
		}
		cur, _ = d.clusterBody()
	}
	old := cur.Builtin
	if cur.BuiltinPrev != "" {
		old = cur.BuiltinPrev
	}
	if old == name && cur.BuiltinPrev == "" {
		return "", nil
	}
	if v, _, ok := d.Users().Get(name); ok && v.Source != users.SourceBuiltin {
		return "", fmt.Errorf("a user named %s exists already; rename or delete that user first", name)
	}
	if err := step(1); err != nil {
		return "", err
	}
	if _, err := d.Cluster().Mutate(ctx, by, func(b *shared.ClusterBody) error {
		if b.BuiltinPrev == "" {
			if b.Builtin != old {
				return fmt.Errorf("the built-in admin was renamed to %s meanwhile", b.Builtin)
			}
			b.BuiltinPrev = old
		}
		b.Builtin = name
		return nil
	}); err != nil {
		return "", err
	}
	if err := step(2); err != nil {
		return "", err
	}
	return d.finishRename(ctx, by, old, name, step)
}

// finishRename does the steps of RenameBuiltin from 3 on: the cluster
// document names name, with old as BuiltinPrev.
func (d *Docs) finishRename(ctx context.Context, by, old, name string, step func(int) error) (string, error) {
	list := d.Users()
	if v, _, ok := list.Get(name); !ok {
		prev, _, found := list.Get(old)
		if !found || prev.Source != users.SourceBuiltin {
			return "", fmt.Errorf("the built-in admin %s is missing, so its password cannot be carried over; set one with signalith passwd once the rename is done", old)
		}
		now := time.Now().UTC()
		_, err := list.Create(ctx, by, name, &UserBody{Username: name, Role: users.Admin, Source: users.SourceBuiltin,
			PasswordHash: prev.PasswordHash, SessionEpoch: 1, Created: now, Updated: now})
		if err != nil && !errors.Is(err, store.ErrExists) {
			return "", err
		}
	} else if v.Source != users.SourceBuiltin {
		return "", fmt.Errorf("a user named %s exists already; rename or delete that user first", name)
	}
	if err := step(3); err != nil {
		return "", err
	}
	if _, etag, ok := list.Get(old); ok && old != name {
		if _, err := list.Delete(ctx, by, old, etag); err != nil && !errors.Is(err, store.ErrNotFound) {
			return "", err
		}
	}
	if err := step(4); err != nil {
		return "", err
	}
	if _, err := d.Cluster().Mutate(ctx, by, func(b *shared.ClusterBody) error {
		if b.Builtin == name {
			b.BuiltinPrev = ""
		}
		return nil
	}); err != nil {
		return "", err
	}
	return old, step(5)
}
