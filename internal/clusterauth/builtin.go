package clusterauth

import (
	"context"
	"errors"
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
func (d *Docs) BuiltinUser() (*UserBody, string, bool) {
	name := d.builtinName()
	if name == "" {
		return nil, "", false
	}
	v, etag, ok := d.Users().Get(name)
	if !ok || v.Source != users.SourceBuiltin {
		return nil, "", false
	}
	return v, etag, true
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
