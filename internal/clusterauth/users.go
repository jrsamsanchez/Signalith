package clusterauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tenants"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// UserBody is the body of <prefix>_config/user:<name>: one user, with
// their password hash (local users and the built-in admin; bcrypt, not
// sealed, so a new cluster key never locks anyone out) and their session
// epoch. Last sign-ins are kept apart (LastSeen), so signing in never
// changes it.
type UserBody struct {
	Username           string     `json:"username"`
	Name               string     `json:"name,omitempty"`
	Email              string     `json:"email,omitempty"`
	Role               users.Role `json:"role"`
	Source             string     `json:"source"`
	Tenant             string     `json:"tenant,omitempty"`
	Disabled           bool       `json:"disabled"`
	MustChangePassword bool       `json:"must_change_password"`
	DN                 string     `json:"dn,omitempty"`
	Subject            string     `json:"subject,omitempty"`
	ExternalID         string     `json:"external_id,omitempty"`
	InactiveAtIdP      bool       `json:"inactive_at_idp,omitempty"`
	Refused            string     `json:"refused,omitempty"`
	PasswordHash       string     `json:"password_hash,omitempty"`
	SessionEpoch       int64      `json:"session_epoch"`
	// MFA is the user's two-step sign-in, its key sealed with the cluster
	// key; the built-in admin's too.
	MFA          *users.StoredMFA `json:"mfa,omitempty"`
	Created      time.Time        `json:"created"`
	Updated      time.Time        `json:"updated"`
	shared.Extra `json:"-"`
}

// mfaKeys seal authenticator keys with the active cluster key, and open
// them with any cluster key this server has.
type mfaKeys struct{ keys *shared.KeySet }

func (k mfaKeys) Seal(field, plain string) (string, error) {
	if k.keys == nil || k.keys.Active() == nil {
		return "", errors.New("this server has no cluster key")
	}
	return k.keys.Active().SecretsKey().Seal(field, plain)
}

func (k mfaKeys) Open(field, stored string) (string, error) {
	return opener(k.keys).Open(field, stored)
}

func (k mfaKeys) Current(stored string) bool {
	return k.keys != nil && k.keys.Active() != nil && secrets.KeyID(stored) == k.keys.Active().ID()
}

// mfaKeys returns the keys authenticator keys are sealed with.
func (d *Docs) mfaKeys() users.MFAKeys { return mfaKeys{d.keys()} }

// bodyOf returns the body of a user record, over the fields of old (nil
// for a new user) this version does not know, the authenticator key
// sealed with keys.
func bodyOf(r users.Record, old *UserBody, keys users.MFAKeys) (*UserBody, error) {
	m, err := users.SealMFA(keys, users.MFAField(r.Username), r.MFA)
	if err != nil {
		return nil, err
	}
	b := &UserBody{Username: r.Username, Name: r.Name, Email: r.Email, Role: r.Role, Source: r.Source, Tenant: r.Tenant, Disabled: r.Disabled,
		MustChangePassword: r.MustChangePassword, DN: r.DN, Subject: r.Subject, ExternalID: r.ExternalID, InactiveAtIdP: r.InactiveAtIdP,
		Refused: r.Refused, SessionEpoch: r.Epoch, MFA: m,
		Created: r.Created.UTC(), Updated: r.Updated.UTC()}
	if r.Source == users.SourceLocal {
		b.PasswordHash = r.Hash
	}
	if old != nil {
		b.Extra = old.Extra
		if old.Source == users.SourceBuiltin {
			b.PasswordHash = old.PasswordHash
		}
	}
	return b, nil
}

// record returns the user record of a body, the authenticator key opened
// with keys.
func record(b *UserBody, etag string, keys users.MFAKeys) users.Record {
	r := users.Record{User: users.User{Username: b.Username, Name: b.Name, Email: b.Email, Role: b.Role, Source: b.Source, Tenant: b.Tenant,
		Disabled: b.Disabled, MustChangePassword: b.MustChangePassword, DN: b.DN, Subject: b.Subject, ExternalID: b.ExternalID,
		InactiveAtIdP: b.InactiveAtIdP, Refused: b.Refused,
		Created: b.Created, Updated: b.Updated, SessionEpoch: b.SessionEpoch}, Epoch: b.SessionEpoch, ETag: etag,
		MFA: b.MFA.Open(keys, users.MFAField(b.Username))}
	if b.Source == users.SourceLocal {
		r.Hash = b.PasswordHash
	}
	return r
}

// validateUser refuses a user document whose body names another user
// than its id, has a role or source this version does not know, or is a
// built-in admin other than the one the cluster document names: a forged
// second built-in admin is refused even with a valid MAC. While the
// built-in admin is renamed (ClusterBody.BuiltinPrev is set), the old
// name's document is accepted as well, until the rename ends it.
func (d *Docs) validateUser(name string, b *UserBody) error {
	if b.Username != name {
		return fmt.Errorf("it holds the user %q", b.Username)
	}
	if !b.Role.Valid() {
		return fmt.Errorf("its role %q is not one this version knows", b.Role)
	}
	if b.Tenant != "" && (tenants.ValidID(b.Tenant) != nil || b.Source != users.SourceLocal) {
		return fmt.Errorf("its tenant %q is not a tenant a user can have", b.Tenant)
	}
	switch b.Source {
	case users.SourceLocal, users.SourceDirectory, users.SourceSSO:
	case users.SourceBuiltin:
		if c, ok := d.clusterBody(); !ok || c.Builtin == "" || c.Builtin != name && (c.BuiltinPrev == "" || c.BuiltinPrev != name) {
			return errors.New("it is a built-in admin the cluster document does not name")
		}
		if b.Role != users.Admin || b.Disabled {
			return errors.New("the built-in admin must be an enabled admin")
		}
	default:
		return fmt.Errorf("its source %q is not one this version knows", b.Source)
	}
	return nil
}

// ErrTenantUsers refuses tenant users, and sessions' tenants, in the
// shared settings below shared.LevelTenants.
var ErrTenantUsers = errors.New("tenants need every server sharing these settings on a version that supports them: upgrade the others first")

// TenantsOn reports whether the cluster keeps tenants (Docs.Tenants, the
// runtime's shared.LevelTenants gate), so tenant users and sessions'
// tenants may be kept in the shared settings. Below it, a tenant user is
// never used: no server writes one, and an older server would read one
// as a user of the provider's.
func (d *Docs) TenantsOn() bool {
	return d.Tenants != nil && d.Tenants()
}

// UsersBackend keeps the users of a users.Store in the shared settings.
// The built-in admin is a user document too (source builtin) but is left
// out: the Store knows it through Builtin.
type UsersBackend struct {
	Docs *Docs
}

var _ users.Backend = (*UsersBackend)(nil)

// Load returns every user but the built-in admin.
func (b *UsersBackend) Load() (map[string]users.Record, error) {
	out := map[string]users.Record{}
	keys := b.Docs.mfaKeys()
	for _, it := range b.Docs.Users().List() {
		if it.Value == nil || it.Value.Source == users.SourceBuiltin || it.Value.Tenant != "" && !b.Docs.TenantsOn() {
			continue
		}
		out[it.Name] = record(it.Value, it.ETag, keys)
	}
	return out, nil
}

// OnChange calls fn after users changed, here or on another server,
// until the next start of the components (Docs.Reset), so a store of an
// earlier start is not kept.
func (b *UsersBackend) OnChange(fn func()) { b.Docs.OnUsers(fn) }

// Create adds a user with _create, so of two servers that add the same
// name at once one wins; the other gets users.ErrExists.
func (b *UsersBackend) Create(ctx context.Context, by string, r users.Record) (users.Record, error) {
	col := b.Docs.Users()
	if r.Source == users.SourceBuiltin {
		return users.Record{}, users.ErrReserved
	}
	if r.Tenant != "" && !b.Docs.TenantsOn() {
		// Servers of an older version would read a tenant user as one of
		// the provider's.
		return users.Record{}, ErrTenantUsers
	}
	keys := b.Docs.mfaKeys()
	body, err := bodyOf(r, nil, keys)
	if err != nil {
		return users.Record{}, err
	}
	_, err = col.Create(ctx, by, r.Username, body)
	if errors.Is(err, store.ErrExists) {
		return users.Record{}, users.ErrExists
	}
	if err != nil {
		return users.Record{}, err
	}
	v, etag, ok := col.Get(r.Username)
	if !ok {
		return users.Record{}, users.ErrNotFound
	}
	return record(v, etag, keys), nil
}

// errNoWrite stops a change that changes nothing.
var errNoWrite = errors.New("nothing to write")

// Change changes the user name with fn: on the latest copy, again on a
// newer one when another server changed it meanwhile (Collection.Mutate),
// or, with etag, on the copy read then (Collection.MutateIf, a
// *shared.StaleError naming who changed it since). The built-in admin is
// not changed here.
func (b *UsersBackend) Change(ctx context.Context, by, name, etag string, fn func(*users.Record) error) (users.Record, error) {
	col := b.Docs.Users()
	keys := b.Docs.mfaKeys()
	var out users.Record
	none := false
	change := func(v *UserBody) error {
		if v.Source == users.SourceBuiltin {
			return users.ErrNotFound
		}
		cur := record(v, "", keys)
		r := cur
		err := fn(&r)
		if errors.Is(err, users.ErrNoChange) {
			out, none = cur, true
			return errNoWrite
		}
		if err != nil {
			return err
		}
		r.Username = name
		nb, err := bodyOf(r, v, keys)
		if err != nil {
			return err
		}
		if sameBody(nb, v) {
			// Only what is kept apart changed, such as a sign-in time.
			out, none = cur, true
			return errNoWrite
		}
		*v = *nb
		return nil
	}
	var err error
	if etag != "" {
		_, err = col.MutateIf(ctx, by, name, etag, change)
	} else {
		_, err = col.Mutate(ctx, by, name, change)
	}
	switch {
	case none && errors.Is(err, errNoWrite):
		_, et, _ := col.Get(name)
		out.ETag = et
		return out, nil
	case errors.Is(err, store.ErrNotFound):
		return users.Record{}, users.ErrNotFound
	case err != nil:
		return users.Record{}, err
	}
	v, et, ok := col.Get(name)
	if !ok {
		return users.Record{}, users.ErrNotFound
	}
	return record(v, et, keys), nil
}

// Delete deletes the user name, leaving a signed tombstone, once check
// allows it on the user as they are now. Without etag a change made
// meanwhile on another server is read and checked again.
func (b *UsersBackend) Delete(ctx context.Context, by, name, etag string, check func(users.Record) error) error {
	col := b.Docs.Users()
	for try := 0; ; try++ {
		v, cur, ok := col.Get(name)
		if !ok || v.Source == users.SourceBuiltin {
			return users.ErrNotFound
		}
		if etag != "" && etag != cur && try == 0 {
			// This server may not have read the latest copy yet.
			if err := col.Refresh(ctx, name); err != nil {
				return err
			}
			continue
		}
		if etag != "" && etag != cur {
			_, err := col.Delete(ctx, by, name, etag)
			if errors.Is(err, store.ErrNotFound) {
				return users.ErrNotFound
			}
			return err
		}
		if check != nil {
			if err := check(record(v, cur, b.Docs.mfaKeys())); err != nil {
				return err
			}
		}
		_, err := col.Delete(ctx, by, name, cur)
		var stale *shared.StaleError
		switch {
		case errors.Is(err, store.ErrNotFound):
			return users.ErrNotFound
		case errors.As(err, &stale) && etag == "" && try < store.ModifyTries:
			continue
		}
		return err
	}
}

// EndSessions moves the session epoch of the user name on, so their
// sessions end on every server, without changing anything else: for a
// directory user whose role was given under directory settings that
// changed since, and who could not be checked again.
func (b *UsersBackend) EndSessions(ctx context.Context, by, name string) error {
	_, err := b.Docs.Users().Mutate(ctx, by, name, func(v *UserBody) error {
		v.SessionEpoch++
		return nil
	})
	return err
}

// sameBody reports whether two bodies hold the same values.
func sameBody(a, b *UserBody) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(x) == string(y)
}

// BuiltinMFA returns the built-in admin's two-step sign-in, or nil.
func (b *UsersBackend) BuiltinMFA() *users.MFA {
	v, _, ok := b.Docs.BuiltinUser()
	if !ok {
		return nil
	}
	return v.MFA.Open(b.Docs.mfaKeys(), users.BuiltinMFAField)
}

// ChangeBuiltinMFA changes the built-in admin's two-step sign-in with
// fn, on the latest copy of its document.
func (b *UsersBackend) ChangeBuiltinMFA(ctx context.Context, by string, fn users.MFAChange) error {
	v, _, ok := b.Docs.BuiltinUser()
	if !ok {
		return errors.New("the built-in admin is not in the shared settings yet")
	}
	keys := b.Docs.mfaKeys()
	_, err := b.Docs.Users().Mutate(ctx, by, v.Username, func(v *UserBody) error {
		if v.Source != users.SourceBuiltin {
			return errors.New(v.Username + " is not the built-in admin")
		}
		next, end, err := fn(v.MFA.Open(keys, users.BuiltinMFAField))
		if err != nil {
			return err
		}
		m, err := users.SealMFA(keys, users.BuiltinMFAField, next)
		if err != nil {
			return err
		}
		v.MFA = m
		if end {
			v.SessionEpoch++
		}
		v.Updated = time.Now().UTC()
		return nil
	})
	if errors.Is(err, users.ErrNoChange) {
		return nil
	}
	return err
}

// resealMFA seals every authenticator key in the users' documents (the
// built-in admin's too) again with the active cluster key, for a key
// rotation.
func (d *Docs) resealMFA(ctx context.Context, keys *shared.KeySet) error {
	for _, it := range d.Users().List() {
		if it.Value == nil || it.Value.MFA == nil || it.Value.MFA.Secret == "" || (mfaKeys{keys}).Current(it.Value.MFA.Secret) {
			continue
		}
		field := users.MFAField(it.Name)
		if it.Value.Source == users.SourceBuiltin {
			field = users.BuiltinMFAField
		}
		if _, err := d.Users().Mutate(ctx, "signalith", it.Name, func(v *UserBody) error {
			if v.MFA == nil || v.MFA.Secret == "" {
				return nil
			}
			sealed, err := shared.Reseal(keys, field, v.MFA.Secret)
			if err != nil {
				return err
			}
			v.MFA.Secret = sealed
			return nil
		}); err != nil {
			return fmt.Errorf("two-step sign-in of %s: %w", it.Name, err)
		}
	}
	return nil
}
