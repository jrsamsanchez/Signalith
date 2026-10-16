package users

import (
	"context"
	"errors"
	"strings"
	"unicode"
)

// Provisioning (SCIM): an identity provider adds, changes, disables and
// removes single sign-on users ahead of their sign-ins. It sees only
// single sign-on users; local and directory users, and the built-in
// admin, are not its to change. A provisioned user has no Subject until
// they first sign in, and their role comes from their groups at each
// sign-in as for any single sign-on user; until then they hold the
// lowest role, which nothing uses since they cannot sign in without the
// provider.

// Provisioned is what provisioning says about a single sign-on user.
type Provisioned struct {
	Username   string
	Name       string
	Email      string
	ExternalID string
	Active     bool
}

var (
	// ErrRename refuses a change of a provisioned user's username.
	ErrRename = errors.New("a Signalith username cannot change; remove the user and add them again with the new name")
	// ErrNotSSO refuses provisioning a name that belongs to a local or
	// directory user, or the built-in admin.
	ErrNotSSO = errors.New("that username belongs to a Signalith user who does not sign in with single sign-on")
)

// cleanExternalID keeps an id from the provider to 256 characters with no
// control characters.
func cleanExternalID(id string) string {
	id = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, id))
	if r := []rune(id); len(r) > 256 {
		id = string(r[:256])
	}
	return id
}

// Pending reports whether u was provisioned and has not signed in yet.
func (u User) Pending() bool { return u.Source == SourceSSO && u.Subject == "" }

// ProvisionedOf returns what provisioning knows of a single sign-on user.
func ProvisionedOf(u User) Provisioned {
	return Provisioned{Username: u.Username, Name: u.Name, Email: u.Email, ExternalID: u.ExternalID, Active: !u.Disabled}
}

// SSOUsers returns the single sign-on users, sorted by username.
func (s *Store) SSOUsers() []User {
	var out []User
	for _, u := range s.List() {
		if u.Source == SourceSSO {
			out = append(out, u)
		}
	}
	return out
}

// Provision adds a single sign-on user before their first sign-in.
// ErrExists when a single sign-on user has the name already, ErrNotSSO
// when someone else has it.
func (s *Store) Provision(ctx context.Context, p Provisioned) (User, error) {
	name := NormalizeUsername(p.Username)
	if err := ValidUsername(name); err != nil {
		return User{}, fieldError("username", err)
	}
	if s.reserved(name) {
		return User{}, ErrNotSSO
	}
	if u, ok := s.Get(name); ok {
		if u.Source != SourceSSO {
			return User{}, ErrNotSSO
		}
		return User{}, ErrExists
	}
	release, err := s.hold()
	if err != nil {
		return User{}, err
	}
	defer release()
	now := s.now()
	r, err := s.b.Create(ctx, Actor(ctx), Record{User: User{Username: name, Source: SourceSSO, Name: cleanSSOName(p.Name),
		Email: cleanSSOEmail(p.Email), ExternalID: cleanExternalID(p.ExternalID), Role: Viewer, Disabled: !p.Active,
		Created: now, Updated: now}, Epoch: 1})
	if err != nil {
		return User{}, err
	}
	return recordUser(r), nil
}

// ChangeProvisioned changes a single sign-on user with fn, on what
// provisioning knows of them as they are now (or as read at etag, when
// set). The username may change only in case. Made inactive, their
// sessions end everywhere. A user who is not a single sign-on user is
// ErrNotFound.
func (s *Store) ChangeProvisioned(ctx context.Context, name, etag string, fn func(*Provisioned) error) (User, error) {
	name = NormalizeUsername(name)
	release, err := s.hold()
	if err != nil {
		return User{}, err
	}
	defer release()
	r, err := s.b.Change(ctx, Actor(ctx), name, etag, func(r *Record) error {
		if r.Source != SourceSSO {
			return ErrNotFound
		}
		p := ProvisionedOf(r.User)
		if err := fn(&p); err != nil {
			return err
		}
		if NormalizeUsername(p.Username) != name {
			return ErrRename
		}
		u := r.User
		u.Name, u.Email, u.ExternalID, u.Disabled = cleanSSOName(p.Name), cleanSSOEmail(p.Email), cleanExternalID(p.ExternalID), !p.Active
		if u == r.User {
			return ErrNoChange
		}
		if u.Disabled && !r.Disabled {
			r.Epoch++
		}
		u.Updated = s.now()
		r.User = u
		return nil
	})
	if err != nil {
		return User{}, err
	}
	return recordUser(r), nil
}

// DeleteProvisioned removes a single sign-on user (ErrNotFound for anyone
// else).
func (s *Store) DeleteProvisioned(ctx context.Context, name, etag string) (User, error) {
	name = NormalizeUsername(name)
	release, err := s.hold()
	if err != nil {
		return User{}, err
	}
	defer release()
	var gone User
	err = s.b.Delete(ctx, Actor(ctx), name, etag, func(r Record) error {
		if r.Source != SourceSSO {
			return ErrNotFound
		}
		gone = recordUser(r)
		return nil
	})
	if err != nil {
		return User{}, err
	}
	return gone, nil
}
