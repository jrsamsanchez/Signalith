// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"errors"
)

// The built-in admin can be turned off once another admin can take over:
// it is a well-known name that always has full rights, so once people
// sign in with admin accounts of their own, it is best kept off and
// turned on again only when needed. An admin turns it on again on the
// Users page, and anyone with access to a server does with signalith
// passwd, which is the way back in if every other admin is locked out.

var (
	// ErrBuiltinLastAdmin refuses to turn the built-in admin off while no
	// other enabled admin could take over.
	ErrBuiltinLastAdmin = errors.New("the built-in admin can be turned off only while another enabled local admin exists; " +
		"add an admin on this page first (directory and single sign-on admins don't count, since their role can change outside Signalith)")
	// ErrNoBuiltinOff says this store cannot turn the built-in admin off.
	ErrNoBuiltinOff = errors.New("the built-in admin cannot be turned off on this server")
)

// builtinOffBackend is a Backend that keeps whether the built-in admin is
// turned off.
type builtinOffBackend interface {
	BuiltinDisabled() bool
	// ChangeBuiltinDisabled turns the built-in admin off or on, once check
	// allows it (check may be nil), and reports whether it changed. Turning
	// it off ends its sessions everywhere, where the backend keeps them.
	ChangeBuiltinDisabled(ctx context.Context, by string, off bool, check func() error) (bool, error)
}

// BuiltinDisabled reports whether the built-in admin is turned off.
func (s *Store) BuiltinDisabled() bool {
	s.fresh()
	return s.builtinOff()
}

// builtinOff is BuiltinDisabled without looking for changes first, for
// checks made during a change.
func (s *Store) builtinOff() bool {
	b, ok := s.b.(builtinOffBackend)
	return ok && b.BuiltinDisabled()
}

// SetBuiltinDisabled turns the built-in admin off or on, and reports
// whether it changed. It is turned off only while another enabled local
// admin of the provider exists (ErrBuiltinLastAdmin): directory and
// single sign-on admins don't count, as for the last admin of all.
func (s *Store) SetBuiltinDisabled(ctx context.Context, off bool) (bool, error) {
	b, ok := s.b.(builtinOffBackend)
	if !ok || s.builtinName() == "" {
		return false, ErrNoBuiltinOff
	}
	release, err := s.hold()
	if err != nil {
		return false, err
	}
	defer release()
	var check func() error
	if off {
		check = func() error {
			if s.otherAdmins() == 0 {
				return ErrBuiltinLastAdmin
			}
			return nil
		}
	}
	return b.ChangeBuiltinDisabled(ctx, Actor(ctx), off, check)
}

// otherAdmins counts the enabled local admins of the provider, the
// built-in admin left out.
func (s *Store) otherAdmins() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, u := range s.users {
		if u.Source == SourceLocal && u.Role == Admin && !u.Disabled && u.Tenant == "" {
			n++
		}
	}
	return n
}

// BuiltinDisabled reports whether the built-in admin is turned off.
func (f *fileBackend) BuiltinDisabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.builtinOff
}

// ChangeBuiltinDisabled turns the built-in admin off or on in the file as
// it is now. Its sessions are kept in memory, so ending them is left to
// the caller.
func (f *fileBackend) ChangeBuiltinDisabled(_ context.Context, _ string, off bool, check func() error) (bool, error) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	release, err := f.begin()
	if err != nil {
		return false, err
	}
	defer release()
	f.mu.Lock()
	if f.builtinOff == off {
		f.mu.Unlock()
		return false, nil
	}
	f.mu.Unlock()
	// check reads the users, under the Store's lock: not under mu.
	if check != nil {
		if err := check(); err != nil {
			return false, err
		}
	}
	f.mu.Lock()
	f.builtinOff = off
	if err := f.saveLocked(); err != nil {
		f.builtinOff = !off
		f.mu.Unlock()
		return false, err
	}
	f.mu.Unlock()
	f.notify()
	return true, nil
}

// ReadFileBuiltinDisabled reports whether the users file at path has the
// built-in admin turned off, as a cluster's import carries it over.
func ReadFileBuiltinDisabled(path string) (bool, error) {
	f := newFileBackend(path)
	if _, err := f.reloadLocked(); err != nil {
		return false, err
	}
	return f.builtinOff, nil
}

// SetFileBuiltinDisabled turns the built-in admin off or on in the users
// file at path, as it is now, and reports whether it changed: for
// signalith passwd, which turns it on again, and a cluster's export. A
// server that uses the file sees the change within a second or so.
func SetFileBuiltinDisabled(path string, off bool) (bool, error) {
	f := newFileBackend(path)
	return f.ChangeBuiltinDisabled(context.Background(), "", off, nil)
}
