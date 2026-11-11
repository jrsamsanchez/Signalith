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
//
// Whether another admin is left is checked on each server's copy of the
// users, and two servers may each make a change the other's copy does
// not show yet (one turns the built-in admin off while another disables
// the last other admin). So whenever a copy is made again with the
// built-in admin off and no other enabled local admin, the built-in admin
// is turned on again: Signalith is never left without an admin.

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
	s.expectOff(off)
	changed, err := b.ChangeBuiltinDisabled(ctx, Actor(ctx), off, check)
	if err != nil || !changed {
		s.offMu.Lock()
		s.ownOff = nil
		s.offMu.Unlock()
	}
	return changed, err
}

// SetBuiltinNoticed has fn hear that the built-in admin was turned off or
// on other than with SetBuiltinDisabled on this store: in the users file
// by another server or by hand, or on again because no other enabled
// local admin was left. why says which, for the audit log.
func (s *Store) SetBuiltinNoticed(fn func(off bool, why string)) {
	s.offMu.Lock()
	defer s.offMu.Unlock()
	s.noticed = fn
}

// expectOff notes a change this store makes, which its next copy of the
// users then does not report as made elsewhere.
func (s *Store) expectOff(off bool) {
	s.offMu.Lock()
	defer s.offMu.Unlock()
	s.ownOff = &off
}

// errEnoughAdmins stops turning the built-in admin on again: another
// admin is there after all.
var errEnoughAdmins = errors.New("another enabled local admin is there")

// builtinAfterLoad looks at the built-in admin in a new copy of the users:
// it reports a change made outside this server to a users file
// (SetBuiltinNoticed), and turns the built-in admin on again when no other
// enabled local admin is left.
func (s *Store) builtinAfterLoad() {
	b, ok := s.b.(builtinOffBackend)
	if !ok || s.builtinName() == "" {
		return
	}
	off := b.BuiltinDisabled()
	s.offMu.Lock()
	prev, own, noticed := s.seenOff, s.ownOff, s.noticed
	s.seenOff = &off
	if own != nil && *own == off {
		s.ownOff = nil
	}
	s.offMu.Unlock()
	if s.path != "" && prev != nil && *prev != off && (own == nil || *own != off) && noticed != nil {
		go noticed(off, "changed in the users file")
	}
	if off && s.otherAdmins() == 0 {
		go s.restoreBuiltin(b)
	}
}

// restoreBuiltin turns the built-in admin on again, once no other enabled
// local admin is left.
func (s *Store) restoreBuiltin(b builtinOffBackend) {
	release, err := s.hold()
	if err != nil {
		return
	}
	defer release()
	s.expectOff(false)
	changed, err := b.ChangeBuiltinDisabled(context.Background(), "signalith", false, func() error {
		if s.otherAdmins() > 0 {
			return errEnoughAdmins
		}
		return nil
	})
	if err != nil || !changed {
		s.offMu.Lock()
		s.ownOff = nil
		s.offMu.Unlock()
		return
	}
	s.offMu.Lock()
	noticed := s.noticed
	s.offMu.Unlock()
	if noticed != nil {
		noticed(false, "no other enabled local admin was left")
	}
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
	next := f.builtinNext
	// An admin's decision replaces one signalith passwd left for the next
	// start.
	f.builtinOff, f.builtinNext = off, false
	if err := f.saveLocked(); err != nil {
		f.builtinOff, f.builtinNext = !off, next
		f.mu.Unlock()
		return false, err
	}
	f.mu.Unlock()
	f.notify()
	return true, nil
}

// SetFileBuiltinOnAtStart has a built-in admin turned off in the users
// file at path turned on when a server next starts (Store.StartBuiltin),
// and reports whether it was off: signalith passwd sets a new password
// that a server of its own files uses only from its next start, so the
// old one must not work again meanwhile.
func SetFileBuiltinOnAtStart(path string) (bool, error) {
	f := newFileBackend(path)
	f.wmu.Lock()
	defer f.wmu.Unlock()
	release, err := f.begin()
	if err != nil {
		return false, err
	}
	defer release()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.builtinOff {
		return false, nil
	}
	if f.builtinNext {
		return true, nil
	}
	f.builtinNext = true
	if err := f.saveLocked(); err != nil {
		f.builtinNext = false
		return false, err
	}
	return true, nil
}

// StartBuiltin is called as a server starts: it turns the built-in admin
// on when signalith passwd asked for that (SetFileBuiltinOnAtStart), and
// on again when no other enabled local admin is left. It reports whether
// the first happened, for the audit log.
func (s *Store) StartBuiltin(ctx context.Context) (bool, error) {
	f, ok := s.b.(*fileBackend)
	on := false
	if ok && s.builtinName() != "" {
		f.mu.RLock()
		next := f.builtinNext
		f.mu.RUnlock()
		if next {
			s.expectOff(false)
			changed, err := f.ChangeBuiltinDisabled(ctx, "signalith passwd", false, nil)
			if err != nil {
				s.offMu.Lock()
				s.ownOff = nil
				s.offMu.Unlock()
				return false, err
			}
			on = changed
		}
	}
	s.builtinAfterLoad()
	return on, nil
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
