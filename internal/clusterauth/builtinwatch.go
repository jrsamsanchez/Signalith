// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterauth

import (
	"sync"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

// A command run on a server (signalith passwd, signalith cluster apply)
// changes the built-in admin's document directly, and has no audit log of
// its own to write to: its lines go to the terminal. BuiltinWatch lets a
// running server write the audit record instead, from what it sees
// change in the shared settings and who the document says changed it.

// What a BuiltinChange is.
const (
	BuiltinRenamed  = "renamed"
	BuiltinPassword = "password"
	BuiltinEnabled  = "enabled"
	BuiltinDisabled = "disabled"
)

// BuiltinChange is one change to the built-in admin a server saw in the
// shared settings: What happened to User, By whom on which server as its
// document records, and for a rename the name it had (From).
type BuiltinChange struct {
	What string
	User string
	From string
	By   shared.By
}

// BuiltinWatch compares each copy of the built-in admin's document with
// the one before, and hands Report what changed: a new name, a new
// password, turned off or on. The first copy it sees only sets what it
// compares with, so a change made while this server was not running is
// not reported.
type BuiltinWatch struct {
	Docs   *Docs
	Report func(BuiltinChange)

	mu   sync.Mutex
	seen *builtinSeen
}

type builtinSeen struct {
	name, hash string
	off        bool
}

// Check looks at the built-in admin now. It is called after the users or
// the cluster document changed (Docs.OnUsers, the cluster document's
// OnChange).
func (w *BuiltinWatch) Check() {
	v, _, ok := w.Docs.BuiltinUser()
	if !ok {
		return
	}
	cur := &builtinSeen{name: v.Username, hash: v.PasswordHash, off: v.Disabled}
	var by shared.By
	if it, ok := w.Docs.Users().Item(v.Username); ok {
		by = it.UpdatedBy
	}
	w.mu.Lock()
	prev := w.seen
	w.seen = cur
	w.mu.Unlock()
	if prev == nil || w.Report == nil {
		return
	}
	if prev.name != cur.name {
		w.Report(BuiltinChange{What: BuiltinRenamed, User: cur.name, From: prev.name, By: by})
	}
	if prev.hash != cur.hash {
		w.Report(BuiltinChange{What: BuiltinPassword, User: cur.name, By: by})
	}
	if prev.off != cur.off {
		what := BuiltinEnabled
		if cur.off {
			what = BuiltinDisabled
		}
		w.Report(BuiltinChange{What: what, User: cur.name, By: by})
	}
}
