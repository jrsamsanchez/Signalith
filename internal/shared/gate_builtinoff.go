// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

// Level 12 lets the built-in admin be turned off (Settings > Users): its
// user document is then marked disabled, which a server whose version
// reads only the level below takes for a damaged document, and whose
// sign-in checks would still let the built-in admin in. So it is turned
// off only once every server seen lately reads this level, and an older
// version refuses to start once the cluster is at it.
const LevelBuiltinOff = 12

// BuiltinOff reports whether the built-in admin may be turned off: the
// users are shared and the cluster is at LevelBuiltinOff.
func (rt *Runtime) BuiltinOff() bool {
	return rt.SharedUsers() && rt.sharedAt(LevelBuiltinOff)
}
