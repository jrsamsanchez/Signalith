package shared

// Level 8 lets the cluster key be rotated: the keyring's next and
// catch_up hold copies of a new key sealed to each member, and every
// member picks its copy up, signs with the new key once the keyring makes
// it active, and reports the keys it holds in its heartbeat. A server
// whose version reads only the level below would miss the new key and
// stop with "missed a change of the cluster key", so rotations wait until
// every server seen lately reads this level, the same way as the levels
// before.
const LevelKeyRotation = 8

// KeyRotation reports whether the cluster key can be rotated: the
// settings are shared and the cluster is at LevelKeyRotation.
func (rt *Runtime) KeyRotation() bool {
	return rt.SharedSettings() && rt.sharedAt(LevelKeyRotation)
}
