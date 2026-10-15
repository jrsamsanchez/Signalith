package shared

// Level 9 keeps API tokens (Settings > API tokens) in the shared
// settings, as api_token documents: a server whose version reads only the
// level below would refuse the tokens the others accept, so tokens are
// made only once every server seen lately reads this level.
const LevelAPITokens = 9

// APITokens reports whether API tokens can be made: the users are shared
// and the cluster is at LevelAPITokens.
func (rt *Runtime) APITokens() bool {
	return rt.SharedUsers() && rt.sharedAt(LevelAPITokens)
}
