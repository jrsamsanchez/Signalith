package shared

// Level 10 keeps tenant users (multi-tenant mode) in the shared users,
// and the tenant a sign-in session works in in its document: a server
// whose version reads only the level below would read a tenant user as
// one of the provider's, so neither is written until every server seen
// lately reads this level, and an older version refuses to start once
// the cluster is at it.
const LevelTenants = 10

// Tenants reports whether tenant users and sessions' tenants may be kept
// in the shared settings: the users are shared and the cluster is at
// LevelTenants.
func (rt *Runtime) Tenants() bool {
	return rt.SharedUsers() && rt.sharedAt(LevelTenants)
}
