package shared

// Level 4 keeps the cluster's one certificate authority in the shared
// settings (the tls document, internal/clustertls): every server issues
// its own HTTPS certificate from it, so an agent set up against one
// server trusts them all. A server whose version reads only level 3 would
// keep a certificate authority of its own, so the level is raised once
// every server seen lately reads it, the same way as the levels before.
const LevelSharedTLS = 4

// ImportTLS is the name of the importer of the founder's certificate
// authority in cluster.import.done. It is recorded whether or not it
// published one: several servers with different certificate authorities
// leave the choice to an admin, and whether the tls document exists says
// whether one was chosen.
const ImportTLS = "tls"

// SharedTLS reports whether cluster certificate authority handling is on:
// the settings are shared, the cluster is at LevelSharedTLS and the tls
// importer ran. It does not say a certificate authority was chosen yet.
func (rt *Runtime) SharedTLS() bool {
	return rt.SharedSettings() && rt.sharedAt(LevelSharedTLS, ImportTLS)
}
