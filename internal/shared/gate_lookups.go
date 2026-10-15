package shared

// LevelSharedLookups is the level from which the asset and identity
// lists are kept in the shared settings rather than in each server's
// lookups folder.
const LevelSharedLookups = 7

// ImportLookups is the name of the importer of the founder's asset and
// identity lists in cluster.import.done.
const ImportLookups = "lookups"

// SharedLookups reports whether this server takes the asset and identity
// lists from the shared settings rather than from its lookups folder: it
// takes the settings of the Settings page from there, the cluster is at
// LevelSharedLookups (every server reads them), and the founder's lists
// were imported.
func (rt *Runtime) SharedLookups() bool {
	return rt.SharedSettings() && rt.sharedAt(LevelSharedLookups, ImportLookups)
}
