package shared

// Level 4 keeps every server's audit records in shared monthly indices,
// the retention history as audit records, and the archive manifests in
// the runtime index, so they survive a takeover. A server whose version
// reads only level 3 would keep writing its own history and manifests,
// so the level is raised only once every server seen lately reads it.

// LevelSharedAudit is the level from which audit records, the retention
// history and archive manifests are shared.
const LevelSharedAudit = 4

// The names of the importers of the founder's retention history and
// archive manifests in cluster.import.done.
const (
	ImportRetentionHistory = "retention_history"
	ImportArchives         = "archives"
)

// SharedAudit reports whether this server keeps its audit records, the
// retention history and the archive manifests in OpenSearch rather than
// in its own files: it takes the settings of the Settings page from the
// shared settings, the cluster is at LevelSharedAudit, and the history
// and manifests were imported.
func (rt *Runtime) SharedAudit() bool {
	return rt.SharedSettings() && rt.sharedAt(LevelSharedAudit, ImportRetentionHistory, ImportArchives)
}
