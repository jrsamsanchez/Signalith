package shared

// LevelSharedLibrary is the level from which the custom detections, the
// choices made for shipped ones and the custom dashboards are kept in the
// shared settings rather than in each server's folders.
const LevelSharedLibrary = 6

// The names of the importers of the founder's detections and dashboards
// in cluster.import.done: they become shared once both ran.
const (
	ImportDetections = "detections"
	ImportDashboards = "dashboards"
)

// SharedLibrary reports whether this server takes the detections and
// dashboards from the shared settings rather than from its folders: it
// takes the settings of the Settings page from there, the cluster is at
// LevelSharedLibrary (every server reads them), and the founder's
// detections and dashboards were imported.
func (rt *Runtime) SharedLibrary() bool {
	return rt.SharedSettings() && rt.sharedAt(LevelSharedLibrary, ImportDetections, ImportDashboards)
}
