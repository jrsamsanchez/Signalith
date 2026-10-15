package clustercfg

import (
	"encoding/json"
	"time"
)

// Requests of the content (see shared.Requests): work any member asks of
// the server that runs the background jobs.
const (
	// RequestFeedRefresh downloads one feed now.
	RequestFeedRefresh = "feed_refresh"
	// RequestRetentionRun runs retention now, or after a change of the
	// policies (trigger policy_change).
	RequestRetentionRun = "retention_run"
)

// FeedRefreshArgs are the arguments of a feed_refresh request.
type FeedRefreshArgs struct {
	Feed string `json:"feed"`
}

// RetentionRunArgs are the arguments of a retention_run request.
type RetentionRunArgs struct {
	// Trigger is retention.TriggerManual (the default) or
	// retention.TriggerChange.
	Trigger string `json:"trigger,omitempty"`
}

// Requests of the settings, each run by the servers it names (see
// shared.Runtime.RunServerRequests).
const (
	// RequestRestart restarts each server it names, one after the other
	// when sequential, so they apply the settings that wait for a
	// restart.
	RequestRestart = "restart"
	// RequestSettingsCheck checks a change of the server's own settings,
	// made on another server's Settings page, against its own files,
	// environment and certificate files before it is saved.
	RequestSettingsCheck = "settings_check"
)

// SettingsCheckWait is how long a Settings page waits for the server
// whose settings it changes to check the change: one offline or slower
// saves it after the type checks alone, and checks it when it starts.
const SettingsCheckWait = 5 * time.Second

// RestartArgs are the arguments of a restart request.
type RestartArgs struct {
	// LocalOnly marks a restart asked for on the server's own Settings
	// page, whose browser confirms a move of its web page, rather than on
	// another server's, which confirms it with Move.
	LocalOnly bool `json:"local_only,omitempty"`
}

// RestartResults are the result of a restart request: each server's
// restart, by node id.
type RestartResults map[string]RestartResult

// RestartResult is how one server's restart went.
type RestartResult struct {
	OK bool `json:"ok"`
	// RolledBack is set when the server started again with its previous
	// settings, Error saying why.
	RolledBack bool   `json:"rolled_back,omitempty"`
	Error      string `json:"error,omitempty"`
	// Keys are the settings the restart applied, or those to blame for
	// the rollback.
	Keys []string `json:"keys,omitempty"`
	// BootID is the boot id of the process that ran it.
	BootID string `json:"boot_id,omitempty"`
	// Move is set when the restart moved the server's web page to
	// another address.
	Move *Move `json:"move,omitempty"`
}

// Move is a restart that moves a server's web page: the server it moved
// to is asked for To/readyz?move=<Token>, which confirms the move. With
// no confirmation in time, the server goes back.
type Move struct {
	Token     string `json:"token"`
	To        string `json:"to"`
	Confirmed bool   `json:"confirmed,omitempty"`
}

// SettingsCheckArgs are the arguments of a settings_check request: the
// change, as the Settings page sent it.
type SettingsCheckArgs struct {
	Values map[string]json.RawMessage `json:"values,omitempty"`
	Clear  []string                   `json:"clear,omitempty"`
	Reset  []string                   `json:"reset,omitempty"`
	Retry  []string                   `json:"retry,omitempty"`
}

// SettingsCheckResult is what the server found: problems by setting
// (Fields) and others, the settings whose value changes, and those whose
// change the page asks to confirm.
type SettingsCheckResult struct {
	Fields   map[string]string `json:"fields,omitempty"`
	Problems []string          `json:"problems,omitempty"`
	Changed  []string          `json:"changed,omitempty"`
	Confirm  []string          `json:"confirm,omitempty"`
}

// Requests of adding and removing servers. Drain and resume are run by
// the server they name; release_jobs and rotate_key by the server that
// runs the background jobs.
const (
	// RequestDrain drains the server it names: it wants no traffic and
	// gives the background jobs up, until it is resumed.
	RequestDrain = "drain"
	// RequestResume undoes a drain.
	RequestResume = "resume"
	// RequestLeave is reserved for a server asked to leave the cluster by
	// itself.
	RequestLeave = "leave"
	// RequestReleaseJobs hands the background jobs to another server.
	RequestReleaseJobs = "release_jobs"
	// RequestRotateKey rotates the cluster key.
	RequestRotateKey = "rotate_key"
)

// ReleaseJobsArgs are the arguments of a release_jobs request: the node
// id of the server to take the background jobs.
type ReleaseJobsArgs struct {
	To string `json:"to"`
}

// RotateKeyArgs are the arguments of a rotate_key request: why it was
// asked for ("rotate-key", or the removal of a server), and the servers
// whose removal it follows.
type RotateKeyArgs struct {
	Reason  string   `json:"reason,omitempty"`
	Removed []string `json:"removed,omitempty"`
}
