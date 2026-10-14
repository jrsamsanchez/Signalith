package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// RuntimeIndex is the index that holds heartbeats, the job lease and
// other coordination documents. The underscore keeps it out of the event
// indices (<prefix>-*).
func RuntimeIndex(prefix string) string { return prefix + "_runtime" }

// runtimeSettings and runtimeMappings are the runtime index's.
func runtimeSettings() map[string]any {
	return map[string]any{"number_of_shards": 1, "auto_expand_replicas": "0-1", "refresh_interval": "1s"}
}

func runtimeMappings() map[string]any {
	kw := map[string]any{"type": "keyword"}
	long := map[string]any{"type": "long"}
	date := map[string]any{"type": "date"}
	return map[string]any{
		"dynamic": "false",
		"properties": map[string]any{
			"kind": kw, "node": kw, "node_id": kw, "state": kw, "target": kw, "detection_id": kw,
			"group_key": kw, "user": kw, "agent": kw, "name": kw,
			"epoch": long, "lease_epoch": long,
			"until": date, "at": date, "last_seen": date, "expires_at": date, "heartbeat_at": date,
			"body": map[string]any{"type": "object", "enabled": false},
		},
	}
}

// Doer sends OpenSearch REST requests. *store.Client has it.
type Doer interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// EnsureRuntime creates the runtime index if it is missing, for what keeps
// a document there besides the servers' own heartbeats and lease, such as
// the sample data's bookkeeping, which the signalith sample-data command
// may write before any server has run.
func EnsureRuntime(ctx context.Context, c Doer, prefix string) error {
	return ensureRuntime(ctx, c, prefix)
}

// ensureRuntime creates the runtime index if it is missing. Any server
// may, at any time; one that finds it already made carries on.
func ensureRuntime(ctx context.Context, c Doer, prefix string) error {
	err := c.Do(ctx, http.MethodPut, "/"+url.PathEscape(RuntimeIndex(prefix)), map[string]any{"settings": runtimeSettings(), "mappings": runtimeMappings()}, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == http.StatusBadRequest && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// ensureRuntimeTemplate saves an index template with the runtime index's
// settings. If someone deletes the index while servers run, their next
// heartbeat makes OpenSearch create it again, and the template keeps
// OpenSearch's defaults (a replica a single node cannot place, fields
// guessed from the documents) out of it. A user who may not save
// templates still gets the index.
func ensureRuntimeTemplate(ctx context.Context, c *store.Client, prefix string) error {
	name := RuntimeIndex(prefix)
	return c.Do(ctx, http.MethodPut, "/_index_template/"+url.PathEscape(name), map[string]any{
		"index_patterns": []string{name},
		// Above any catch-all template someone may have.
		"priority": 500,
		"template": map[string]any{"settings": runtimeSettings(), "mappings": runtimeMappings()},
		"_meta":    map[string]any{"managed_by": "signalith"},
	}, nil)
}

// Document ids in the runtime index.
const leaseID = "lease:jobs"

func nodeDocID(nodeID string) string { return "node:" + nodeID }

// LeaseDocID is the job lease's document id in the runtime index.
const LeaseDocID = leaseID

// NodeDocID returns the id of the heartbeat of the server nodeID.
func NodeDocID(nodeID string) string { return nodeDocID(nodeID) }

// Features of this version that another server or the command line may
// need to find in the heartbeat of the server running the background jobs.
const (
	// FeatureSampleData: the background jobs leave the one-click sample
	// data out (the scheduled detections and the threat intel feeds).
	FeatureSampleData = "sample_data"
	// FeatureIndexedAt: the heartbeat says when the server last stored an
	// event (IndexedAt), so one without it has stored none.
	FeatureIndexedAt = "indexed_at"
)

// features are this version's, as its heartbeats list them.
var features = []string{FeatureSampleData, FeatureIndexedAt}

// Server states in heartbeats.
const (
	StateStarting = "starting"
	StateReady    = "ready"
	StateStopping = "stopping"
	StateStopped  = "stopped"
	// StateConflict is a server that found another process using its
	// identity: it runs no jobs until that is fixed.
	StateConflict = "conflict"
	// StateDown is a server whose parts could not start (a restart in
	// place failed with the new settings and the previous ones): it
	// answers only with a page that says so, receives no syslog and runs
	// no jobs, and tries again.
	StateDown = "down"
	// StateOffline is never written: it is a heartbeat that stopped
	// changing.
	StateOffline = "offline"
	// StateUnreachable is never written either: it is this server, on its
	// own page, while it cannot reach OpenSearch, or OpenSearch doesn't
	// answer it in time (OSInfo.Problem is then store.ProblemTimeout).
	StateUnreachable = "unreachable"
	// StateRefused is never written either: it is this server, on its own
	// page, while OpenSearch answers but turns it away (OSInfo.Problem
	// says how).
	StateRefused = "refused"
)

// Heartbeat is a server's document in the runtime index, node:<node_id>,
// rewritten every 10 seconds.
type Heartbeat struct {
	Kind        string    `json:"kind"`
	NodeID      string    `json:"node_id"`
	Name        string    `json:"name"`
	BootID      string    `json:"boot_id"`
	State       string    `json:"state"`
	Version     string    `json:"version"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	Deployment  string    `json:"deployment,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	HeartbeatAt time.Time `json:"heartbeat_at"`
	// ClockOffsetMS is OpenSearch's clock minus this server's, nil when
	// it could not be measured.
	ClockOffsetMS *int64 `json:"clock_offset_ms"`
	NodeURL       string `json:"node_url,omitempty"`
	Listen        string `json:"listen,omitempty"`
	Syslog        Syslog `json:"syslog"`
	// LeaderEligible is true when this server may run the background
	// jobs, and NotEligible says why not otherwise.
	LeaderEligible bool   `json:"leader_eligible"`
	NotEligible    string `json:"not_eligible,omitempty"`
	Leader         bool   `json:"leader"`
	LeaseEpoch     int64  `json:"lease_epoch"`
	// Frozen is true while it holds the jobs in delete-only emergency
	// mode, because OpenSearch refuses writes.
	Frozen           bool         `json:"frozen,omitempty"`
	FilesFingerprint Fingerprints `json:"files_fingerprint"`
	OpenSearch       OSInfo       `json:"opensearch"`
	MachineMoved     bool         `json:"machine_moved"`
	Problems         []string     `json:"problems"`
	// PrevBoot is the boot id of the process that used this server's
	// state folder before this one. A server that finds its heartbeat
	// overwritten by a process whose PrevBoot is its own BootID knows a
	// copy of its folder was started elsewhere while it runs.
	PrevBoot string `json:"prev_boot,omitempty"`
	// CannotTakeOver says why this server, though it may run the jobs,
	// would not take them over by itself now.
	CannotTakeOver string `json:"cannot_take_over,omitempty"`
	// Security sums up this server's last security check, for the
	// Security page of the others. A server too old to check itself has
	// none.
	Security *SecuritySummary `json:"security,omitempty"`
	// Features lists what this server's version can do that an older one
	// cannot, where another server must know it (see FeatureSampleData).
	Features []string `json:"features,omitempty"`
	// IndexedAt is the last time this server stored an event; nil before
	// the first, and from versions before it was kept, which do not list
	// FeatureIndexedAt (see Node.IndexingServers).
	IndexedAt *time.Time `json:"indexed_at,omitempty"`
	// Mode is how the server uses the shared configuration (shared.Mode),
	// "" from versions before it; ClusterKID the cluster key it signs
	// with; ConfigSeq how far it has read the config index; MaxRev the
	// highest revision of a shared document it applied (accept-restore
	// goes above every server's).
	Mode       string `json:"mode,omitempty"`
	ClusterKID string `json:"cluster_kid,omitempty"`
	ConfigSeq  int64  `json:"config_seq,omitempty"`
	MaxRev     int64  `json:"max_rev,omitempty"`
	// NeedsUpgrade lists the shared documents a newer version wrote, and
	// Tamper those changed in OpenSearch outside Signalith: the server
	// keeps its last good copy of each.
	NeedsUpgrade []string `json:"needs_upgrade,omitempty"`
	Tamper       []string `json:"tamper,omitempty"`
	// SettingsDrift lists, per source, the shared settings whose value in
	// the server's file or environment differs from the one in use.
	SettingsDrift map[string][]string `json:"settings_drift,omitempty"`
	// LevelMin and LevelMax are the levels of the stored formats the
	// server's version reads.
	LevelMin int `json:"level_min,omitempty"`
	LevelMax int `json:"level_max,omitempty"`
}

// SecuritySummary is a server's last security check, as its heartbeat
// carries it. CheckedAt is nil until the first check has run.
type SecuritySummary struct {
	CheckedAt *time.Time `json:"checked_at"`
	Risk      int        `json:"risk"`
	Attention int        `json:"attention"`
	Unknown   int        `json:"unknown"`
	// CAScope is the scope of the certificate authority in use (standard,
	// strict or unconstrained), "" without one of Signalith's own.
	CAScope string `json:"ca_scope,omitempty"`
}

// Syslog is where a server listens for syslog.
type Syslog struct {
	UDP string `json:"udp"`
	TCP string `json:"tcp"`
	TLS string `json:"tls"`
}

// OSInfo is how a server reaches OpenSearch.
type OSInfo struct {
	OK        bool   `json:"ok"`
	Endpoint  string `json:"endpoint,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
	// Problem is how OpenSearch turned the server's last heartbeat away
	// (a store.Refusal, such as not_initialized or busy), or "timeout"
	// when it took the heartbeat but didn't answer in time (store.Problem).
	Problem string `json:"problem,omitempty"`
}

// LeaseDoc is lease:jobs, which names the server that runs the
// background jobs.
type LeaseDoc struct {
	Kind          string    `json:"kind"`
	Job           string    `json:"job"`
	Holder        string    `json:"holder"`
	HolderName    string    `json:"holder_name"`
	HolderVersion string    `json:"holder_version"`
	HolderBoot    string    `json:"holder_boot"`
	Epoch         int64     `json:"epoch"`
	AcquiredAt    time.Time `json:"acquired_at"`
	RenewedAt     time.Time `json:"renewed_at"`
	TTLMS         int64     `json:"ttl_ms"`
	// Prefer names the server a release hands the jobs to.
	Prefer        string `json:"prefer"`
	ReleasedBy    string `json:"released_by"`
	ReleaseReason string `json:"release_reason"`
	// Fingerprint covers the holder's own files that the jobs use, and
	// Fingerprints its parts, so a server whose files differ does not take
	// over without anyone noticing.
	Fingerprint  string       `json:"fingerprint"`
	Fingerprints Fingerprints `json:"fingerprints"`
}

// Fingerprints are hashes of the files each server keeps for itself
// that the background jobs use. Until they are shared through OpenSearch,
// a server whose files differ from the job holder's does not take over the
// jobs by itself.
type Fingerprints struct {
	Retention  string `json:"retention,omitempty"`
	Feeds      string `json:"feeds,omitempty"`
	Detections string `json:"detections,omitempty"`
	// Notify is the notification channels and rules; "" when a server
	// has none.
	Notify string `json:"notify,omitempty"`
	// Playbooks is the playbooks; "" when a server has none.
	Playbooks string `json:"playbooks,omitempty"`
	// Archives names the archive folder (its id file), only while some
	// retention policy archives: servers that share one folder share it.
	Archives string `json:"archives,omitempty"`
	// Users is the users and the directory sign-in settings in the
	// server's own files. The background jobs do not use them, so it is
	// not part of Combined or Differ: it names the servers whose users a
	// late import of the users leaves out (shared.LateImport).
	Users string `json:"users,omitempty"`
	// Unknown is true when they could not be worked out in time: the
	// archive folder's share may not answer.
	Unknown bool `json:"-"`
}

// Combined is one hash over all the parts.
func (f Fingerprints) Combined() string {
	h := sha256.New()
	for _, p := range []string{f.Retention, f.Feeds, f.Detections, f.Archives} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	// Only when set, so servers without notifications hash as servers of
	// versions before them do.
	if f.Notify != "" {
		h.Write([]byte("notify:" + f.Notify))
		h.Write([]byte{0})
	}
	if f.Playbooks != "" {
		h.Write([]byte("playbooks:" + f.Playbooks))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// SharedPrefix starts the fingerprint of the parts a member of the
// cluster takes from the shared settings rather than its files:
// "shared:<cluster id>". Two members of one cluster always match on
// them; a server that keeps them in its own files (an older version, or
// one not part of the cluster yet) never matches a member.
const SharedPrefix = "shared:"

// SharedFingerprint is the fingerprint of the shared parts of a member
// of the cluster clusterID.
func SharedFingerprint(clusterID string) string { return SharedPrefix + clusterID }

// differWords names a part that differs, saying so when one of the two
// servers keeps it in its own files and the other shares it.
func differWords(what, a, b string) string {
	if strings.HasPrefix(a, SharedPrefix) != strings.HasPrefix(b, SharedPrefix) {
		return what + " (one server keeps them in its own files: an older version, or not part of the cluster yet)"
	}
	return what
}

// Differ lists the parts that differ between f and o, in words: "retention
// policies", "threat intel feeds", "detections folder", "notification
// channels", "playbooks", "archive folder".
func (f Fingerprints) Differ(o Fingerprints) []string {
	var out []string
	if f.Retention != o.Retention {
		out = append(out, differWords("retention policies", f.Retention, o.Retention))
	}
	if f.Feeds != o.Feeds {
		out = append(out, differWords("threat intel feeds", f.Feeds, o.Feeds))
	}
	if f.Detections != o.Detections {
		out = append(out, "detections folder")
	}
	if f.Notify != o.Notify {
		out = append(out, "notification channels")
	}
	if f.Playbooks != o.Playbooks {
		out = append(out, "playbooks")
	}
	if f.Archives != o.Archives {
		out = append(out, "archive folder")
	}
	return out
}

// Hash returns "sha256:<hex>" of the parts, each ended by a zero byte.
func Hash(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
