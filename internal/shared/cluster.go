package shared

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The cluster document, <prefix>_config/cluster, says that the servers
// sharing this OpenSearch are one cluster: its id and name, which server
// founded it and when, the level of the stored formats every server must
// read, how far the import of the founder's files has come, and the
// migrations run once for the whole cluster. It is created with _create,
// so of two servers that found at the same moment one wins.

// Document ids and kinds of the cluster and the keyring.
const (
	ClusterDocID = "cluster"
	KeyringDocID = "keyring"
)

// The levels of the stored formats this version reads and writes. A
// cluster whose level is outside them was made by a version too new, or
// too old to upgrade from directly, and this server refuses to start.
//
// Level 2 keeps the users, the directory sign-in settings and the
// sessions in the shared settings. A server whose version reads only
// level 1 ignores them, so the level is raised only once every server
// seen lately reads level 2 (RaiseLevel), and from then on an older
// version refuses to start rather than keep users of its own.
//
// Level 3 keeps the settings of the Settings page in the shared settings
// too, and has each server run the requests that name it (a restart of
// these servers, one at a time), so it is raised the same way.
const (
	LevelMin = 1
	LevelMax = LevelSharedLibrary
)

// LevelSharedUsers is the level from which users are kept in the shared
// settings.
const LevelSharedUsers = 2

// LevelSharedSettings is the level from which the settings of the
// Settings page are kept in the shared settings.
const LevelSharedSettings = 3

// The names of the importers of users and of the directory sign-in
// settings in cluster.import.done: users become shared once both ran.
const (
	ImportUsers     = "users"
	ImportDirectory = "directory"
)

// ImportSettings is the name of the importer of the founder's settings in
// cluster.import.done: settings become shared once it ran.
const ImportSettings = "settings"

// Import states.
const (
	ImportImporting = "importing"
	ImportReady     = "ready"
)

// ImportState is how far the import of the founder's files has come.
// Done holds, per source, the hash of what was imported (or "none"), so
// an import cut short goes on from where it stopped.
type ImportState struct {
	State string            `json:"state"`
	By    string            `json:"by"`
	At    string            `json:"at"`
	Done  map[string]string `json:"done"`
	// Late is set when a server other than the founder ran imports added
	// after founding, because the founder was gone.
	Late  *LateImport `json:"late,omitempty"`
	Extra `json:"-"`
}

// LateImport records imports added after founding (by a newer version)
// that the server running the background jobs ran because the founder
// had not been seen for FounderGone: what was imported came from its
// files, not the founder's.
type LateImport struct {
	// By is the server that ran them, and ByID its node id.
	By      string   `json:"by"`
	ByID    string   `json:"by_id"`
	At      string   `json:"at"`
	Sources []string `json:"sources"`
	// Differ names the servers whose users and directory settings differ
	// from those of the server that ran them: they keep theirs only in
	// their files.
	Differ []string `json:"differ,omitempty"`
}

// MarshalJSON writes the state with the fields this version does not
// know.
func (s ImportState) MarshalJSON() ([]byte, error) {
	type plain ImportState
	return MarshalExtra(plain(s), s.Extra)
}

// UnmarshalJSON reads the state, keeping the fields this version does
// not know.
func (s *ImportState) UnmarshalJSON(data []byte) error {
	type plain ImportState
	var p plain
	extra, err := UnmarshalExtra(data, &p)
	*s = ImportState(p)
	s.Extra = extra
	return err
}

// ClusterBody is the body of the cluster document.
type ClusterBody struct {
	ClusterID string `json:"cluster_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	// CreatedBy is the founder's name, and CreatedByID its node id.
	CreatedBy   string      `json:"created_by"`
	CreatedByID string      `json:"created_by_id"`
	IndexPrefix string      `json:"index_prefix"`
	Level       int         `json:"level"`
	Import      ImportState `json:"import"`
	// Builtin is the user name of the built-in admin, set by the users
	// importer: it is fixed for the cluster from then on.
	Builtin string `json:"builtin,omitempty"`
	// BuiltinPrev is the built-in admin's name before a rename (signalith
	// cluster apply), set only while the rename is under way: until it is
	// cleared, a user document of either name may be the built-in admin.
	BuiltinPrev string `json:"builtin_prev,omitempty"`
	// Merged lists the servers whose files were merged in when they
	// joined (signalith join --merge).
	Merged map[string]json.RawMessage `json:"merged,omitempty"`
	// Migrations holds, per migration run once for the cluster, when it
	// ran.
	Migrations map[string]string `json:"migrations,omitempty"`
	Extra      `json:"-"`
}

// ErrClusterExists is a founding that found a cluster already there.
var ErrClusterExists = errors.New("the servers sharing this OpenSearch are a cluster already")

// LevelError is a cluster whose stored formats this version cannot use.
type LevelError struct {
	Level int
	// max is the highest level this version reads, LevelMax when 0.
	max int
}

func (e *LevelError) Error() string {
	top := cmp.Or(e.max, LevelMax)
	if e.Level > top {
		return fmt.Sprintf("the shared settings in OpenSearch are at level %d, which a newer version of Signalith wrote; this version reads up to level %d. "+
			"Install the version the other servers run, or a newer one", e.Level, top)
	}
	return fmt.Sprintf("the shared settings in OpenSearch are at level %d, which this version of Signalith no longer reads (it needs level %d or above). "+
		"Upgrade through the version named in the release notes first", e.Level, LevelMin)
}

// CheckLevel returns a *LevelError when level is outside what this
// version reads.
func CheckLevel(level int) error { return checkLevel(level, LevelMax) }

func checkLevel(level, top int) error {
	if level < LevelMin || level > top {
		return &LevelError{Level: level, max: top}
	}
	return nil
}

func newClusterID() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "c_" + hex.EncodeToString(b)
}

// Importer moves one source of the founder's files into the shared
// configuration, such as its feed list. Each is idempotent: it may run
// again after a crash, and what is already there counts as done.
type Importer struct {
	// Name is the source's name in cluster.import.done.
	Name string
	// Source returns a hash of what there is to import, "" for nothing.
	// An importer whose hash is recorded as done is not run again.
	Source func() (string, error)
	// Run imports it, by the user by.
	Run func(ctx context.Context, by string) error
	// MinLevel is the cluster level the importer needs (0 for any): one
	// whose content a server of a version that reads only lower levels
	// would ignore waits until the level is raised, and then runs as a
	// late import (Runtime.lateImports).
	MinLevel int
}

// importNone is recorded for a source that had nothing to import.
const importNone = "none"

// imports runs the importers not done yet, each after a check that this
// server may still change the shared settings (check: it still holds the
// job lease), and records each in the cluster document. An importer that
// needs a higher level than the cluster's waits for a late import.
func (rt *Runtime) imports(ctx context.Context, by string, check func(context.Context) error) error {
	h, cdoc := rt.Hub(), rt.Cluster()
	for _, im := range rt.opts.Importers {
		if err := rt.importOne(ctx, by, im, check); err != nil {
			return err
		}
	}
	_, err := cdoc.Mutate(ctx, by, func(b *ClusterBody) error {
		b.Import.State, b.Import.At = ImportReady, h.now()
		return nil
	})
	return err
}

// importOne runs the importer im unless what it would import is recorded
// as done, or the cluster's level is below what it needs, and records it.
func (rt *Runtime) importOne(ctx context.Context, by string, im Importer, check func(context.Context) error) error {
	cdoc := rt.Cluster()
	body, ok := cdoc.Get()
	if !ok {
		return errors.New("the cluster document cannot be read")
	}
	if im.MinLevel > body.Level {
		return nil
	}
	hash := importNone
	if im.Source != nil {
		h, err := im.Source()
		if err != nil {
			return fmt.Errorf("could not read what to import for %s: %w", im.Name, err)
		}
		if h != "" {
			hash = h
		}
	}
	if done, ok := body.Import.Done[im.Name]; ok && done == hash {
		return nil
	}
	if check != nil {
		if err := check(ctx); err != nil {
			return err
		}
	}
	if hash != importNone && im.Run != nil {
		if err := im.Run(ctx, by); err != nil {
			return fmt.Errorf("could not import %s: %w", im.Name, err)
		}
	}
	if _, err := cdoc.Mutate(ctx, by, func(b *ClusterBody) error {
		if b.Import.Done == nil {
			b.Import.Done = map[string]string{}
		}
		b.Import.Done[im.Name] = hash
		return nil
	}); err != nil {
		return err
	}
	rt.log.Info("imported into the shared settings", "source", im.Name)
	return nil
}

// FounderGone is how long the founder must have been unseen before the
// server that runs the background jobs runs, from its own files, the
// imports a newer version added after founding.
const FounderGone = 7 * 24 * time.Hour

// lateImports runs the importers a newer version added after the cluster
// was founded (their names are missing from cluster.import.done) once the
// cluster's level allows them. They import the founder's files, so the
// founder runs them while it is a member, whether or not it holds the
// job lease (each is idempotent, and done is recorded with a
// compare-and-set); when it has not been seen for FounderGone, the
// server that runs the background jobs does (lease: the caller holds
// the job lease), and the cluster document records that the servers
// whose users differ keep theirs only in their files.
func (rt *Runtime) lateImports(ctx context.Context, lease bool) error {
	cdoc := rt.Cluster()
	body, ok := cdoc.Get()
	if !ok || body.Import.State != ImportReady {
		return nil
	}
	var pending []Importer
	for _, im := range rt.opts.Importers {
		if _, done := body.Import.Done[im.Name]; !done && im.MinLevel <= body.Level {
			pending = append(pending, im)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	check := rt.opts.LeaseCheck
	if body.CreatedByID == rt.opts.Self.NodeID {
		check = nil
	} else {
		if !lease {
			return nil
		}
		peers, known := rt.peersSeen()
		if !known || !founderGone(peers, body.CreatedByID) {
			return nil
		}
		if check := rt.opts.LeaseCheck; check != nil {
			if err := check(ctx); err != nil {
				return err
			}
		}
		names := make([]string, 0, len(pending))
		for _, im := range pending {
			names = append(names, im.Name)
		}
		differ := usersDiffer(peers, rt.opts.Self.NodeID)
		if _, err := cdoc.Mutate(ctx, "signalith", func(b *ClusterBody) error {
			l := b.Import.Late
			if l == nil {
				l = &LateImport{}
			}
			l.By, l.ByID, l.At, l.Differ = rt.opts.Self.Name, rt.opts.Self.NodeID, rt.Hub().now(), differ
			for _, n := range names {
				if !slices.Contains(l.Sources, n) {
					l.Sources = append(l.Sources, n)
				}
			}
			b.Import.Late = l
			return nil
		}); err != nil {
			return err
		}
		founder := cmp.Or(body.CreatedBy, body.CreatedByID)
		rt.log.Warn("the server that founded the cluster has not been seen for 7 days, so this server imports its own files into the shared settings",
			"audit", true, "founder", founder, "sources", strings.Join(names, ","), "differ", strings.Join(differ, ","))
	}
	for _, im := range pending {
		if err := rt.importOne(ctx, "signalith", im, check); err != nil {
			return err
		}
	}
	return nil
}

// founderGone reports whether the founder nodeID has not been seen for
// FounderGone: its heartbeat is that old, or was removed (after a week).
func founderGone(peers []Peer, nodeID string) bool {
	for _, p := range peers {
		if p.NodeID == nodeID {
			return !p.Live && p.SeenAgo >= FounderGone
		}
	}
	return true
}

// usersDiffer names the servers whose fingerprint of their users and
// directory settings differs from server self's; servers of versions
// without one are left out.
func usersDiffer(peers []Peer, self string) []string {
	mine := ""
	for _, p := range peers {
		if p.NodeID == self {
			mine = p.Users
		}
	}
	var out []string
	for _, p := range peers {
		if p.NodeID != self && p.Users != "" && p.Users != mine {
			out = append(out, cmp.Or(p.Name, p.NodeID))
		}
	}
	slices.Sort(out)
	return out
}
