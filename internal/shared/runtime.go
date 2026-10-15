package shared

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Runtime is this server's place in the shared configuration: whether it
// is a member of the cluster and reads its settings from OpenSearch, or
// still uses its own files (legacy mode), and why. It owns the Hub with
// the cluster, keyring and nodecfg documents, runs the watcher, keeps
// cache.enc, founds the cluster when this server holds the job lease and
// no cluster exists yet, and joins it when it has the cluster key.
//
// It lives as long as the process, like the cluster node: an in-process
// restart only points it at the new OpenSearch client (Use). It knows
// nothing of the node itself and asks through the callbacks in
// RuntimeOptions, so the cluster package can ask it in turn.
type Runtime struct {
	opts  RuntimeOptions
	log   *slog.Logger
	clock Clock

	// stepMu lets one evaluation or watch cycle run at a time.
	stepMu sync.Mutex
	// running counts the loop and the cache writer, for Wait.
	running sync.WaitGroup

	mu       sync.Mutex
	client   *store.Client
	prefix   string
	master   Sealer
	hub      *Hub
	cluster  *Doc[ClusterBody]
	keyring  *Doc[KeyringBody]
	nodecfg  *Doc[NodeCfg]
	requests *Requests
	mode     Mode
	why      string
	// joined is true once this server checked the cluster document with
	// its key (or took a copy from cache.enc): from then on the watcher
	// reads the shared settings, rather than each step looking for the
	// cluster again.
	joined      bool
	provisional bool
	// addedBy is how this server got the cluster key, for the keyring.
	addedBy string
	// keysSig names the cluster keys in use, to notice new ones.
	keysSig     string
	listed      []string
	clusterID   string
	clusterName string
	level       int
	// contactAt is when OpenSearch last answered, on the monotonic clock,
	// and contacted whether it ever has.
	contactAt time.Duration
	contacted bool
	// noHolderSince is when no server that may run the background jobs
	// was seen up any more, on the monotonic clock (legacy c).
	noHolderSince *time.Duration
	holder        string
	cacheID       string
	cacheStop     context.CancelFunc
	cacheWriter   *CacheWriter
	ctx           context.Context
	onMode        []func(old, new Mode)
	fatal         chan error
	failed        bool
	wake          chan struct{}
	reqWake       chan struct{}
	// srvWake wakes the loop of the requests that name this server
	// (RunServerRequests), as reqWake wakes the leader's.
	srvWake chan struct{}
	// boot is this process's boot id, recorded with each request part it
	// claims, so the next process can tell a part it left running.
	boot          string
	started       bool
	keyFileWarned bool
	// fingerprint is this server's node key's, once read or made.
	fingerprint string
}

// Mode is how this server uses the shared configuration.
type Mode string

// Modes.
const (
	// ModeStarting is before this server first looked for the cluster.
	ModeStarting Mode = "starting"
	// ModeLegacyA: OpenSearch could not be reached at the first start
	// with this version, and there is no cache.enc: the server uses its
	// files.
	ModeLegacyA Mode = "legacy_a"
	// ModeLegacyB: a cluster exists, but this server has no key to it:
	// it was upgraded as the second server of a pair, or waits to join.
	ModeLegacyB Mode = "legacy_b"
	// ModeLegacyC: no cluster exists yet, and this server does not hold
	// the job lease, which the founder must.
	ModeLegacyC Mode = "legacy_c"
	// ModeImporting: this server founded the cluster and moves its files
	// into it.
	ModeImporting Mode = "importing"
	// ModeMember: this server reads the shared settings from OpenSearch.
	ModeMember Mode = "member"
	// ModeDegraded: a member that cannot use OpenSearch now: it serves the
	// copy it has, and changes are paused.
	ModeDegraded Mode = "degraded"
	// ModeKeyMissing: the shared settings are signed with a cluster key
	// this server does not have; it missed a key change.
	ModeKeyMissing Mode = "key_missing"
	// ModeGone: a member that finds the cluster document gone: the config
	// index was deleted or replaced. It never founds a new cluster.
	ModeGone Mode = "gone"
)

// SharedContent reports whether this server takes the content of the
// shared settings (feeds, retention policies) from OpenSearch rather than
// from its own files: it is a member, or was one and keeps its copy while
// it cannot use OpenSearch. While the founder is still moving its files
// into OpenSearch, every server uses its own files until that is done:
// the shared content is not all there yet.
func (rt *Runtime) SharedContent() bool {
	rt.mu.Lock()
	m, c := rt.mode, rt.cluster
	rt.mu.Unlock()
	switch m {
	case ModeMember, ModeDegraded, ModeKeyMissing, ModeGone:
	default:
		return false
	}
	b, ok := c.Get()
	return ok && b.Import.State != ImportImporting
}

// SharedUsers reports whether this server keeps the users, the directory
// sign-in settings and the sessions in the shared settings rather than in
// its own files: it takes the shared content, the cluster is at level 2
// (every server reads them), and the users and the directory settings
// were imported.
func (rt *Runtime) SharedUsers() bool {
	return rt.SharedContent() && rt.sharedAt(LevelSharedUsers, ImportUsers, ImportDirectory)
}

// SharedSettings reports whether this server takes the settings of the
// Settings page from the shared settings rather than from its own files:
// it keeps the users there, the cluster is at level 3 (every server reads
// them and runs the requests that name it), and the founder's settings
// were imported.
func (rt *Runtime) SharedSettings() bool {
	return rt.SharedUsers() && rt.sharedAt(LevelSharedSettings, ImportSettings)
}

// sharedAt reports whether a feature that comes with a cluster level is
// on: the cluster is at level or above, and the importers named imports
// ran. It says nothing of this server's mode, so a feature's gate chains
// it on another gate, such as SharedSettings.
func (rt *Runtime) sharedAt(level int, imports ...string) bool {
	b, ok := rt.Cluster().Get()
	if !ok || b.Level < level {
		return false
	}
	for _, name := range imports {
		if _, done := b.Import.Done[name]; !done {
			return false
		}
	}
	return true
}

// ImportStalled is how long the founder may take to move its files into
// OpenSearch before the other servers report it.
const ImportStalled = 30 * time.Minute

// importWarning is the warning of a member while the founder moves its
// files into OpenSearch, or nil.
func (rt *Runtime) importWarning() *Warning {
	b, ok := rt.Cluster().Get()
	if !ok || b.Import.State != ImportImporting || b.Import.By == rt.opts.Self.NodeID {
		return nil
	}
	who := b.Import.By
	if b.CreatedByID == b.Import.By && b.CreatedBy != "" {
		who = b.CreatedBy
	}
	if at, err := time.Parse(time.RFC3339Nano, b.Import.At); err == nil && rt.clock.Now().Sub(at) >= ImportStalled {
		return &Warning{Level: "red", Text: fmt.Sprintf("%s started moving its files into the shared settings at %s and has not finished, so this server still uses its own files. "+
			"It finishes only while %s runs the background jobs: make sure it is up, and if another server runs them, restart that one so %s takes them over.",
			who, b.Import.At, who, who),
			Banner: "The shared settings are not ready yet; this server uses its own files."}
	}
	return &Warning{Level: "amber", Text: fmt.Sprintf("Waiting for %s to finish moving its files into the shared settings; until then this server uses its own files.", who)}
}

// lateWarning is the warning of a late import from a server other than
// the founder, while servers whose users differ are named; nil otherwise.
func (rt *Runtime) lateWarning() *Warning {
	b, ok := rt.Cluster().Get()
	if !ok || b.Import.Late == nil || len(b.Import.Late.Differ) == 0 {
		return nil
	}
	l := b.Import.Late
	founder := cmp.Or(b.CreatedBy, b.CreatedByID)
	return &Warning{Level: "amber", Text: fmt.Sprintf("%s, which founded the cluster, had not been seen for 7 days, so %s put its own users and directory sign-in settings into the shared settings on %s. "+
		"Those of %s differ: their own users are kept only in their files.", founder, l.By, l.At, strings.Join(l.Differ, ", "))}
}

// founderWarning is the warning while imports a newer version added wait
// for the server that founded the cluster, which is down: it runs them
// once it is back, or the server that runs the background jobs does once
// it has not been seen for FounderGone. nil otherwise.
func (rt *Runtime) founderWarning() *Warning {
	b, ok := rt.Cluster().Get()
	if !ok || b.Import.State != ImportReady || b.CreatedByID == rt.opts.Self.NodeID {
		return nil
	}
	waiting := false
	for _, im := range rt.opts.Importers {
		if _, done := b.Import.Done[im.Name]; !done && im.MinLevel <= b.Level {
			waiting = true
		}
	}
	if !waiting {
		return nil
	}
	peers, known := rt.peersSeen()
	if !known || founderGone(peers, b.CreatedByID) {
		return nil
	}
	for _, p := range peers {
		if p.NodeID == b.CreatedByID && p.Live {
			return nil
		}
	}
	founder := cmp.Or(b.CreatedBy, b.CreatedByID)
	return &Warning{Level: "amber", Text: fmt.Sprintf("Users, sign-in and settings become shared once %s, which founded the cluster, is back: it brings in its users, directory sign-in settings and Settings page. "+
		"Until then each server keeps its own. If %s is gone for good, the server that runs the background jobs brings in its own once %s has not been seen for 7 days.", founder, founder, founder)}
}

// Writable says why the shared settings cannot be changed on this server
// now, or nil when they can: it must be a member that reads them from
// OpenSearch.
func (rt *Runtime) Writable() error {
	switch m, why := rt.Mode(); m {
	case ModeMember:
		return nil
	case ModeDegraded:
		return &PausedError{Why: why}
	default:
		return &PausedError{Why: m.Text()}
	}
}

// PausedError is a change of the shared settings asked while they cannot
// be changed on this server; the API answers it with 503.
type PausedError struct{ Why string }

func (e *PausedError) Error() string {
	if e.Why == "" {
		return "changes to the shared settings are paused on this server right now; try again in a moment"
	}
	return "changes to the shared settings are paused on this server right now (" + e.Why + "); try again in a moment"
}

// MovingError is a change of this server's own files refused while what
// they hold moves into the shared settings: the files were read for the
// move, and the restart that switches this server to the shared settings
// has not come yet, so a change saved in them would be lost. What names
// it, such as "users".
type MovingError struct{ What string }

func (e *MovingError) Error() string {
	return "this server is moving its " + e.What + " into the cluster; try again in a moment"
}

// Legacy reports whether a server in mode m uses its own files.
func (m Mode) Legacy() bool {
	return m == ModeLegacyA || m == ModeLegacyB || m == ModeLegacyC || m == ModeStarting
}

// Self is this server.
type Self struct {
	NodeID string
	Name   string
	// BootID is this process's boot id (the heartbeat's); a runtime
	// without one makes its own.
	BootID string
}

// Peer is a server as its heartbeat shows it, this one included.
type Peer struct {
	NodeID string
	Name   string
	// Live is true while its heartbeat moves.
	Live bool
	// Eligible is true when it may run the background jobs, and Leader
	// when it runs them.
	Eligible bool
	Leader   bool
	// MaxRev is the highest revision of a shared document it applied.
	MaxRev int64
	// LevelMax is the highest level its version reads, 0 for a version
	// that does not say (it reads level 1).
	LevelMax int
	// SeenAgo is how long ago its heartbeat stopped, 0 while it is live.
	SeenAgo time.Duration
	// Users is the fingerprint of its users and directory sign-in
	// settings, "" from versions without one.
	Users string
}

// RuntimeOptions are what a Runtime needs.
type RuntimeOptions struct {
	// StateDir is the state folder, which holds the keys and cache.enc.
	StateDir string
	Self     Self
	// KeyFile is SIGNALITH_CLUSTER_KEY_FILE: a server that has it is a
	// member, and may found the cluster with that key.
	KeyFile string
	// ClusterName is the name of a cluster this server founds.
	ClusterName string
	// HoldsLease reports whether this server holds the job lease now,
	// LeaseCheck confirms it before a change (nil: never; the command
	// line founds without), and LeaseEpoch is the lease's epoch.
	HoldsLease func() bool
	LeaseCheck func(ctx context.Context) error
	LeaseEpoch func() int64
	// Peers lists the servers as their heartbeats show them; nil knows
	// of none.
	Peers func() []Peer
	// Importers move the founder's files into the shared settings.
	Importers []Importer
	// Content makes the documents of the shared settings themselves (the
	// feed list, the retention policies) on each hub the runtime builds,
	// before cache.enc is read into it.
	Content func(h *Hub)
	// ReadOnly is for the command line: nothing is written, the cluster
	// is never founded, and no cache is kept.
	ReadOnly bool
	// DegradedAfter is how long OpenSearch may fail to answer before a
	// member counts as degraded; 0 is 15 seconds.
	DegradedAfter time.Duration
	Clock         Clock
	Timing        Timing
	Log           *slog.Logger

	// levelMax stands in for LevelMax, so tests can run a runtime of an
	// older version; 0 is LevelMax.
	levelMax int
}

// NoHolderWait is how long legacy mode waits for a server that may run
// the background jobs, and so found the cluster, before it names
// signalith cluster found.
const NoHolderWait = 10 * time.Minute

// NewRuntime returns the runtime; Use points it at OpenSearch and Start
// runs it.
func NewRuntime(o RuntimeOptions) *Runtime {
	if o.Clock == nil {
		o.Clock = realClock{start: time.Now()}
	}
	if o.Timing == (Timing{}) {
		o.Timing = DefaultTiming
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.ClusterName == "" {
		o.ClusterName = "Signalith"
	}
	if o.DegradedAfter == 0 {
		o.DegradedAfter = 15 * time.Second
	}
	rt := &Runtime{opts: o, log: o.Log, clock: o.Clock, mode: ModeStarting, fatal: make(chan error, 1),
		wake: make(chan struct{}, 1), reqWake: make(chan struct{}, 1), srvWake: make(chan struct{}, 1), boot: o.Self.BootID}
	if rt.boot == "" {
		rt.boot = newBootID()
	}
	rt.build()
	return rt
}

// build makes the hub and its documents. The caller holds rt.mu, or no
// one else has rt yet.
func (rt *Runtime) build() {
	h := NewHub(Options{NodeName: rt.opts.Self.Name, Clock: rt.opts.Clock, Timing: rt.opts.Timing, Log: rt.opts.Log})
	rt.hub = h
	rt.cluster = NewDoc[ClusterBody](h, ClusterDocID, "cluster", 1)
	rt.keyring = NewDoc[KeyringBody](h, KeyringDocID, "keyring", 1)
	rt.nodecfg = NewDoc[NodeCfg](h, NodeCfgID(rt.opts.Self.NodeID), NodeCfgKind, 1)
	rt.nodecfg.Local = true
	rt.requests = NewRequests(h, rt.opts.Self.NodeID)
	rt.requests.wake = rt.wakeRequests
	if rt.opts.Content != nil {
		rt.opts.Content(h)
	}
	h.Watch("requests", func(context.Context) error {
		rt.wakeRequests()
		return nil
	})
	rt.joined, rt.provisional, rt.keysSig, rt.listed = false, false, "", nil
	rt.clusterID, rt.clusterName, rt.level = "", "", 0
}

// Hub returns the hub of the shared documents.
func (rt *Runtime) Hub() *Hub {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.hub
}

// Cluster returns the cluster document.
func (rt *Runtime) Cluster() *Doc[ClusterBody] {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.cluster
}

// Keyring returns the keyring document.
func (rt *Runtime) Keyring() *Doc[KeyringBody] {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.keyring
}

// NodeCfg returns this server's nodecfg document.
func (rt *Runtime) NodeCfg() *Doc[NodeCfg] {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.nodecfg
}

// Requests returns the requests of this cluster.
func (rt *Runtime) Requests() *Requests {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.requests
}

// Mode returns the mode, and why when there is more to say.
func (rt *Runtime) Mode() (Mode, string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.mode, rt.why
}

// OnMode adds a function called after each change of mode.
func (rt *Runtime) OnMode(fn func(old, new Mode)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.onMode = append(rt.onMode, fn)
}

// Fatal receives an error when this server must not run: the cluster
// uses stored formats this version does not read.
func (rt *Runtime) Fatal() <-chan error { return rt.fatal }

func (rt *Runtime) keyStore() KeyStore {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return KeyStore{Dir: rt.opts.StateDir, Master: rt.master}
}

func (rt *Runtime) target() (*store.Client, string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.client, rt.prefix
}

func (rt *Runtime) setMode(m Mode, why string) {
	rt.mu.Lock()
	old := rt.mode
	rt.mode, rt.why = m, why
	subs := slices.Clone(rt.onMode)
	rt.mu.Unlock()
	if old == m {
		return
	}
	if why != "" {
		rt.log.Info("shared settings: "+m.Text(), "mode", string(m), "why", why)
	} else {
		rt.log.Info("shared settings: "+m.Text(), "mode", string(m))
	}
	for _, fn := range subs {
		fn(old, m)
	}
}

// Text says what mode m means, for the log.
func (m Mode) Text() string {
	switch m {
	case ModeLegacyA:
		return "OpenSearch could not be reached and there is no copy of the shared settings, so this server uses its own files"
	case ModeLegacyB:
		return "this server is not part of the cluster yet, so it uses its own files"
	case ModeLegacyC:
		return "no cluster exists yet; this server uses its own files until the server that runs the background jobs founds it"
	case ModeImporting:
		return "this server founded the cluster and moves its files into OpenSearch"
	case ModeMember:
		return "this server is a member of the cluster and reads the shared settings from OpenSearch"
	case ModeDegraded:
		return "this server cannot use the shared settings in OpenSearch now; it keeps the copy it has and changes are paused"
	case ModeKeyMissing:
		return "the shared settings are signed with a cluster key this server does not have"
	case ModeGone:
		return "the shared settings in OpenSearch are gone"
	}
	return "starting"
}

// Use points the runtime at an OpenSearch client and index prefix, with
// the master key that seals this server's keys and cache.enc, at each
// start of the server's components. Another prefix starts over. The first
// time, it puts cache.enc in use and looks for the cluster at once.
func (rt *Runtime) Use(c *store.Client, prefix string, master Sealer) {
	rt.stepMu.Lock()
	defer rt.stepMu.Unlock()
	rt.mu.Lock()
	first := rt.client == nil
	changed := !first && rt.prefix != prefix
	rt.client, rt.master = c, master
	if changed {
		rt.stopCacheLocked()
		rt.build()
		rt.mode, rt.why = ModeStarting, ""
	}
	rt.prefix = prefix
	h := rt.hub
	rt.mu.Unlock()
	h.Use(c, prefix)
	if first || changed {
		rt.restoreCache()
		// The mode is known before the components are built from it, but
		// founding, which may take a while, is left to the loop.
		ctx, cancel := context.WithTimeout(context.Background(), useWait)
		rt.stepLocked(ctx, false)
		cancel()
		return
	}
	rt.Kick()
}

// useWait bounds the first look for the cluster, which the start of the
// server's components waits for.
const useWait = 10 * time.Second

// Kick makes the runtime look again now.
func (rt *Runtime) Kick() {
	select {
	case rt.wake <- struct{}{}:
	default:
	}
}

// Start runs the runtime until ctx ends: it looks for the cluster, or
// reads the shared settings, every Timing.Poll.
func (rt *Runtime) Start(ctx context.Context) {
	rt.mu.Lock()
	if rt.started {
		rt.mu.Unlock()
		return
	}
	rt.started, rt.ctx = true, ctx
	id := rt.clusterID
	rt.mu.Unlock()
	if id != "" && !rt.opts.ReadOnly {
		rt.startCache(id)
	}
	rt.log.Info("shared settings watcher started")
	rt.running.Go(func() {
		for {
			rt.step(ctx)
			select {
			case <-ctx.Done():
				return
			case <-rt.wake:
			case <-rt.clock.After(rt.opts.Timing.Poll):
			}
		}
	})
}

// Wait waits, once the context Start got ended, for the loop and the
// writer of cache.enc to end; the writer saves what changed last first.
func (rt *Runtime) Wait() { rt.running.Wait() }

func (rt *Runtime) step(ctx context.Context) {
	rt.stepMu.Lock()
	defer rt.stepMu.Unlock()
	rt.stepLocked(ctx, true)
}

// stepLocked looks for the cluster, or reads the shared settings once.
// mayFound lets it found the cluster. The caller holds stepMu.
func (rt *Runtime) stepLocked(ctx context.Context, mayFound bool) {
	rt.mu.Lock()
	joined, failed, c := rt.joined, rt.failed, rt.client
	rt.mu.Unlock()
	if failed || c == nil || ctx.Err() != nil {
		return
	}
	if joined {
		rt.cycle(ctx)
		return
	}
	rt.evaluate(ctx, mayFound)
}

// localKeys are the cluster keys this server has.
type localKeys struct {
	stored []*ClusterKey
	// file is the key in SIGNALITH_CLUSTER_KEY_FILE.
	file *ClusterKey
	all  []*ClusterKey
	// cutShort are the stored keys of a founding that stopped before
	// the cluster document was made: no cluster ever had them.
	cutShort []*ClusterKey
}

func (k localKeys) get(kid string) *ClusterKey {
	for _, c := range k.all {
		if c.ID() == kid {
			return c
		}
	}
	return nil
}

// storedOther reports whether this server keeps a cluster key of a
// cluster it was a member of: one that is not the key file's, and not
// left by a founding cut short.
func (k localKeys) storedOther() bool {
	for _, c := range k.stored {
		if (k.file == nil || c.ID() != k.file.ID()) && !slices.Contains(k.cutShort, c) {
			return true
		}
	}
	return false
}

// foundingPath is the file that marks the cluster key kid as made by a
// founding whose cluster document is not known to exist yet. It is
// written before the key and removed once a cluster document signed with
// the key was seen, so a founding cut short (the server stopped, or
// OpenSearch failed) is not taken for a lost cluster.
func foundingPath(stateDir, kid string) string {
	return filepath.Join(stateDir, "cluster", "founding-"+kid)
}

// markFounding marks the key kid as being founded with.
func markFounding(stateDir, kid string) error {
	p := foundingPath(stateDir, kid)
	if err := securefile.MkdirPrivate(filepath.Dir(p)); err != nil {
		return err
	}
	return securefile.WriteFile(p, nil)
}

// founded removes the mark of the key kid: a cluster document signed
// with it exists.
func (rt *Runtime) founded(kid string) {
	if err := os.Remove(foundingPath(rt.opts.StateDir, kid)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		rt.log.Debug("could not remove the founding mark", "err", err)
	}
}

// readKeys reads the cluster keys in the state folder, and the key file.
// A key file that cannot be read is logged and left out.
func (rt *Runtime) readKeys() (localKeys, error) {
	var out localKeys
	ks := rt.keyStore()
	if ks.Master == nil {
		return out, nil
	}
	stored, err := ks.ClusterKeys()
	if err != nil {
		return out, err
	}
	out.stored = stored
	out.all = slices.Clone(stored)
	for _, k := range stored {
		if _, err := os.Stat(foundingPath(rt.opts.StateDir, k.ID())); err == nil {
			out.cutShort = append(out.cutShort, k)
		}
	}
	if p := rt.opts.KeyFile; p != "" {
		k, err := KeyFromFile(p)
		rt.mu.Lock()
		warned := rt.keyFileWarned
		rt.keyFileWarned = true
		rt.mu.Unlock()
		switch {
		case err != nil && !warned:
			rt.log.Error("the cluster key file cannot be used", "file", p, "err", err)
		case err == nil:
			if w := KeyFileWarning(p); w != "" && !warned {
				rt.log.Warn(w)
			}
			out.file = k
			if out.get(k.ID()) == nil {
				out.all = append(out.all, k)
			}
		}
	}
	return out, nil
}

// restoreCache puts cache.enc in use as a provisional copy, until
// OpenSearch answers.
func (rt *Runtime) restoreCache() {
	_, prefix := rt.target()
	path := CachePath(rt.opts.StateDir)
	id, pfx, err := CacheHeader(path)
	if err != nil || pfx != prefix {
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			rt.log.Warn("the copy of the shared settings cannot be read", "path", path, "err", err)
		}
		return
	}
	keys, err := rt.readKeys()
	if err != nil || len(keys.all) == 0 {
		return
	}
	ks := rt.keyStore()
	cache := Cache{Path: path, Master: ks.Master, ClusterID: id, Prefix: prefix}
	d, err := cache.Read(rt.clock.Now())
	if errors.Is(err, ErrCacheOld) {
		rt.log.Warn("the copy of the shared settings is older than 30 days, so it was removed", "path", path)
		_ = cache.Remove()
		return
	}
	if err != nil {
		rt.log.Warn("the copy of the shared settings cannot be used", "path", path, "err", err)
		return
	}
	var active *ClusterKey
	for _, cd := range d.Docs {
		var e Envelope
		if cd.ID == ClusterDocID && json.Unmarshal(cd.Source, &e) == nil {
			active = keys.get(macKID(e.MAC))
		}
	}
	if active == nil {
		return
	}
	rt.mu.Lock()
	h, doc := rt.hub, rt.cluster
	rt.mu.Unlock()
	h.SetKeys(NewKeySet(active))
	h.Restore(d)
	if body, ok := doc.Get(); ok {
		rt.mu.Lock()
		rt.joined, rt.provisional, rt.keysSig = true, true, active.ID()
		rt.clusterID, rt.clusterName, rt.level = body.ClusterID, body.Name, body.Level
		rt.mu.Unlock()
		rt.log.Info("using the copy of the shared settings until OpenSearch answers", "path", path, "written_at", d.WrittenAt)
	}
}

// hasCache reports whether this server keeps a cache.enc for the index
// prefix: it has been a member.
func (rt *Runtime) hasCache(prefix string) (string, bool) {
	id, pfx, err := CacheHeader(CachePath(rt.opts.StateDir))
	return id, err == nil && pfx == prefix
}

// unreachable is a look for the cluster that OpenSearch did not answer.
func (rt *Runtime) unreachable(err error) {
	m, _ := rt.Mode()
	why := "OpenSearch cannot be reached: " + store.Sentence(err.Error())
	switch m {
	case ModeStarting, ModeLegacyA:
		rt.setMode(ModeLegacyA, why)
	case ModeDegraded:
		rt.setMode(ModeDegraded, why)
	}
	// Legacy (b) and (c) go on with their files; the next look decides.
}

func (rt *Runtime) markContact() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.contactAt, rt.contacted = rt.clock.Mono(), true
}

// evaluate looks for the cluster: this server joins it when its key
// verifies the cluster document, founds it when there is none and it
// holds the job lease, and otherwise works out which legacy mode it is
// in.
func (rt *Runtime) evaluate(ctx context.Context, mayFound bool) {
	c, prefix := rt.target()
	keys, kerr := rt.readKeys()
	if kerr != nil {
		rt.setMode(ModeKeyMissing, "this server's cluster key cannot be opened: "+kerr.Error())
		return
	}
	ectx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !rt.opts.ReadOnly {
		if err := EnsureConfig(ectx, c, prefix); err != nil {
			rt.unreachable(err)
			return
		}
		// The sessions index is made here with its own mappings, before
		// the first sign-in: a session write must not make OpenSearch
		// create it with dynamic defaults, nor create it while writes to
		// the existing indices are refused. A sign-in still works without
		// it (Sessions.Create falls back as for any refused write), so a
		// failure is only logged.
		if err := EnsureSessions(ectx, c, prefix); err != nil {
			rt.log.Debug("could not make the sessions index", "index", SessionsIndex(prefix), "err", err)
		}
	}
	src, _, found, err := c.Get(ectx, ConfigIndex(prefix), ClusterDocID)
	if err != nil {
		rt.unreachable(err)
		return
	}
	rt.markContact()
	if !found {
		rt.noCluster(ctx, prefix, keys, mayFound)
		return
	}
	rt.mu.Lock()
	rt.noHolderSince = nil
	rt.mu.Unlock()
	var e Envelope
	if json.Unmarshal(src, &e) != nil {
		rt.setMode(ModeDegraded, "the cluster document in OpenSearch is not one Signalith wrote")
		return
	}
	if len(keys.all) == 0 {
		rt.notMember()
		return
	}
	var active *ClusterKey
	for _, k := range keys.all {
		if Verify(NewKeySet(k), ClusterDocID, &e) == nil && e.ID == ClusterDocID {
			active = k
			break
		}
	}
	if active == nil {
		err := Verify(NewKeySet(keys.all[0], keys.all[1:]...), ClusterDocID, &e)
		var uk *UnknownKeyError
		if errors.As(err, &uk) {
			// Not signed with a key this server has. A server that was a
			// member of this very cluster missed a key change; any other
			// is not part of it.
			var peek ClusterBody
			_ = json.Unmarshal([]byte(e.Body), &peek)
			if id, ok := rt.hasCache(prefix); ok && id != "" && id == peek.ClusterID {
				rt.setMode(ModeKeyMissing, err.Error())
				return
			}
			rt.notMember()
			return
		}
		rt.log.Error("config.tamper: the cluster document in OpenSearch was changed outside Signalith", "audit", true, "doc", ClusterDocID, "reason", err.Error())
		rt.setMode(ModeDegraded, "the cluster document in OpenSearch was changed outside Signalith ("+err.Error()+")")
		return
	}
	rt.join(ctx, active, keys)
}

// noCluster is a look that found no cluster document.
func (rt *Runtime) noCluster(ctx context.Context, prefix string, keys localKeys, mayFound bool) {
	_, cached := rt.hasCache(prefix)
	if cached || keys.storedOther() {
		// A member never founds a new cluster: the old one was lost.
		if active := rt.activeFor(keys); active != nil {
			rt.mu.Lock()
			rt.joined = true
			rt.mu.Unlock()
			rt.setKeys(active, keys, rt.listedKIDs())
		}
		rt.setMode(ModeGone, "")
		return
	}
	rt.setMode(ModeLegacyC, "")
	rt.noteHolder()
	if !mayFound || rt.opts.ReadOnly || !rt.holdsLease() {
		return
	}
	if err := rt.found(ctx, "signalith", false); err != nil && !errors.Is(err, ErrClusterExists) && ctx.Err() == nil {
		rt.log.Warn("could not found the cluster; trying again", "err", err)
	}
}

// activeFor picks the key a server that lost the cluster document signs
// with: the one of its cache, else the only one it has.
func (rt *Runtime) activeFor(keys localKeys) *ClusterKey {
	if k := rt.Hub().Keys().Active(); k != nil {
		return k
	}
	if len(keys.all) == 1 {
		return keys.all[0]
	}
	return nil
}

// noteHolder notes whether a server that may run the background jobs is
// up, for legacy (c)'s warning.
func (rt *Runtime) noteHolder() {
	var peers []Peer
	if rt.opts.Peers != nil {
		peers = rt.opts.Peers()
	}
	holder, up := "", false
	for _, p := range peers {
		if p.Live && p.Eligible {
			up = true
		}
		if p.Live && p.Leader {
			holder = p.Name
		}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.holder = holder
	switch {
	case up:
		rt.noHolderSince = nil
	case rt.noHolderSince == nil:
		now := rt.clock.Mono()
		rt.noHolderSince = &now
	}
}

// notMember is a look that found a cluster this server has no key to:
// legacy (b). Its node key is made now, so the Servers page can show the
// fingerprint an admin approves it by.
func (rt *Runtime) notMember() {
	rt.setMode(ModeLegacyB, "")
	if !rt.opts.ReadOnly {
		if _, err := rt.nodeKey(); err != nil {
			rt.log.Debug("could not make this server's node key", "err", err)
		}
	}
}

// nodeKey returns this server's node key, making it the first time, and
// keeps its fingerprint for Status.
func (rt *Runtime) nodeKey() (*NodeKey, error) {
	ks := rt.keyStore()
	if ks.Master == nil {
		return nil, errors.New("this server has no master key to keep its node key with")
	}
	nk, err := ks.NodeKey()
	if err != nil {
		return nil, err
	}
	rt.mu.Lock()
	rt.fingerprint = nk.Fingerprint()
	rt.mu.Unlock()
	return nk, nil
}

// setKeys gives the hub the cluster keys: active signs, and the other
// keys this server has that the keyring lists are accepted too (a key
// change in progress). It reports whether they changed.
func (rt *Runtime) setKeys(active *ClusterKey, keys localKeys, listed []string) bool {
	others := []*ClusterKey{}
	ids := []string{active.ID()}
	for _, k := range keys.all {
		if k.ID() != active.ID() && slices.Contains(listed, k.ID()) {
			others = append(others, k)
			ids = append(ids, k.ID())
		}
	}
	slices.Sort(ids[1:])
	sig := strings.Join(ids, ",")
	rt.mu.Lock()
	h := rt.hub
	same := rt.keysSig == sig && h.Keys().Active() != nil
	rt.keysSig = sig
	rt.mu.Unlock()
	if !same {
		h.SetKeys(NewKeySet(active, others...))
	}
	return !same
}

// listedKIDs are the ids of the keys the keyring in memory names.
func (rt *Runtime) listedKIDs() []string {
	if kr, ok := rt.Keyring().Get(); ok {
		return kr.KIDs()
	}
	return nil
}

// join makes this server a member with its key active.
func (rt *Runtime) join(ctx context.Context, active *ClusterKey, keys localKeys) {
	addedBy := AddedByImport
	if keys.file != nil && keys.file.ID() == active.ID() {
		addedBy = AddedByKeyFile
		if !rt.opts.ReadOnly && slices.IndexFunc(keys.stored, func(k *ClusterKey) bool { return k.ID() == active.ID() }) < 0 {
			if err := rt.keyStore().SaveClusterKey(active); err != nil {
				rt.log.Warn("could not keep the cluster key from the key file in the state folder", "err", err)
			}
		}
	}
	if !rt.opts.ReadOnly && slices.Contains(keys.cutShort, active) {
		rt.founded(active.ID())
	}
	rt.mu.Lock()
	rt.joined, rt.addedBy = true, addedBy
	rt.mu.Unlock()
	rt.setKeys(active, keys, rt.listedKIDs())
	rt.cycle(ctx)
}

// newKeys reads this server's cluster keys again, for a server that
// misses one: a key imported meanwhile (signalith cluster import-key) is
// used at once, and the key the keyring names as active signs when this
// server has it. It reports whether the keys changed.
func (rt *Runtime) newKeys() bool {
	active := rt.Hub().Keys().Active()
	if active == nil {
		return false
	}
	keys, err := rt.readKeys()
	if err != nil {
		return false
	}
	if kr, ok := rt.Keyring().Get(); ok && kr.Active != "" {
		if k := keys.get(kr.Active); k != nil {
			active = k
		}
	}
	return rt.setKeys(active, keys, rt.listedKIDs())
}

// cycle reads the shared settings once, and works out the mode from
// what it found.
func (rt *Runtime) cycle(ctx context.Context) {
	rt.mu.Lock()
	h := rt.hub
	rt.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := h.Cycle(cctx)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		rt.mu.Lock()
		down := !rt.contacted || rt.clock.Mono()-rt.contactAt >= rt.opts.DegradedAfter
		rt.mu.Unlock()
		if down {
			rt.setMode(ModeDegraded, "OpenSearch cannot be reached: "+store.Sentence(err.Error()))
		}
		rt.log.Debug("could not read the shared settings", "err", err)
		return
	}
	rt.markContact()
	rt.afterCycle(ctx)
}

// afterCycle works out the mode after a watch cycle, and does what a
// member does once: check the level, keep the keyring's list of keys,
// add itself to the keyring, finish an import, keep cache.enc.
func (rt *Runtime) afterCycle(ctx context.Context) {
	rt.mu.Lock()
	h, cdoc, kdoc := rt.hub, rt.cluster, rt.keyring
	rt.mu.Unlock()
	if cdoc.Missing() {
		rt.setMode(ModeGone, "")
		return
	}
	body, ok := cdoc.Get()
	if !ok {
		p := h.problemOf(ClusterDocID)
		switch {
		case p != nil && p.Kind == ProblemKeyMissing:
			rt.mu.Lock()
			rt.joined = false
			rt.mu.Unlock()
			rt.setMode(ModeKeyMissing, p.Reason)
		case p != nil:
			rt.setMode(ModeDegraded, "the cluster document in OpenSearch cannot be used: "+p.Reason)
		}
		return
	}
	if err := checkLevel(body.Level, rt.maxLevel()); err != nil {
		rt.fail(err)
		return
	}
	rt.mu.Lock()
	rt.clusterID, rt.clusterName, rt.level, rt.provisional = body.ClusterID, body.Name, body.Level, false
	addedBy := rt.addedBy
	rt.mu.Unlock()
	kr, kok := kdoc.Get()
	if kok {
		rt.useListed(kr.KIDs())
	}
	moved := kok && kr.Active != "" && h.Keys().Active() != nil && kr.Active != h.Keys().Active().ID()
	if (len(h.KeyMissing()) > 0 || moved) && rt.newKeys() {
		// Read everything again with the key found.
		rt.Kick()
	}
	if !rt.opts.ReadOnly {
		if _, listed := kr.Members[rt.opts.Self.NodeID]; !kok || !listed {
			if addedBy == "" {
				addedBy = AddedByImport
			}
			if err := rt.AddSelf(ctx, addedBy); err != nil {
				rt.log.Warn("could not add this server to the cluster's keyring; trying again", "err", err)
			}
		}
		if body.Import.State == ImportImporting && body.Import.By == rt.opts.Self.NodeID && rt.holdsLease() {
			rt.setMode(ModeImporting, "")
			if err := rt.imports(ctx, "signalith", rt.opts.LeaseCheck); err != nil {
				rt.log.Warn("could not finish moving this server's files into the shared settings; trying again", "err", err)
				return
			}
		}
		rt.startCache(body.ClusterID)
	}
	if km := h.KeyMissing(); len(km) > 0 {
		rt.setMode(ModeKeyMissing, "some shared settings are signed with a cluster key this server does not have: "+strings.Join(km, ", "))
		return
	}
	rt.setMode(ModeMember, "")
	if !rt.opts.ReadOnly {
		// The founder brings in its own files whether or not it runs the
		// background jobs: after a rolling upgrade another server may
		// keep them for good.
		lease := rt.holdsLease()
		if lease {
			rt.RaiseLevel(ctx)
		}
		if lease || body.CreatedByID == rt.opts.Self.NodeID {
			if err := rt.lateImports(ctx, lease); err != nil && ctx.Err() == nil {
				rt.log.Warn("could not finish importing into the shared settings; trying again", "err", err)
			}
		}
	}
}

func (rt *Runtime) holdsLease() bool { return rt.opts.HoldsLease != nil && rt.opts.HoldsLease() }

// useListed keeps the ids of the keys the keyring lists, so a document
// signed with one this server lacks counts as a missed key change.
func (rt *Runtime) useListed(kids []string) {
	rt.mu.Lock()
	same := slices.Equal(rt.listed, kids)
	rt.listed = kids
	h := rt.hub
	rt.mu.Unlock()
	if !same {
		h.SetListed(kids)
	}
}

// fail stops this server for good.
func (rt *Runtime) fail(err error) {
	rt.mu.Lock()
	already := rt.failed
	rt.failed = true
	rt.mu.Unlock()
	if already {
		return
	}
	rt.log.Error("this server cannot run with the shared settings in OpenSearch", "err", err)
	select {
	case rt.fatal <- err:
	default:
	}
}

// startCache keeps cache.enc for the cluster id from now on.
func (rt *Runtime) startCache(id string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.ctx == nil || rt.ctx.Err() != nil || rt.cacheID == id || rt.master == nil {
		return
	}
	rt.stopCacheLocked()
	ctx, cancel := context.WithCancel(rt.ctx)
	w := NewCacheWriter(rt.hub, Cache{Path: CachePath(rt.opts.StateDir), Master: rt.master, ClusterID: id, Prefix: rt.prefix})
	rt.cacheID, rt.cacheStop, rt.cacheWriter = id, cancel, w
	w.Changed()
	rt.running.Go(func() { w.Run(ctx) })
}

func (rt *Runtime) stopCacheLocked() {
	if rt.cacheStop != nil {
		rt.cacheStop()
	}
	rt.cacheID, rt.cacheStop, rt.cacheWriter = "", nil, nil
}

// FlushCache writes cache.enc now, when this server keeps one.
func (rt *Runtime) FlushCache() error {
	rt.mu.Lock()
	w := rt.cacheWriter
	rt.mu.Unlock()
	if w == nil {
		return nil
	}
	return w.Flush()
}

// errNotHolder is a founding by a server that does not hold the job
// lease.
var errNotHolder = errors.New("only the server that runs the background jobs may found the cluster")

// Found makes the servers sharing this OpenSearch a cluster, with this
// server's files as its settings, as "signalith cluster found" does (the
// caller checked that no other server may): no lease is needed.
func (rt *Runtime) Found(ctx context.Context, by string) error {
	rt.stepMu.Lock()
	defer rt.stepMu.Unlock()
	return rt.found(ctx, by, true)
}

// found founds the cluster: the cluster key is made (or taken from the
// key file) and kept in the state folder first, so a cluster never exists
// without a server that has its key; then the cluster document is
// created, which only one server can do; then the keyring, and the
// imports. Unless manual, this server must hold the job lease throughout.
func (rt *Runtime) found(ctx context.Context, by string, manual bool) error {
	keys, err := rt.readKeys()
	if err != nil {
		return err
	}
	if !manual && !rt.holdsLease() {
		return errNotHolder
	}
	k := keys.file
	if k == nil && len(keys.cutShort) > 0 {
		// A founding cut short before the cluster document was made left
		// its key: it is used again.
		k = keys.cutShort[0]
	}
	if k == nil && manual && len(keys.stored) == 1 {
		// "signalith cluster found" uses the only key there is.
		k = keys.stored[0]
	}
	if k == nil {
		if k, err = NewClusterKey(); err != nil {
			return err
		}
	}
	ks := rt.keyStore()
	if ks.Master == nil {
		return errors.New("this server has no master key to keep the cluster key with")
	}
	if _, err := rt.nodeKey(); err != nil {
		return fmt.Errorf("could not make this server's node key: %w", err)
	}
	// saved is a key this founding owns: made now, or left by a founding
	// cut short. It is removed when no cluster document is made with it.
	saved := slices.Contains(keys.cutShort, k)
	if slices.IndexFunc(keys.stored, func(s *ClusterKey) bool { return s.ID() == k.ID() }) < 0 {
		if err := markFounding(rt.opts.StateDir, k.ID()); err != nil {
			return fmt.Errorf("could not keep the cluster key: %w", err)
		}
		if err := ks.SaveClusterKey(k); err != nil {
			rt.founded(k.ID())
			return fmt.Errorf("could not keep the cluster key: %w", err)
		}
		saved = true
	}
	unsave := func() {
		if saved {
			_ = os.Remove(ClusterKeyPath(rt.opts.StateDir, k.ID()))
			rt.founded(k.ID())
		}
	}
	check := rt.opts.LeaseCheck
	if manual {
		check = nil
	}
	if check != nil {
		if err := check(ctx); err != nil {
			unsave()
			return err
		}
	}
	rt.mu.Lock()
	h, cdoc, prefix := rt.hub, rt.cluster, rt.prefix
	rt.mu.Unlock()
	prev, prevSig := h.Keys(), rt.keysSigNow()
	h.SetKeys(NewKeySet(k))
	now := h.now()
	body := &ClusterBody{ClusterID: newClusterID(), Name: rt.opts.ClusterName, CreatedAt: now,
		CreatedBy: rt.opts.Self.Name, CreatedByID: rt.opts.Self.NodeID, IndexPrefix: prefix, Level: rt.foundLevel(),
		Import: ImportState{State: ImportImporting, By: rt.opts.Self.NodeID, At: now, Done: map[string]string{}}}
	if _, err := cdoc.Create(ctx, by, body); err != nil {
		// An answer lost on the way may hide a document that was made:
		// look before giving the key up.
		made, there, lerr := false, errors.Is(err, store.ErrExists), error(nil)
		if !there {
			made, there, lerr = rt.madeWith(ctx, k, body.ClusterID)
		}
		if !made {
			h.SetKeys(prev)
			rt.mu.Lock()
			rt.keysSig = prevSig
			rt.mu.Unlock()
			if lerr != nil {
				// Unknown: the key and its mark stay, and the next look
				// decides (it joins when the document was made, else it
				// founds with the same key).
				return err
			}
			unsave()
			if there {
				rt.log.Info("another server founded the cluster first")
				rt.Kick()
				return ErrClusterExists
			}
			return err
		}
		if err := cdoc.Load(ctx); err != nil {
			rt.log.Debug("could not read the cluster document just made", "err", err)
		}
	}
	rt.founded(k.ID())
	addedBy := AddedByFounder
	rt.mu.Lock()
	rt.joined, rt.addedBy, rt.keysSig = true, addedBy, k.ID()
	rt.clusterID, rt.clusterName, rt.level = body.ClusterID, body.Name, body.Level
	rt.mu.Unlock()
	rt.setMode(ModeImporting, "")
	rt.log.Info("founded the cluster: the servers sharing this OpenSearch now keep their shared settings in it", "audit", true, "by", by,
		"cluster_id", body.ClusterID, "cluster_key", k.ID(), "index", ConfigIndex(prefix))
	if err := rt.AddSelf(ctx, addedBy); err != nil {
		return fmt.Errorf("founded the cluster, but could not write its keyring (it is written again): %w", err)
	}
	if err := rt.imports(ctx, by, check); err != nil {
		return fmt.Errorf("founded the cluster, but the import was cut short (it goes on): %w", err)
	}
	rt.cycle(ctx)
	return nil
}

// madeWith reads the cluster document after a create whose answer was
// lost: made is a document signed with k for the cluster id, there any
// cluster document at all.
func (rt *Runtime) madeWith(ctx context.Context, k *ClusterKey, clusterID string) (made, there bool, err error) {
	c, prefix := rt.target()
	src, _, found, err := c.Get(ctx, ConfigIndex(prefix), ClusterDocID)
	if err != nil || !found {
		return false, false, err
	}
	var e Envelope
	if json.Unmarshal(src, &e) != nil || Verify(NewKeySet(k), ClusterDocID, &e) != nil {
		return false, true, nil
	}
	var b ClusterBody
	if json.Unmarshal([]byte(e.Body), &b) != nil {
		return false, true, nil
	}
	return b.ClusterID == clusterID, true, nil
}

// ErrNotMember is a change of the shared settings asked of a server that
// is not a member of the cluster now.
var ErrNotMember = errors.New("this server is not a member of the cluster now")

// Migrate runs fn once for the whole cluster: unless the migration name
// is recorded in the cluster document, it runs fn (after a check that
// this server still holds the job lease) and records it. It reports
// whether fn ran. A server that is not a member gets ErrNotMember.
func (rt *Runtime) Migrate(ctx context.Context, name string, fn func(context.Context) error) (bool, error) {
	if m, _ := rt.Mode(); m != ModeMember {
		return false, ErrNotMember
	}
	cdoc := rt.Cluster()
	if body, ok := cdoc.Get(); !ok || body.Migrations[name] != "" {
		return false, nil
	}
	if check := rt.opts.LeaseCheck; check != nil {
		if err := check(ctx); err != nil {
			return false, err
		}
	}
	if err := fn(ctx); err != nil {
		return true, err
	}
	_, err := cdoc.Mutate(ctx, "signalith", func(b *ClusterBody) error {
		if b.Migrations == nil {
			b.Migrations = map[string]string{}
		}
		if b.Migrations[name] == "" {
			b.Migrations[name] = rt.Hub().now()
		}
		return nil
	})
	if err == nil {
		rt.log.Info("ran a migration of the cluster", "migration", name)
	}
	return true, err
}

// AcceptRestore makes every server accept the shared settings now in
// OpenSearch, after a snapshot was restored on purpose (see
// Hub.AcceptRestore); the other servers' highest revisions come from
// their heartbeats.
func (rt *Runtime) AcceptRestore(ctx context.Context, by string, peerMaxRev int64) error {
	rt.stepMu.Lock()
	defer rt.stepMu.Unlock()
	rt.mu.Lock()
	h, joined := rt.hub, rt.joined
	rt.mu.Unlock()
	if !joined {
		return ErrNotMember
	}
	if rt.opts.Peers != nil {
		for _, p := range rt.opts.Peers() {
			peerMaxRev = max(peerMaxRev, p.MaxRev)
		}
	}
	return h.AcceptRestore(ctx, by, peerMaxRev)
}

// Housekeep removes old tombstones and finished requests; the server that
// runs the background jobs calls it every 10 minutes.
func (rt *Runtime) Housekeep(ctx context.Context) {
	if m, _ := rt.Mode(); m != ModeMember || rt.opts.ReadOnly {
		return
	}
	rt.mu.Lock()
	h, reqs := rt.hub, rt.requests
	rt.mu.Unlock()
	now := rt.clock.Now()
	if n, err := reqs.Housekeep(ctx, now); err != nil {
		rt.log.Debug("could not remove old requests", "err", err)
	} else if n > 0 {
		rt.log.Info("removed finished requests older than 7 days", "requests", n)
	}
	if n, err := h.Housekeep(ctx, now); err != nil {
		rt.log.Debug("could not remove old tombstones", "err", err)
	} else if n > 0 {
		rt.log.Info("removed the records of items deleted more than 30 days ago", "items", n)
	}
	if rt.holdsLease() && rt.RaiseLevel(ctx) {
		// The loop runs the imports the new level allows.
		rt.Kick()
	}
}

// maxLevel is the highest level this version reads.
func (rt *Runtime) maxLevel() int { return cmp.Or(rt.opts.levelMax, LevelMax) }

// LevelSeen is how lately a server must have been seen for its version to
// count for the cluster's level: a server stopped for longer is expected
// to be upgraded before it comes back, and an older version then refuses
// to start.
const LevelSeen = 24 * time.Hour

// peersSeen lists the servers, this one included, as their heartbeats
// show them; known is false when there is no list yet (no heartbeat of
// this server among them), so nothing is decided from it.
func (rt *Runtime) peersSeen() (peers []Peer, known bool) {
	if rt.opts.Peers == nil {
		return nil, false
	}
	peers = rt.opts.Peers()
	return peers, slices.ContainsFunc(peers, func(p Peer) bool { return p.NodeID == rt.opts.Self.NodeID })
}

// lowestLevel is the highest level every server seen within LevelSeen
// reads, this one included; a server that does not say reads level 1.
func (rt *Runtime) lowestLevel(peers []Peer) int {
	low := rt.maxLevel()
	for _, p := range peers {
		if p.NodeID == rt.opts.Self.NodeID || !p.Live && p.SeenAgo >= LevelSeen {
			continue
		}
		low = min(low, max(p.LevelMax, LevelMin))
	}
	return low
}

// foundLevel is the level a cluster founded now starts at: the lowest
// that every server seen lately reads, so none of them stops.
func (rt *Runtime) foundLevel() int {
	var peers []Peer
	if rt.opts.Peers != nil {
		peers = rt.opts.Peers()
	}
	return rt.lowestLevel(peers)
}

// RaiseLevel raises the cluster's level by one when every server seen
// within LevelSeen reads the next level, and reports whether it did. The
// server that runs the background jobs calls it after each watch cycle
// and at housekeeping; the change is a compare-and-set, so two servers
// never raise it twice. The level's work (the late imports) runs after.
func (rt *Runtime) RaiseLevel(ctx context.Context) bool {
	if m, _ := rt.Mode(); m != ModeMember || rt.opts.ReadOnly {
		return false
	}
	cdoc := rt.Cluster()
	body, ok := cdoc.Get()
	if !ok || body.Level >= rt.maxLevel() {
		return false
	}
	peers, known := rt.peersSeen()
	if !known || rt.lowestLevel(peers) <= body.Level {
		return false
	}
	if check := rt.opts.LeaseCheck; check != nil {
		if err := check(ctx); err != nil {
			return false
		}
	}
	from := body.Level
	errRaised := errors.New("raised already")
	_, err := cdoc.Mutate(ctx, "signalith", func(b *ClusterBody) error {
		if b.Level != from {
			return errRaised
		}
		b.Level = from + 1
		return nil
	})
	if err != nil {
		if !errors.Is(err, errRaised) {
			rt.log.Warn("could not raise the level of the shared settings; trying again", "err", err)
		}
		return false
	}
	rt.mu.Lock()
	rt.level = from + 1
	rt.mu.Unlock()
	rt.log.Info("raised the level of the shared settings: every server seen in the last 24 hours reads it, and older versions no longer start",
		"audit", true, "from", from, "to", from+1)
	return true
}

// RunRequests runs the requests for the server that holds the job lease
// until ctx ends: when watch:requests changes, and every minute. It is one
// of the background jobs, so it runs on that server. Requests that name a
// server are left to RunServerRequests.
func (rt *Runtime) RunRequests(ctx context.Context, handlers map[string]Handler) {
	rt.runRequests(ctx, handlers, RunLeader, rt.reqWake)
}

// RunServerRequests runs the requests that name this server (such as its
// part of a restart of several servers, one at a time) until ctx ends:
// when watch:requests changes, and every minute. Unlike RunRequests it runs
// on every server, for as long as the process does, so an in-process
// restart run from it does not end it. A part of this server's that an
// earlier process left running (it stopped before the part was over) is
// failed, so a request in sequence does not go on past it.
func (rt *Runtime) RunServerRequests(ctx context.Context, handlers map[string]Handler) {
	rt.runRequests(ctx, handlers, RunServer, rt.srvWake)
}

func (rt *Runtime) runRequests(ctx context.Context, handlers map[string]Handler, only string, wake <-chan struct{}) {
	for {
		if m, _ := rt.Mode(); m == ModeMember {
			rn := &Runner{Requests: rt.Requests(), Handlers: handlers, Log: rt.log, Only: only, Boot: rt.boot,
				Lease: func() (int64, bool) {
					var e int64
					if rt.opts.LeaseEpoch != nil {
						e = rt.opts.LeaseEpoch()
					}
					return e, rt.holdsLease()
				},
				Offline: rt.offline}
			if _, err := rn.RunOnce(ctx); err != nil && ctx.Err() == nil {
				rt.log.Debug("could not read the requests", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-rt.clock.After(time.Minute):
		}
	}
}

// wakeRequests wakes the loops that run requests: one was made, or a
// part of one is over.
func (rt *Runtime) wakeRequests() {
	for _, ch := range []chan struct{}{rt.reqWake, rt.srvWake} {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// BootID returns this process's boot id, as recorded with the request
// parts it claims.
func (rt *Runtime) BootID() string { return rt.boot }

// Self returns this server's node id and name.
func (rt *Runtime) Self() Self {
	s := rt.opts.Self
	s.BootID = rt.boot
	return s
}

// offline reports whether server nodeID's heartbeat stopped.
func (rt *Runtime) offline(nodeID string) bool {
	if rt.opts.Peers == nil {
		return false
	}
	for _, p := range rt.opts.Peers() {
		if p.NodeID == nodeID {
			return !p.Live
		}
	}
	return true
}

// Ready reports whether a load balancer should send this server traffic
// as far as the shared settings go, and if not, why: the mode.
func (rt *Runtime) Ready() (bool, string) {
	m, _ := rt.Mode()
	switch m {
	case ModeDegraded, ModeKeyMissing, ModeGone, ModeStarting:
		return false, string(m)
	}
	return true, ""
}

// NotEligible says why this server may not run the background jobs now,
// as far as the shared settings go; "" when it may. It reads only what
// the runtime holds, so the node may ask while it holds its own lock.
func (rt *Runtime) NotEligible() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	switch rt.mode {
	case ModeLegacyA:
		return "it waits for OpenSearch to move its settings into it"
	case ModeLegacyB:
		return "it is not part of the cluster yet"
	case ModeKeyMissing:
		return "it missed a change of the cluster key"
	case ModeGone:
		return "the shared settings in OpenSearch are gone"
	case ModeDegraded:
		if rt.contacted && rt.clock.Mono()-rt.contactAt < rt.opts.DegradedAfter {
			// OpenSearch answers, but the shared settings cannot be used.
			return "the shared settings in OpenSearch cannot be used"
		}
	}
	return ""
}

// Status is the shared configuration as this server uses it.
type Status struct {
	Mode        Mode   `json:"mode"`
	Why         string `json:"why,omitempty"`
	ClusterID   string `json:"cluster_id,omitempty"`
	ClusterName string `json:"cluster_name,omitempty"`
	// ClusterKID is the id of the cluster key that signs.
	ClusterKID string `json:"cluster_kid,omitempty"`
	Level      int    `json:"level,omitempty"`
	LevelMin   int    `json:"level_min"`
	LevelMax   int    `json:"level_max"`
	// ConfigSeq is how far this server has read the config index, and
	// MaxRev the highest revision it applied.
	ConfigSeq    int64    `json:"config_seq"`
	MaxRev       int64    `json:"max_rev"`
	NeedsUpgrade []string `json:"needs_upgrade,omitempty"`
	Tamper       []string `json:"tamper,omitempty"`
	KeyMissing   []string `json:"key_missing,omitempty"`
	// Provisional is true while the settings in use come from cache.enc.
	Provisional bool `json:"provisional,omitempty"`
	// Fingerprint is this server's node key's, "" before it has one.
	Fingerprint string `json:"fingerprint,omitempty"`
	NotEligible string `json:"not_eligible,omitempty"`
}

// Status returns the shared configuration as this server uses it.
func (rt *Runtime) Status() Status {
	rt.mu.Lock()
	st := Status{Mode: rt.mode, Why: rt.why, ClusterID: rt.clusterID, ClusterName: rt.clusterName, Level: rt.level,
		LevelMin: LevelMin, LevelMax: rt.maxLevel(), Provisional: rt.provisional}
	h, joined, master, fp := rt.hub, rt.joined, rt.master, rt.fingerprint
	rt.mu.Unlock()
	st.NotEligible = rt.NotEligible()
	if joined {
		if k := h.Keys().Active(); k != nil {
			st.ClusterKID = k.ID()
		}
		st.ConfigSeq, st.MaxRev = h.Applied(), h.MaxRev()
		st.NeedsUpgrade, st.Tamper, st.KeyMissing = h.NeedsUpgrade(), h.Tamper(), h.KeyMissing()
	}
	if fp == "" && master != nil {
		// Read once; a server without one yet has none to show.
		if nk, err := (KeyStore{Dir: rt.opts.StateDir, Master: master}).LoadNodeKey(); err == nil {
			fp = nk.Fingerprint()
			rt.mu.Lock()
			rt.fingerprint = fp
			rt.mu.Unlock()
		}
	}
	st.Fingerprint = fp
	return st
}

// Warning is something about the shared settings an admin should know:
// red for a problem, amber for attention. Banner, on red ones, is a short
// form for every page.
type Warning struct {
	Level  string
	Text   string
	Banner string
}

// Warnings lists what an admin should know about the shared settings on
// this server.
func (rt *Runtime) Warnings() []Warning {
	st := rt.Status()
	rt.mu.Lock()
	holder := rt.holder
	since := rt.noHolderSince
	now := rt.clock.Mono()
	rt.mu.Unlock()
	var w []Warning
	switch st.Mode {
	case ModeLegacyA:
		w = append(w, Warning{Level: "amber", Text: "OpenSearch could not be reached when this server started, and it has no copy of the shared settings, so it uses its own files. " +
			"It moves its settings into OpenSearch once OpenSearch answers."})
	case ModeLegacyB:
		fp := ""
		if st.Fingerprint != "" {
			fp = " Its fingerprint is " + st.Fingerprint + "."
		}
		w = append(w, Warning{Level: "red", Text: "This server is not part of the cluster yet, so it uses its own files and runs no background jobs. " +
			"Give it the cluster key: export it on a member with signalith cluster export-key and run signalith cluster import-key here, or set SIGNALITH_CLUSTER_KEY_FILE. " +
			"It joins within seconds of having the key." + fp,
			Banner: "This server is not part of the cluster yet, so it runs no background jobs."})
	case ModeLegacyC:
		switch {
		case since != nil && now-*since >= NoHolderWait:
			w = append(w, Warning{Level: "red", Text: "No server that may run the background jobs has been up for 10 minutes, so nobody moves the shared settings into OpenSearch. " +
				"Start one, or run signalith cluster found on the server whose files should become the cluster's settings.",
				Banner: "Nobody moves the shared settings into OpenSearch."})
		case holder != "":
			w = append(w, Warning{Level: "amber", Text: fmt.Sprintf("Waiting for %s, which runs the background jobs, to move shared settings into OpenSearch.", holder)})
		}
	case ModeImporting:
		w = append(w, Warning{Level: "amber", Text: "This server is moving its settings into OpenSearch, to share them with the other servers."})
	case ModeDegraded:
		text := "The shared settings in OpenSearch cannot be used, so this server keeps the copy it has and changes are paused."
		if st.Why != "" {
			text += " " + store.Sentence(st.Why)
		}
		w = append(w, Warning{Level: "red", Text: text, Banner: "OpenSearch cannot be reached; changes are paused."})
	case ModeKeyMissing:
		w = append(w, Warning{Level: "red", Text: "The shared settings are signed with a cluster key this server does not have: it missed a change of the cluster key. " +
			"Import the current key (signalith cluster export-key on a member, then signalith cluster import-key here).",
			Banner: "This server missed a change of the cluster key, so it runs no background jobs."})
	case ModeGone:
		fix := "Restore them from this server's copy with signalith cluster import -from-cache; the other servers resume by themselves."
		_, prefix := rt.target()
		if _, ok := rt.hasCache(prefix); !ok {
			fix = "This server keeps no copy of them: restore them on a server that does (signalith cluster import -from-cache). " +
				"If none does, run signalith cluster found -force on the server whose files should become the shared settings."
		}
		w = append(w, Warning{Level: "red", Text: "The shared settings in OpenSearch are gone (their index was deleted or replaced). " + fix,
			Banner: "The shared settings in OpenSearch are gone."})
	}
	if st.Mode == ModeMember {
		if iw := rt.importWarning(); iw != nil {
			w = append(w, *iw)
		}
		if lw := rt.lateWarning(); lw != nil {
			w = append(w, *lw)
		}
		if fw := rt.founderWarning(); fw != nil {
			w = append(w, *fw)
		}
	}
	if len(st.Tamper) > 0 {
		w = append(w, Warning{Level: "red", Text: fmt.Sprintf("Shared settings were changed in OpenSearch outside Signalith (%s), so this server keeps its last good copy. "+
			"If a snapshot of OpenSearch was restored on purpose, run signalith cluster accept-restore.", strings.Join(st.Tamper, ", ")),
			Banner: "Shared settings were changed in OpenSearch outside Signalith."})
	}
	if len(st.NeedsUpgrade) > 0 {
		w = append(w, Warning{Level: "amber", Text: fmt.Sprintf("Some shared settings were written by a newer version of Signalith (%s), so this server keeps its last good copy. Upgrade it.",
			strings.Join(st.NeedsUpgrade, ", "))})
	}
	return w
}

func (rt *Runtime) keysSigNow() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.keysSig
}
