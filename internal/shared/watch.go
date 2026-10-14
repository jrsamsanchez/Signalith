package shared

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Clock tells the time. cluster.Clock and the tests' ostest.Clock have
// these methods.
type Clock interface {
	// Now is the wall-clock time, written into documents for people to
	// read.
	Now() time.Time
	// Mono is the time on a clock that only moves forward.
	Mono() time.Duration
	// After receives once d has passed.
	After(d time.Duration) <-chan time.Time
}

type realClock struct{ start time.Time }

func (realClock) Now() time.Time                         { return time.Now().Round(0) }
func (c realClock) Mono() time.Duration                  { return time.Since(c.start) }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Timing holds the intervals of the shared configuration. The defaults
// are the design's; tests shorten them.
type Timing struct {
	// Poll is how often the versions are read, and Resync how often
	// every collection is listed again in full, as a safety net.
	Poll, Resync time.Duration
	// Wait is how long an API request that names a newer configuration
	// than this server has waits for it (see Hub.Wait).
	Wait time.Duration
	// CacheEvery is how often, at most, cache.enc is written.
	CacheEvery time.Duration
}

// DefaultTiming is the timing servers run with.
var DefaultTiming = Timing{Poll: 2 * time.Second, Resync: 5 * time.Minute, Wait: time.Second, CacheEvery: 10 * time.Second}

// Problem kinds.
const (
	// ProblemTamper is a document changed or forged outside Signalith, an
	// older revision written back (a rollback), or a document that
	// vanished without a tombstone.
	ProblemTamper = "tamper"
	// ProblemUpgrade is a document of a kind or format this version does
	// not know: a newer version wrote it.
	ProblemUpgrade = "needs_upgrade"
	// ProblemKeyMissing is a document signed with a cluster key the
	// keyring lists but this server does not have: it missed a key
	// change.
	ProblemKeyMissing = "key_missing"
	// ProblemInvalid is a signed document whose body this version cannot
	// use.
	ProblemInvalid = "invalid"
)

// Problem is a document the server does not use: it keeps its last good
// copy instead.
type Problem struct {
	ID     string    `json:"id"`
	Kind   string    `json:"kind"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
	// ver is the version reported, so that one is logged once.
	ver store.Version
}

// ProblemError is a write refused because the document has a problem.
type ProblemError struct{ Problem }

func (e *ProblemError) Error() string {
	return fmt.Sprintf("%s cannot be changed now: %s", e.ID, e.Reason)
}

// Options are what a Hub needs.
type Options struct {
	// NodeName is this server's name, written as updated_by.node.
	NodeName string
	Clock    Clock
	Timing   Timing
	Log      *slog.Logger
}

// tracked is a single document the watcher follows.
type tracked interface {
	docID() string
	// gen is a counter that moves on every change applied, so a read
	// made before a change is not applied after it.
	gen() uint64
	// apply checks a copy read from the index uuid and uses it, or
	// refuses it. It reports false when it left the copy alone because
	// gen moved: that copy must be read again.
	apply(d store.Doc, uuid string, gen uint64) bool
	reload(ctx context.Context) error
	cached() []CacheDoc
	// local is a document only this server tracks (see Doc.Local): its
	// _seq_no is left out of the token.
	local() bool
}

// collection is a collection the watcher reloads when its watch
// document changes.
type collection interface {
	watchID() string
	// reload lists the collection again. It reports false when an item
	// read was left alone because it changed meanwhile, so the listing
	// must be done again.
	reload(ctx context.Context) (bool, error)
	owns(id string) bool
	restore(d store.Doc, uuid string)
	cached() []CacheDoc
}

// Hub is this server's copy of the shared configuration: it holds the
// cluster keys, follows the documents and collections made on it, refuses
// copies that fail their checks, and says how far it has read (Token).
//
// Every 2 seconds one _mget without sources reads the versions of the
// tracked documents and of the watch documents (watch:<name>, unsigned
// counters each collection write bumps). A version that differs from the
// last one seen (never "is greater", so an index made again still
// reloads) is read in full and checked; a changed watch document makes
// its collections list their items again. A server's own writes are
// applied at once.
type Hub struct {
	opts  Options
	clock Clock
	log   *slog.Logger

	// cycling holds a token while a watch cycle runs, so one runs at a
	// time and a request waiting for its turn can give up (Wait).
	cycling chan struct{}

	mu     sync.Mutex
	client *store.Client
	prefix string
	keys   *KeySet
	listed map[string]bool
	uuid   string
	// applied is how far this server has read, as a _seq_no: the highest
	// one among the versions of a cycle that applied (or refused) every
	// change it found, so every write up to it is reflected here. Only the
	// watcher moves it; -1 before any (the first document of an index has
	// 0).
	applied int64
	// written is the highest _seq_no of this server's own writes of
	// tracked or watch documents in the index of writtenUUID, for the
	// token of the answer to a request that wrote (Written).
	written     int64
	writtenUUID string
	// seen is the last version read of each tracked document; a missing
	// entry was never read, a zero version was read missing.
	seen     map[string]store.Version
	floors   map[string]int64
	problems map[string]*Problem
	singles  map[string]tracked
	colls    []collection
	resyncAt time.Duration
	// changed is called after anything new was applied (cache.enc).
	changed func()
	// confirmed is when a cycle last read everything it found, on the
	// wall clock, or when the cache.enc restored was written.
	confirmed time.Time
}

// NewHub returns a hub; Use points it at OpenSearch.
func NewHub(opts Options) *Hub {
	if opts.Clock == nil {
		opts.Clock = realClock{start: time.Now()}
	}
	if opts.Timing == (Timing{}) {
		opts.Timing = DefaultTiming
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	return &Hub{opts: opts, clock: opts.Clock, log: opts.Log, applied: -1, cycling: make(chan struct{}, 1), seen: map[string]store.Version{}, floors: map[string]int64{},
		problems: map[string]*Problem{}, singles: map[string]tracked{}, listed: map[string]bool{}}
}

// Use points the hub at an OpenSearch client and index prefix; an
// in-process restart calls it again with the new client.
func (h *Hub) Use(c *store.Client, prefix string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if prefix != h.prefix {
		h.uuid, h.applied, h.seen = "", -1, map[string]store.Version{}
	}
	h.client, h.prefix = c, prefix
}

// SetKeys sets the cluster keys. Every document is read again at the
// next cycle, so one refused for a key this server lacked is used now.
func (h *Hub) SetKeys(k *KeySet) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keys = k
	h.seen = map[string]store.Version{}
}

// Keys returns the cluster keys.
func (h *Hub) Keys() *KeySet {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.keys
}

// SetListed sets the ids of the cluster keys the keyring lists. A
// document signed with one of them that this server lacks means it missed
// a key change, not that someone forged it.
func (h *Hub) SetListed(kids []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.listed = map[string]bool{}
	for _, k := range kids {
		h.listed[k] = true
	}
	h.seen = map[string]store.Version{}
}

// OnApplied sets a function called after something new was applied.
func (h *Hub) OnApplied(fn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.changed = fn
}

func (h *Hub) target() (*store.Client, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.client, h.prefix
}

func (h *Hub) index() string {
	_, p := h.target()
	return ConfigIndex(p)
}

// indexUUID returns the uuid of the config index, reading it when this
// server has not yet. Copies are told apart by it as well as by their
// version, which starts over in an index made again.
func (h *Hub) indexUUID(ctx context.Context) (string, error) {
	h.mu.Lock()
	u, c, prefix := h.uuid, h.client, h.prefix
	h.mu.Unlock()
	if u != "" {
		return u, nil
	}
	u, err := IndexUUID(ctx, c, prefix)
	if err != nil {
		return "", err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.uuid == "" && h.prefix == prefix {
		h.uuid = u
	}
	return u, nil
}

func (h *Hub) track(t tracked) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.singles[t.docID()] = t
}

func (h *Hub) trackCollection(c collection) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.colls = append(h.colls, c)
}

// now is the time written into a document.
func (h *Hub) now() string { return h.clock.Now().UTC().Format(time.RFC3339Nano) }

// open checks a stored copy of document id: a document Signalith wrote,
// signed with a cluster key this server has, of the kind expected and a
// format this version reads. The revision is checked by the caller.
func (h *Hub) open(id, kind string, format int, src json.RawMessage) (*Envelope, *Problem) {
	var e Envelope
	if err := json.Unmarshal(src, &e); err != nil {
		return nil, &Problem{Kind: ProblemTamper, Reason: "it is not a document Signalith wrote"}
	}
	h.mu.Lock()
	keys, listed := h.keys, h.listed
	h.mu.Unlock()
	if keys.Active() == nil {
		return nil, &Problem{Kind: ProblemKeyMissing, Reason: "this server has no cluster key"}
	}
	err := Verify(keys, id, &e)
	var uk *UnknownKeyError
	switch {
	case errors.Is(err, ErrNewerMAC):
		// The form is not covered by any MAC, so anyone who can write to
		// OpenSearch could put one there: it is never trusted to mean
		// "upgrade". A newer version that adds a form says so in a signed
		// document (the cluster level) first.
		return nil, &Problem{Kind: ProblemTamper, Reason: "it was changed in OpenSearch outside Signalith, or written by a newer version of Signalith (" + err.Error() + ")"}
	case errors.As(err, &uk) && listed[uk.KID]:
		return nil, &Problem{Kind: ProblemKeyMissing, Reason: err.Error()}
	case err != nil:
		return nil, &Problem{Kind: ProblemTamper, Reason: "it was changed in OpenSearch outside Signalith (" + err.Error() + ")"}
	case e.ID != id:
		return nil, &Problem{Kind: ProblemTamper, Reason: "it holds the id " + e.ID}
	case e.Kind != kind:
		return nil, &Problem{Kind: ProblemUpgrade, Reason: fmt.Sprintf("it is of kind %q, which this version of Signalith does not know", e.Kind)}
	case e.Format > format:
		return nil, &Problem{Kind: ProblemUpgrade, Reason: fmt.Sprintf("it is in format %d; this version of Signalith reads up to %d", e.Format, format)}
	case e.Format < 1:
		return nil, &Problem{Kind: ProblemTamper, Reason: "it has no format"}
	}
	return &e, nil
}

// checkRev refuses a revision older than the one applied: a copy written
// back from before.
func (h *Hub) checkRev(id string, rev int64) *Problem {
	h.mu.Lock()
	floor := h.floors[id]
	h.mu.Unlock()
	if rev < floor {
		return &Problem{Kind: ProblemTamper, Reason: fmt.Sprintf("it was rolled back to revision %d; revision %d was applied before", rev, floor)}
	}
	return nil
}

// report records a problem with document id at version v and logs it the
// first time. A tampered document is an audit event.
func (h *Hub) report(id string, p *Problem, v store.Version) {
	h.mu.Lock()
	old := h.problems[id]
	p.ID, p.ver = id, v
	if old != nil && old.Kind == p.Kind && old.Reason == p.Reason && old.ver.Same(v) {
		h.mu.Unlock()
		return
	}
	p.At = h.clock.Now()
	h.problems[id] = p
	h.mu.Unlock()
	switch p.Kind {
	case ProblemTamper:
		h.log.Error("config.tamper: a shared setting was changed in OpenSearch outside Signalith; the last good copy stays in use",
			"audit", true, "doc", id, "reason", p.Reason, "seq_no", v.SeqNo)
	case ProblemUpgrade:
		h.log.Warn("a shared setting was written by a newer version of Signalith; upgrade this server. The last good copy stays in use",
			"doc", id, "reason", p.Reason)
	default:
		h.log.Warn("a shared setting cannot be used; the last good copy stays in use", "doc", id, "kind", p.Kind, "reason", p.Reason)
	}
}

// fine forgets the problem with document id and records rev as applied.
// It returns the function to call once the caller has let go of its
// locks, or nil.
func (h *Hub) fine(id string, rev int64) func() {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.problems, id)
	if rev > h.floors[id] {
		h.floors[id] = rev
	}
	return h.changed
}

// problemOf returns the problem with document id, or nil.
func (h *Hub) problemOf(id string) *Problem {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p := h.problems[id]; p != nil {
		c := *p
		return &c
	}
	return nil
}

// Problems lists the documents not in use, by id.
func (h *Hub) Problems() []Problem {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []Problem
	for _, p := range h.problems {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (h *Hub) problemIDs(kind string) []string {
	var out []string
	for _, p := range h.Problems() {
		if p.Kind == kind {
			out = append(out, p.ID)
		}
	}
	return out
}

// Tamper lists the documents changed outside Signalith, rolled back or
// gone without a tombstone.
func (h *Hub) Tamper() []string { return h.problemIDs(ProblemTamper) }

// NeedsUpgrade lists the documents a newer version of Signalith wrote.
func (h *Hub) NeedsUpgrade() []string { return h.problemIDs(ProblemUpgrade) }

// KeyMissing lists the documents signed with a cluster key this server
// missed.
func (h *Hub) KeyMissing() []string { return h.problemIDs(ProblemKeyMissing) }

// firstRev is the revision a new document id is written at: above any
// revision this server applied to it before, so an item deleted, its
// tombstone housekept, and made again does not look like a rollback to
// the servers that saw the tombstone. For an item (all), it is above
// every revision applied here too: a server that never saw the tombstone
// cannot know its revision, and this makes it very likely to be above.
func (h *Hub) firstRev(id string, all bool) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.floors[id]
	if all {
		for _, f := range h.floors {
			r = max(r, f)
		}
	}
	return r + 1
}

// Confirmed returns when this server last read the shared settings in
// full from OpenSearch (or when the cache.enc it started from was
// written), so a copy kept while OpenSearch cannot be used can be judged
// by its age; zero before either.
func (h *Hub) Confirmed() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.confirmed
}

// Applied returns how far this server has read the config index, as a
// _seq_no (see Token); -1 before it has read anything.
func (h *Hub) Applied() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.applied
}

// Housekeep removes the tombstones of every collection that are older
// than TombstoneAge at now. It returns how many.
func (h *Hub) Housekeep(ctx context.Context, now time.Time) (int, error) {
	h.mu.Lock()
	cols := slices.Clone(h.colls)
	h.mu.Unlock()
	n := 0
	var errs []error
	for _, col := range cols {
		hk, ok := col.(interface {
			Housekeep(context.Context, time.Time) (int, int64, error)
		})
		if !ok {
			continue
		}
		k, _, err := hk.Housekeep(ctx, now)
		n += k
		if err != nil {
			errs = append(errs, err)
		}
	}
	return n, errors.Join(errs...)
}

// MaxRev returns the highest revision applied of any document.
func (h *Hub) MaxRev() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	var m int64
	for _, r := range h.floors {
		m = max(m, r)
	}
	return m
}

// ownWrite records this server's write of a tracked document id, so the
// watcher does not read it back. It does not move applied: writes of
// other servers before it may not be read yet.
func (h *Hub) ownWrite(id string, v store.Version) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seen[id] = v
}

// bump rewrites the watch document id, so every server reloads what it
// watches. When nobody else bumped it since this server last read it,
// this server, which applied its own change already, has nothing to
// reload. fields, when set, are added to the body. It returns the bump's
// _seq_no.
func (h *Hub) bump(ctx context.Context, id string, fields map[string]any) (int64, error) {
	c, prefix := h.target()
	var out struct {
		SeqNo       int64 `json:"_seq_no"`
		PrimaryTerm int64 `json:"_primary_term"`
		Version     int64 `json:"_version"`
	}
	index := ConfigIndex(prefix)
	body := map[string]any{}
	maps.Copy(body, fields)
	body["kind"], body["id"], body["at"] = "watch", id, h.now()
	err := c.Do(ctx, http.MethodPut, "/"+url.PathEscape(index)+"/_doc/"+url.PathEscape(id), body, &out)
	if err != nil {
		return 0, fmt.Errorf("could not tell the other servers about the change (%s): %w", id, err)
	}
	v := store.Version{SeqNo: out.SeqNo, PrimaryTerm: out.PrimaryTerm, Version: out.Version}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.wroteLocked(h.uuid, v.SeqNo)
	if last, ok := h.seen[id]; ok && last.Version+1 == v.Version && last.PrimaryTerm == v.PrimaryTerm {
		h.seen[id] = v
	}
	return v.SeqNo, nil
}

// Start runs the watcher until ctx ends.
func (h *Hub) Start(ctx context.Context) {
	go func() {
		for {
			if err := h.Cycle(ctx); err != nil && ctx.Err() == nil {
				h.log.Debug("could not read the shared settings", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-h.clock.After(h.opts.Timing.Poll):
			}
		}
	}()
}

// Kick runs one watch cycle now, for a request that waits for a change.
func (h *Hub) Kick(ctx context.Context) error { return h.Cycle(ctx) }

// Cycle reads the versions of everything tracked and applies what
// changed; every Resync it reads every document and lists every
// collection again too. Once a cycle has applied or refused every change
// it found, applied moves to the highest _seq_no it read: the config
// index has one shard, so every write up to that one is reflected.
func (h *Hub) Cycle(ctx context.Context) error {
	select {
	case h.cycling <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-h.cycling }()
	h.mu.Lock()
	c, prefix := h.client, h.prefix
	if c == nil {
		h.mu.Unlock()
		return errors.New("no OpenSearch")
	}
	full := h.clock.Mono() >= h.resyncAt
	if full {
		h.resyncAt = h.clock.Mono() + h.opts.Timing.Resync
	}
	index := ConfigIndex(prefix)
	var refs []store.Ref
	gens := map[string]uint64{}
	singles := maps.Clone(h.singles)
	for id := range singles {
		refs = append(refs, store.Ref{Index: index, ID: id})
	}
	watches := map[string][]collection{}
	for _, col := range h.colls {
		if _, ok := watches[col.watchID()]; !ok {
			refs = append(refs, store.Ref{Index: index, ID: col.watchID()})
		}
		watches[col.watchID()] = append(watches[col.watchID()], col)
	}
	h.mu.Unlock()
	// A document's lock is never taken under h.mu.
	for id, t := range singles {
		gens[id] = t.gen()
	}

	// The uuid is read every cycle, before the versions: an index made
	// again can hold documents at the very versions of the old one.
	uuid, err := IndexUUID(ctx, c, prefix)
	if err != nil {
		return err
	}
	h.mu.Lock()
	if uuid != h.uuid {
		// The index was made again: its sequence numbers start over.
		h.uuid, h.applied, h.seen = uuid, -1, map[string]store.Version{}
	}
	h.mu.Unlock()
	vers, err := c.MGetVersions(ctx, refs)
	if err != nil {
		return err
	}

	// Single documents: fetch the changed ones in one request.
	complete := true
	var fetch []store.Ref
	h.mu.Lock()
	for _, r := range refs {
		if h.singles[r.ID] == nil {
			continue
		}
		if last, ok := h.seen[r.ID]; full || !ok || !last.Same(vers[r]) {
			fetch = append(fetch, r)
		}
	}
	h.mu.Unlock()
	docs, err := c.MGet(ctx, fetch)
	if err != nil {
		return err
	}
	for _, d := range docs {
		h.mu.Lock()
		t := h.singles[d.ID]
		h.mu.Unlock()
		if !t.apply(d, uuid, gens[d.ID]) {
			// Left for the next cycle, which reads it again.
			complete = false
			continue
		}
		h.mu.Lock()
		h.seen[d.ID] = d.Version
		h.mu.Unlock()
	}

	// Collections: list again those whose watch document changed.
	var errs []error
	for wid, cols := range watches {
		r := store.Ref{Index: index, ID: wid}
		h.mu.Lock()
		last, ok := h.seen[wid]
		h.mu.Unlock()
		if ok && last.Same(vers[r]) && !full {
			continue
		}
		done := true
		for _, col := range cols {
			all, err := col.reload(ctx)
			if err != nil {
				errs = append(errs, err)
			}
			if all && err == nil {
				continue
			}
			done = false
			if _, ok := col.(watchFunc); !ok {
				// A collection not read holds the token back; work
				// a watch function starts (requests) is not part of it.
				complete = false
			}
		}
		if !done {
			continue
		}
		h.mu.Lock()
		h.seen[wid] = vers[r]
		h.mu.Unlock()
	}
	if complete {
		// Documents only this server tracks are left out: the other
		// servers never read them, so they could not reach the token.
		top := int64(-1)
		for r, v := range vers {
			if t := singles[r.ID]; !v.IsZero() && (t == nil || !t.local()) {
				top = max(top, v.SeqNo)
			}
		}
		h.mu.Lock()
		if h.uuid == uuid {
			h.applied = max(h.applied, top)
		}
		h.confirmed = h.clock.Now()
		h.mu.Unlock()
	}
	return errors.Join(errs...)
}

// Snapshot returns what cache.enc keeps: every document applied, with
// its version, and the revisions applied.
func (h *Hub) Snapshot() CacheData {
	h.mu.Lock()
	singles := make([]tracked, 0, len(h.singles))
	for _, t := range h.singles {
		singles = append(singles, t)
	}
	cols := slices.Clone(h.colls)
	d := CacheData{IndexUUID: h.uuid, AppliedSeq: h.applied, Floors: map[string]int64{}, WrittenAt: h.clock.Now().UTC()}
	for id, r := range h.floors {
		d.Floors[id] = r
		d.MaxRev = max(d.MaxRev, r)
	}
	h.mu.Unlock()
	for _, t := range singles {
		d.Docs = append(d.Docs, t.cached()...)
	}
	for _, c := range cols {
		d.Docs = append(d.Docs, c.cached()...)
	}
	sort.Slice(d.Docs, func(i, j int) bool { return d.Docs[i].ID < d.Docs[j].ID })
	return d
}

// Restore applies the documents of a cache.enc, checked as if read from
// OpenSearch, as a provisional configuration until OpenSearch answers;
// its revisions count as applied, so an older copy is refused later.
func (h *Hub) Restore(d CacheData) {
	h.mu.Lock()
	for id, r := range d.Floors {
		h.floors[id] = max(h.floors[id], r)
	}
	if d.WrittenAt.After(h.confirmed) {
		h.confirmed = d.WrittenAt
	}
	singles := maps.Clone(h.singles)
	cols := slices.Clone(h.colls)
	h.mu.Unlock()
	for _, cd := range d.Docs {
		doc := store.Doc{Ref: store.Ref{Index: h.index(), ID: cd.ID}, Found: true, Source: cd.Source,
			Version: store.Version{SeqNo: cd.Seq, PrimaryTerm: cd.Term}}
		if t := singles[cd.ID]; t != nil {
			t.apply(doc, d.IndexUUID, t.gen())
			continue
		}
		for _, c := range cols {
			if c.owns(cd.ID) {
				c.restore(doc, d.IndexUUID)
				break
			}
		}
	}
}

// AcceptRestore makes this server, and every other, accept the documents
// now in OpenSearch after an intentional snapshot restore lowered their
// revisions: every document of the config index whose MAC verifies,
// whether this server follows it or not (another server's nodecfg, a kind
// only a newer version knows), is written again, signed, at a revision
// above every one applied anywhere (peerMaxRev is the highest the other
// servers' heartbeats report). Documents that fail their MAC stay
// refused.
func (h *Hub) AcceptRestore(ctx context.Context, by string, peerMaxRev int64) error {
	rev := max(peerMaxRev, h.MaxRev()) + 1
	c, prefix := h.target()
	keys := h.Keys()
	k := keys.Active()
	if c == nil || k == nil {
		return errors.New("this server cannot sign the shared settings now")
	}
	index := ConfigIndex(prefix)
	docs, err := c.SearchDocs(ctx, index, map[string]any{"bool": map[string]any{
		"must_not": []any{map[string]any{"term": map[string]any{"kind": "watch"}}}}})
	if err != nil {
		return err
	}
	var errs []error
	var refused []string
	for _, d := range docs {
		var e Envelope
		if json.Unmarshal(d.Source, &e) != nil || Verify(keys, d.ID, &e) != nil || e.ID != d.ID {
			refused = append(refused, d.ID)
			continue
		}
		// Extra, the fields this version does not know, is kept.
		e.Rev, e.UpdatedAt, e.UpdatedBy, e.WriteID = rev, h.now(), By{User: by, Node: h.opts.NodeName}, ""
		if err := Sign(k, d.ID, &e); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := c.PutIf(ctx, index, d.ID, &e, d.Version, false); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.ID, err))
		}
	}
	if len(refused) > 0 {
		h.log.Warn("accept-restore left documents that fail their checks as they are", "docs", refused)
	}

	// This server reads its documents now; a bump of every watch document
	// makes every server list its collections again.
	h.mu.Lock()
	singles := slices.Collect(maps.Values(h.singles))
	cols := slices.Clone(h.colls)
	h.mu.Unlock()
	for _, t := range singles {
		if err := t.reload(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	for _, col := range cols {
		if _, ok := col.(watchFunc); ok {
			continue
		}
		if _, err := col.reload(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	watches, err := c.SearchVersions(ctx, index, map[string]any{"term": map[string]any{"kind": "watch"}})
	if err != nil {
		errs = append(errs, err)
	}
	for _, w := range watches {
		if _, err := h.bump(ctx, w.ID, nil); err != nil {
			errs = append(errs, err)
		}
	}
	h.log.Info("accepted the shared settings restored in OpenSearch", "audit", true, "by", by, "rev", rev)
	return errors.Join(errs...)
}

// itemName returns the name of a collection item from its id.
func itemName(kind, id string) (string, bool) { return strings.CutPrefix(id, kind+":") }
