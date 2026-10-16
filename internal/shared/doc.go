package shared

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// entry is a document as applied: its envelope, its stored source, its
// version and the uuid of the index it was read from or written to.
type entry struct {
	env  Envelope
	src  json.RawMessage
	ver  store.Version
	uuid string
}

// same reports whether the entry is the copy at version v of the index
// uuid. A version alone does not tell: an index made again starts its
// sequence numbers over.
func (e *entry) same(uuid string, v store.Version) bool {
	return e.uuid == uuid && e.ver.Same(v)
}

// etag is the entry's ETag, "<seq_no>.<primary term>.<index uuid>", so
// that one read before the index was made again never matches.
func (e *entry) etag() string {
	if e.uuid == "" {
		return e.ver.String()
	}
	return e.ver.String() + "." + e.uuid
}

// cacheDoc returns the entry as cache.enc keeps it.
func (e *entry) cacheDoc(id string) CacheDoc {
	return CacheDoc{ID: id, Seq: e.ver.SeqNo, Term: e.ver.PrimaryTerm, Source: e.src}
}

// StaleError is a save based on a version someone else changed since: it
// says who, on which server, and when, for "Changed on siem-b by Bob a
// moment ago. Reload". The API answers it with 412.
type StaleError struct {
	By   string
	Node string
	At   string
}

func (e *StaleError) Error() string {
	if e.By == "" && e.Node == "" {
		return "it was changed since it was read; reload it"
	}
	what := "it was changed"
	if e.Node != "" {
		what += " on " + e.Node
	}
	if e.By != "" {
		what += " by " + e.By
	}
	if e.At != "" {
		what += " at " + e.At
	}
	return what + "; reload it"
}

// Retry waits between tries of a write that conflicted: random, from 10
// ms growing to 250 ms.
const (
	retryMin = 10 * time.Millisecond
	retryMax = 250 * time.Millisecond
)

func retryWait(ctx context.Context, try int) error {
	top := min(retryMin<<try, retryMax)
	wait := retryMin + time.Duration(rand.Int64N(int64(top-retryMin)+1))
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Doc is one shared document, such as the feed list or the retention
// policies, of body type T (which embeds Extra). Get reads memory; the
// hub keeps it current.
type Doc[T any] struct {
	h      *Hub
	id     string
	kind   string
	format int
	// Validate, when set, checks a body read or about to be written; a
	// body it refuses is not used.
	Validate func(*T) error
	// Local marks a document only this server tracks (its nodecfg): its
	// writes do not move the token pages wait for, which the other
	// servers would never reach. Set it before use.
	Local bool

	// wmu lets one write of this server's run at a time: writers on the
	// same server queue rather than conflict, and compare-and-set settles
	// the writes of different servers.
	wmu  sync.Mutex
	mu   sync.Mutex
	cur  *entry
	g    uint64
	subs []func(old, new *T)
	// missing is true when the last read found no document.
	missing bool
}

// NewDoc returns the document id, of kind and up to format, and tracks it
// on h.
func NewDoc[T any](h *Hub, id, kind string, format int) *Doc[T] {
	d := &Doc[T]{h: h, id: id, kind: kind, format: format}
	h.track(d)
	return d
}

func (d *Doc[T]) docID() string { return d.id }

func (d *Doc[T]) local() bool { return d.Local }

func (d *Doc[T]) gen() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.g
}

// Get returns a copy of the document's body, and false when there is
// none yet.
func (d *Doc[T]) Get() (*T, bool) {
	d.mu.Lock()
	cur := d.cur
	d.mu.Unlock()
	if cur == nil {
		return new(T), false
	}
	v, err := decodeBody[T](cur.env.Body)
	if err != nil {
		return new(T), false
	}
	return v, true
}

// ETag returns the version of the copy in memory, "<seq_no>.<primary
// term>.<index uuid>", or "" when there is none.
func (d *Doc[T]) ETag() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cur == nil {
		return ""
	}
	return d.cur.etag()
}

// Updated returns who changed the document last, on which server and
// when, and its revision.
func (d *Doc[T]) Updated() (by By, at string, rev int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cur == nil {
		return By{}, "", 0
	}
	return d.cur.env.UpdatedBy, d.cur.env.UpdatedAt, d.cur.env.Rev
}

// Missing reports whether the last read found no document in
// OpenSearch, whatever copy is kept in memory.
func (d *Doc[T]) Missing() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.missing
}

// OnChange adds a function called with the old and new body whenever
// another copy is applied; old is nil the first time.
func (d *Doc[T]) OnChange(fn func(old, new *T)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subs = append(d.subs, fn)
}

// apply checks a copy read from the index uuid and uses it when it
// passes. A copy read before gen moved (another copy was applied since)
// is left for the next read, and apply reports false. The decision is
// made under d.mu, so a write of this server's own cannot slip in
// between the check of the revision and its use.
func (d *Doc[T]) apply(doc store.Doc, uuid string, gen uint64) bool {
	var e *Envelope
	var p *Problem
	if doc.Found {
		if e, p = d.h.open(d.id, d.kind, d.format, doc.Source); p == nil {
			if _, err := d.decode(e); err != nil {
				p = &Problem{Kind: ProblemInvalid, Reason: err.Error()}
			}
		}
	}
	d.mu.Lock()
	if d.g != gen {
		d.mu.Unlock()
		return false
	}
	if d.cur != nil && doc.Found && d.cur.same(uuid, doc.Version) {
		d.mu.Unlock()
		return true
	}
	d.missing = !doc.Found
	if !doc.Found {
		if d.cur != nil {
			d.h.report(d.id, &Problem{Kind: ProblemTamper, Reason: "it was deleted in OpenSearch outside Signalith"}, store.Version{})
		}
		d.mu.Unlock()
		return true
	}
	if p == nil {
		p = d.h.checkRev(d.id, e.Rev)
	}
	if p != nil {
		d.h.report(d.id, p, doc.Version)
		d.mu.Unlock()
		return true
	}
	d.setLocked(&entry{env: *e, src: doc.Source, ver: doc.Version, uuid: uuid}, false)
	return true
}

func (d *Doc[T]) decode(e *Envelope) (*T, error) {
	v, err := decodeBody[T](e.Body)
	if err != nil {
		return nil, fmt.Errorf("its body cannot be read: %w", err)
	}
	if d.Validate != nil {
		if err := d.Validate(v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// set puts this server's own write in use, unless the watcher applied a
// later revision meanwhile.
func (d *Doc[T]) set(e *entry) {
	d.mu.Lock()
	if d.cur != nil && d.cur.env.Rev > e.env.Rev {
		d.mu.Unlock()
		d.h.ownWrite(d.id, e.ver)
		return
	}
	d.setLocked(e, true)
}

// setLocked puts an entry in use, unlocks d.mu and tells the
// subscribers.
func (d *Doc[T]) setLocked(e *entry, own bool) {
	old := d.cur
	d.cur, d.missing = e, false
	d.g++
	changed := d.h.fine(d.id, e.env.Rev)
	if own {
		d.h.ownWrite(d.id, e.ver)
	}
	subs := append([]func(old, new *T){}, d.subs...)
	d.mu.Unlock()
	var ov *T
	if old != nil {
		ov, _ = decodeBody[T](old.env.Body)
	}
	for _, fn := range subs {
		nv, _ := decodeBody[T](e.env.Body)
		fn(ov, nv)
	}
	if changed != nil {
		changed()
	}
}

// Load reads the document now, as at start-up.
func (d *Doc[T]) Load(ctx context.Context) error {
	return d.reload(ctx)
}

func (d *Doc[T]) reload(ctx context.Context) error {
	c, _ := d.h.target()
	uuid, err := d.h.indexUUID(ctx)
	if err != nil {
		return err
	}
	g := d.gen()
	src, ver, found, err := c.Get(ctx, d.h.index(), d.id)
	if err != nil {
		return err
	}
	d.apply(store.Doc{Ref: store.Ref{Index: d.h.index(), ID: d.id}, Found: found, Version: ver, Source: src}, uuid, g)
	return nil
}

// usable returns the entry to build a write on, or why there is none.
func (d *Doc[T]) usable() (*entry, error) {
	if p := d.h.problemOf(d.id); p != nil {
		return nil, &ProblemError{Problem: *p}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cur, nil
}

// envelope makes the signed envelope of a new revision with body v.
func (d *Doc[T]) envelope(base *entry, by string, v *T) (*Envelope, error) {
	if d.Validate != nil {
		if err := d.Validate(v); err != nil {
			return nil, err
		}
	}
	body, err := encodeBody(v)
	if err != nil {
		return nil, err
	}
	e := &Envelope{Kind: d.kind, ID: d.id, Format: d.format, Rev: d.h.firstRev(d.id, false), UpdatedAt: d.h.now(),
		UpdatedBy: By{User: by, Node: d.h.opts.NodeName}, Body: body}
	if base != nil {
		e.Rev, e.Extra = base.env.Rev+1, base.env.Extra
		if base.env.Format > d.format {
			e.Format = base.env.Format
		}
	}
	k := d.h.Keys().Active()
	if k == nil {
		return nil, errors.New("this server has no cluster key")
	}
	if err := Sign(k, d.id, e); err != nil {
		return nil, err
	}
	return e, nil
}

// write writes e over base (create when base is nil) and applies it.
func (d *Doc[T]) write(ctx context.Context, base *entry, e *Envelope) (int64, error) {
	c, _ := d.h.target()
	uuid, err := d.h.indexUUID(ctx)
	if err != nil {
		return 0, err
	}
	var ver store.Version
	if base == nil {
		ver, err = c.Create(ctx, d.h.index(), d.id, e, false)
		if errors.Is(err, store.ErrExists) {
			err = store.ErrConflict
		}
	} else {
		ver, err = c.PutIf(ctx, d.h.index(), d.id, e, base.ver, false)
	}
	if err != nil {
		return 0, err
	}
	src, _ := json.Marshal(e)
	d.set(&entry{env: *e, src: src, ver: ver, uuid: uuid})
	if !d.Local {
		d.h.mu.Lock()
		d.h.wroteLocked(uuid, ver.SeqNo)
		d.h.mu.Unlock()
	}
	return ver.SeqNo, nil
}

// Mutate changes the document with fn, which checks what must hold and
// may return an error to change nothing. fn gets a copy of the latest
// body (an empty one when there is none) and runs again on the newer copy
// when another server changed it in between, up to 10 times. It returns
// the _seq_no written, for the page's configuration token.
func (d *Doc[T]) Mutate(ctx context.Context, by string, fn func(*T) error) (int64, error) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	var last error
	for try := range store.ModifyTries {
		if try > 0 {
			if err := retryWait(ctx, try); err != nil {
				return 0, err
			}
		}
		base, err := d.usable()
		if err != nil {
			return 0, err
		}
		if base == nil {
			// Not read yet, or not there: read it to be sure.
			if err := d.reload(ctx); err != nil {
				return 0, err
			}
			if base, err = d.usable(); err != nil {
				return 0, err
			}
		}
		v := new(T)
		if base != nil {
			if v, err = decodeBody[T](base.env.Body); err != nil {
				return 0, err
			}
		}
		if err := fn(v); err != nil {
			return 0, err
		}
		e, err := d.envelope(base, by, v)
		if err != nil {
			return 0, err
		}
		seq, err := d.write(ctx, base, e)
		if !errors.Is(err, store.ErrConflict) {
			return seq, err
		}
		last = err
		if err := d.reload(ctx); err != nil {
			return 0, err
		}
	}
	return 0, last
}

// SaveIf replaces the document with v, for a page that read it at etag
// (ETag). Another change since gives a *StaleError naming who made it.
func (d *Doc[T]) SaveIf(ctx context.Context, by string, v *T, etag string) (int64, error) {
	return d.MutateIf(ctx, by, etag, func(cur *T) error {
		*cur = *v
		return nil
	})
}

// MutateIf changes the document with fn, for a page that read it at etag
// (ETag). fn gets a copy of the revision etag names, never an older copy
// this server still holds, so a change made elsewhere is not lost. Another
// change since gives a *StaleError naming who made it.
func (d *Doc[T]) MutateIf(ctx context.Context, by, etag string, fn func(*T) error) (int64, error) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	base, err := d.usable()
	if err != nil {
		return 0, err
	}
	if base == nil || base.etag() != etag {
		// Memory may be behind OpenSearch: read it.
		if err := d.reload(ctx); err != nil {
			return 0, err
		}
		if base, err = d.usable(); err != nil {
			return 0, err
		}
	}
	if base == nil && etag != "" || base != nil && base.etag() != etag {
		return 0, d.stale(base)
	}
	v := new(T)
	if base != nil {
		if v, err = decodeBody[T](base.env.Body); err != nil {
			return 0, err
		}
	}
	if err := fn(v); err != nil {
		return 0, err
	}
	e, err := d.envelope(base, by, v)
	if err != nil {
		return 0, err
	}
	seq, err := d.write(ctx, base, e)
	if errors.Is(err, store.ErrConflict) {
		if rerr := d.reload(ctx); rerr != nil {
			return 0, err
		}
		d.mu.Lock()
		cur := d.cur
		d.mu.Unlock()
		return 0, d.stale(cur)
	}
	return seq, err
}

func (d *Doc[T]) stale(cur *entry) error {
	if cur == nil {
		return &StaleError{}
	}
	return &StaleError{By: cur.env.UpdatedBy.User, Node: cur.env.UpdatedBy.Node, At: cur.env.UpdatedAt}
}

// Create writes the document only if it does not exist yet, as founding
// the cluster does: store.ErrExists when it does.
func (d *Doc[T]) Create(ctx context.Context, by string, v *T) (int64, error) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	e, err := d.envelope(nil, by, v)
	if err != nil {
		return 0, err
	}
	seq, err := d.write(ctx, nil, e)
	if errors.Is(err, store.ErrConflict) {
		err = store.ErrExists
	}
	return seq, err
}

func (d *Doc[T]) cached() []CacheDoc {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cur == nil {
		return nil
	}
	return []CacheDoc{d.cur.cacheDoc(d.id)}
}
