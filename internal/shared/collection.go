package shared

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Collection is a list of shared items that grows, such as users or
// detections: one document per item, <kind>:<name>, of body type T (which
// embeds Extra). List and Get read memory. Every write ends with a bump
// of the collection's watch document, so the other servers list it again
// within one poll.
//
// A deleted item is kept as a signed tombstone (deleted, empty body) for
// 30 days, so a server can tell a deletion from an item someone removed
// in OpenSearch: an item that disappears without a tombstone is kept from
// memory and reported as tampered with.
type Collection[T any] struct {
	h      *Hub
	kind   string
	watch  string
	format int
	// Validate, when set, checks an item's body read or about to be
	// written; an item it refuses is not used. ValidateItem does the same
	// with the item's name, for a body that must agree with its id.
	Validate     func(*T) error
	ValidateItem func(name string, v *T) error

	// wmu lets one write of this server's run at a time (see Doc).
	wmu   sync.Mutex
	mu    sync.Mutex
	items map[string]*entry
	gens  map[string]uint64
	subs  []func()
}

// NewCollection returns the collection of items of kind, up to format,
// whose watch document is watch:<watch>, and tracks it on h.
func NewCollection[T any](h *Hub, kind, watch string, format int) *Collection[T] {
	c := &Collection[T]{h: h, kind: kind, watch: "watch:" + watch, format: format, items: map[string]*entry{}, gens: map[string]uint64{}}
	h.trackCollection(c)
	return c
}

func (c *Collection[T]) watchID() string { return c.watch }

// ItemID returns the document id of the item name.
func (c *Collection[T]) ItemID(name string) string { return c.kind + ":" + name }

func (c *Collection[T]) owns(id string) bool {
	_, ok := itemName(c.kind, id)
	return ok
}

// Item is one item of a collection as List returns it.
type Item[T any] struct {
	Name      string
	Value     *T
	ETag      string
	UpdatedBy By
	UpdatedAt string
}

// List returns copies of the items, by name.
func (c *Collection[T]) List() []Item[T] {
	c.mu.Lock()
	var out []Item[T]
	for id, e := range c.items {
		if e.env.Deleted {
			continue
		}
		name, _ := itemName(c.kind, id)
		out = append(out, Item[T]{Name: name, ETag: e.etag(), UpdatedBy: e.env.UpdatedBy, UpdatedAt: e.env.UpdatedAt, Value: nil})
		out[len(out)-1].Value, _ = decodeBody[T](e.env.Body)
	}
	c.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns a copy of the item name and its ETag.
func (c *Collection[T]) Get(name string) (*T, string, bool) {
	c.mu.Lock()
	e := c.items[c.ItemID(name)]
	c.mu.Unlock()
	if e == nil || e.env.Deleted {
		return nil, "", false
	}
	v, err := decodeBody[T](e.env.Body)
	if err != nil {
		return nil, "", false
	}
	return v, e.etag(), true
}

// OnChange adds a function called whenever items were added, changed or
// removed.
func (c *Collection[T]) OnChange(fn func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subs = append(c.subs, fn)
}

func (c *Collection[T]) notify() {
	c.mu.Lock()
	subs := append([]func(){}, c.subs...)
	c.mu.Unlock()
	for _, fn := range subs {
		fn()
	}
}

// validate runs Validate and ValidateItem on the body of item id.
func (c *Collection[T]) validate(id string, v *T) error {
	if c.Validate != nil {
		if err := c.Validate(v); err != nil {
			return err
		}
	}
	if c.ValidateItem != nil {
		name, _ := itemName(c.kind, id)
		return c.ValidateItem(name, v)
	}
	return nil
}

// check checks a copy of item id read from OpenSearch.
func (c *Collection[T]) check(id string, src json.RawMessage) (*Envelope, *Problem) {
	e, p := c.h.open(id, c.kind, c.format, src)
	if p == nil && !e.Deleted {
		v, err := decodeBody[T](e.Body)
		if err == nil {
			err = c.validate(id, v)
		}
		if err != nil {
			p = &Problem{Kind: ProblemInvalid, Reason: err.Error()}
		}
	}
	return e, p
}

// apply uses a copy of an item read from the index uuid when it passes
// its checks and nothing was applied to that item since gen. It reports
// whether the copy was put in use, and whether it was left alone because
// gen moved, so it must be read again.
func (c *Collection[T]) apply(d store.Doc, uuid string, gen uint64) (used, left bool) {
	e, p := c.check(d.ID, d.Source)
	c.mu.Lock()
	cur := c.items[d.ID]
	if c.gens[d.ID] != gen {
		c.mu.Unlock()
		return false, true
	}
	if cur != nil && cur.same(uuid, d.Version) {
		c.mu.Unlock()
		return false, false
	}
	if p == nil {
		p = c.h.checkRev(d.ID, e.Rev)
	}
	if p != nil {
		c.h.report(d.ID, p, d.Version)
		c.mu.Unlock()
		return false, false
	}
	changed := c.setLocked(d.ID, &entry{env: *e, src: d.Source, ver: d.Version, uuid: uuid})
	c.mu.Unlock()
	if changed != nil {
		changed()
	}
	return true, false
}

// set puts this server's own write of item id in use, unless a later
// revision was applied meanwhile.
func (c *Collection[T]) set(id string, e *entry) {
	c.mu.Lock()
	if cur := c.items[id]; cur != nil && cur.env.Rev > e.env.Rev {
		c.mu.Unlock()
		return
	}
	changed := c.setLocked(id, e)
	c.mu.Unlock()
	if changed != nil {
		changed()
	}
}

// setLocked puts an entry in use; the caller holds c.mu and calls the
// function returned, if any, once it let go.
func (c *Collection[T]) setLocked(id string, e *entry) func() {
	c.items[id] = e
	c.gens[id]++
	return c.h.fine(id, e.env.Rev)
}

func (c *Collection[T]) restore(d store.Doc, uuid string) {
	c.mu.Lock()
	g := c.gens[d.ID]
	c.mu.Unlock()
	if used, _ := c.apply(d, uuid, g); used {
		c.notify()
	}
}

// reload lists the collection and reads the items that changed. It
// reports false when an item changed here while it was read, so the
// listing must be done again.
func (c *Collection[T]) reload(ctx context.Context) (bool, error) {
	cl, _ := c.h.target()
	index := c.h.index()
	uuid, err := c.h.indexUUID(ctx)
	if err != nil {
		return false, err
	}
	// What changes during the listing is not judged by it.
	c.mu.Lock()
	gens := maps.Clone(c.gens)
	c.mu.Unlock()
	listed, err := cl.SearchVersions(ctx, index, map[string]any{"term": map[string]any{"kind": c.kind}})
	if err != nil {
		return false, err
	}
	present := map[string]bool{}
	var fetch []store.Ref
	c.mu.Lock()
	for _, d := range listed {
		if !c.owns(d.ID) {
			continue
		}
		present[d.ID] = true
		if cur := c.items[d.ID]; cur == nil || !cur.same(uuid, d.Version) {
			fetch = append(fetch, store.Ref{Index: index, ID: d.ID})
		}
	}
	for id, e := range c.items {
		if present[id] || gens[id] != c.gens[id] {
			continue
		}
		if e.env.Deleted {
			// A tombstone housekeeping removed.
			delete(c.items, id)
			c.gens[id]++
			continue
		}
		c.h.report(id, &Problem{Kind: ProblemTamper, Reason: "it was removed in OpenSearch outside Signalith"}, store.Version{})
	}
	c.mu.Unlock()
	docs, err := cl.MGet(ctx, fetch)
	if err != nil {
		return false, err
	}
	changed, all := false, true
	for _, d := range docs {
		if !d.Found {
			continue
		}
		used, left := c.apply(d, uuid, gens[d.ID])
		changed = changed || used
		all = all && !left
	}
	if changed {
		c.notify()
	}
	return all, nil
}

// usable returns the item to build a write on.
func (c *Collection[T]) usable(id string) (*entry, error) {
	if p := c.h.problemOf(id); p != nil {
		return nil, &ProblemError{Problem: *p}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.items[id], nil
}

// envelope makes the signed envelope of an item's new revision; v nil is
// a tombstone.
func (c *Collection[T]) envelope(id string, base *entry, by string, v *T) (*Envelope, error) {
	e := &Envelope{Kind: c.kind, ID: id, Format: c.format, Rev: c.h.firstRev(id, true), UpdatedAt: c.h.now(),
		UpdatedBy: By{User: by, Node: c.h.opts.NodeName}}
	if v == nil {
		e.Deleted = true
	} else {
		if err := c.validate(id, v); err != nil {
			return nil, err
		}
		body, err := encodeBody(v)
		if err != nil {
			return nil, err
		}
		e.Body = body
	}
	if base != nil {
		e.Rev, e.Extra = base.env.Rev+1, base.env.Extra
	}
	k := c.h.Keys().Active()
	if k == nil {
		return nil, errors.New("this server has no cluster key")
	}
	return e, Sign(k, id, e)
}

// write writes e over base (create when base is nil), applies it, and
// bumps the watch document. It returns the _seq_no for the page's token.
func (c *Collection[T]) write(ctx context.Context, id string, base *entry, e *Envelope) (int64, error) {
	cl, _ := c.h.target()
	uuid, err := c.h.indexUUID(ctx)
	if err != nil {
		return 0, err
	}
	var ver store.Version
	if base == nil {
		ver, err = cl.Create(ctx, c.h.index(), id, e, true)
	} else {
		ver, err = cl.PutIf(ctx, c.h.index(), id, e, base.ver, true)
	}
	if err != nil {
		return 0, err
	}
	src, _ := json.Marshal(e)
	c.set(id, &entry{env: *e, src: src, ver: ver, uuid: uuid})
	c.notify()
	seq, err := c.h.bump(ctx, c.watch, nil)
	if err != nil {
		// Saved: the others find it at their next full listing.
		c.h.log.Warn("saved, but the other servers may not see it for up to 5 minutes", "doc", id, "err", err)
		return ver.SeqNo, nil
	}
	return seq, nil
}

// Create adds the item name: store.ErrExists when there is one. An item
// deleted earlier (a tombstone) is written over.
func (c *Collection[T]) Create(ctx context.Context, by, name string, v *T) (int64, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	id := c.ItemID(name)
	base, err := c.usable(id)
	if err != nil {
		return 0, err
	}
	if base != nil && !base.env.Deleted {
		return 0, store.ErrExists
	}
	e, err := c.envelope(id, base, by, v)
	if err != nil {
		return 0, err
	}
	seq, err := c.write(ctx, id, base, e)
	if err == nil || base != nil || !errors.Is(err, store.ErrExists) {
		if errors.Is(err, store.ErrConflict) {
			return 0, store.ErrExists
		}
		return seq, err
	}
	// There is a copy this server has not read: a tombstone may be
	// written over.
	if err := c.readOne(ctx, id); err != nil {
		return 0, err
	}
	if base, err = c.usable(id); err != nil {
		return 0, err
	}
	if base == nil || !base.env.Deleted {
		return 0, store.ErrExists
	}
	if e, err = c.envelope(id, base, by, v); err != nil {
		return 0, err
	}
	seq, err = c.write(ctx, id, base, e)
	if errors.Is(err, store.ErrConflict) {
		return 0, store.ErrExists
	}
	return seq, err
}

// Refresh reads the item name from OpenSearch now, so Get returns what
// is there rather than what the last poll found.
func (c *Collection[T]) Refresh(ctx context.Context, name string) error {
	return c.readOne(ctx, c.ItemID(name))
}

// readOne reads item id now.
func (c *Collection[T]) readOne(ctx context.Context, id string) error {
	cl, _ := c.h.target()
	uuid, err := c.h.indexUUID(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	g := c.gens[id]
	c.mu.Unlock()
	src, ver, found, err := cl.Get(ctx, c.h.index(), id)
	if err != nil || !found {
		return err
	}
	if used, _ := c.apply(store.Doc{Ref: store.Ref{Index: c.h.index(), ID: id}, Found: true, Version: ver, Source: src}, uuid, g); used {
		c.notify()
	}
	return nil
}

// SaveIf replaces the item name, read at etag: a *StaleError when it
// changed since, store.ErrNotFound when it is not there.
func (c *Collection[T]) SaveIf(ctx context.Context, by, name string, v *T, etag string) (int64, error) {
	return c.replace(ctx, by, name, etag, func(*Envelope) (*T, error) { return v, nil })
}

// Delete deletes the item name, read at etag, leaving a signed
// tombstone.
func (c *Collection[T]) Delete(ctx context.Context, by, name, etag string) (int64, error) {
	return c.replace(ctx, by, name, etag, func(*Envelope) (*T, error) { return nil, nil })
}

// MutateIf changes the item name with fn, for a page that read it at
// etag. fn gets a copy of the revision etag names and may return an error
// to change nothing. Another change since gives a *StaleError naming who
// made it; a missing or deleted item gives store.ErrNotFound.
func (c *Collection[T]) MutateIf(ctx context.Context, by, name, etag string, fn func(*T) error) (int64, error) {
	return c.replace(ctx, by, name, etag, func(base *Envelope) (*T, error) {
		v, err := decodeBody[T](base.Body)
		if err != nil {
			return nil, err
		}
		return v, fn(v)
	})
}

// Mutate changes the item name with fn, which checks what must hold and
// may return an error to change nothing. fn gets a copy of the latest
// body and runs again on the newer copy when another server changed it in
// between, up to store.ModifyTries times. A missing or deleted item gives
// store.ErrNotFound.
func (c *Collection[T]) Mutate(ctx context.Context, by, name string, fn func(*T) error) (int64, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	id := c.ItemID(name)
	var last error
	for try := range store.ModifyTries {
		if try > 0 {
			if err := retryWait(ctx, try); err != nil {
				return 0, err
			}
		}
		base, err := c.usable(id)
		if err != nil {
			return 0, err
		}
		if base == nil || base.env.Deleted {
			// Not read yet, or deleted: read it to be sure.
			if err := c.readOne(ctx, id); err != nil {
				return 0, err
			}
			if base, err = c.usable(id); err != nil {
				return 0, err
			}
		}
		if base == nil || base.env.Deleted {
			return 0, store.ErrNotFound
		}
		v, err := decodeBody[T](base.env.Body)
		if err != nil {
			return 0, err
		}
		if err := fn(v); err != nil {
			return 0, err
		}
		e, err := c.envelope(id, base, by, v)
		if err != nil {
			return 0, err
		}
		seq, err := c.write(ctx, id, base, e)
		if !errors.Is(err, store.ErrConflict) {
			return seq, err
		}
		last = err
		if err := c.readOne(ctx, id); err != nil {
			return 0, err
		}
	}
	return 0, last
}

// replace writes over the item name, read at etag, the body change
// returns for it (nil for a tombstone).
func (c *Collection[T]) replace(ctx context.Context, by, name, etag string, change func(*Envelope) (*T, error)) (int64, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	id := c.ItemID(name)
	base, err := c.usable(id)
	if err != nil {
		return 0, err
	}
	if base == nil || base.etag() != etag {
		if err := c.readOne(ctx, id); err != nil {
			return 0, err
		}
		if base, err = c.usable(id); err != nil {
			return 0, err
		}
	}
	if base == nil || base.env.Deleted {
		return 0, store.ErrNotFound
	}
	if base.etag() != etag {
		return 0, &StaleError{By: base.env.UpdatedBy.User, Node: base.env.UpdatedBy.Node, At: base.env.UpdatedAt}
	}
	v, err := change(&base.env)
	if err != nil {
		return 0, err
	}
	e, err := c.envelope(id, base, by, v)
	if err != nil {
		return 0, err
	}
	seq, err := c.write(ctx, id, base, e)
	if errors.Is(err, store.ErrConflict) {
		_ = c.readOne(ctx, id)
		c.mu.Lock()
		cur := c.items[id]
		c.mu.Unlock()
		if cur == nil {
			return 0, &StaleError{}
		}
		return 0, &StaleError{By: cur.env.UpdatedBy.User, Node: cur.env.UpdatedBy.Node, At: cur.env.UpdatedAt}
	}
	return seq, err
}

// TombstoneAge is how long a deleted item's tombstone is kept.
const TombstoneAge = 30 * 24 * time.Hour

// Housekeep removes the tombstones older than TombstoneAge at now, then
// bumps the watch document. It returns how many it removed and the
// bump's _seq_no (0 when none was removed).
func (c *Collection[T]) Housekeep(ctx context.Context, now time.Time) (int, int64, error) {
	type old struct {
		id  string
		ver store.Version
	}
	var list []old
	c.mu.Lock()
	for id, e := range c.items {
		if !e.env.Deleted {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.env.UpdatedAt)
		if err == nil && now.Sub(at) > TombstoneAge {
			list = append(list, old{id, e.ver})
		}
	}
	c.mu.Unlock()
	cl, _ := c.h.target()
	n := 0
	var errs []error
	for _, o := range list {
		err := cl.DeleteIf(ctx, c.h.index(), o.id, o.ver, true)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, fmt.Errorf("%s: %w", o.id, err))
			continue
		}
		c.mu.Lock()
		delete(c.items, o.id)
		c.gens[o.id]++
		c.mu.Unlock()
		n++
	}
	if n == 0 {
		return 0, 0, errors.Join(errs...)
	}
	seq, err := c.h.bump(ctx, c.watch, nil)
	return n, seq, errors.Join(append(errs, err)...)
}

func (c *Collection[T]) cached() []CacheDoc {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []CacheDoc
	for id, e := range c.items {
		out = append(out, e.cacheDoc(id))
	}
	return out
}
