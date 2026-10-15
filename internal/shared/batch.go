package shared

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// MutateMany changes the items names, one after another, with fn, which
// gets a copy of each item's latest body (nil when there is none, or it
// was deleted) and returns the body to write (nil deletes the item) or
// write false to leave it as it is. Like Mutate, an item another server
// changed in between is read again and fn runs again on the newer copy.
//
// The other servers are told once, at the end, so a change of hundreds
// of items (turning on the rules of a content pack, or an import) costs
// one bump and one refresh rather than one of each per item. Items
// written before an error stay written. It returns how many it wrote and
// the bump's _seq_no for the page's token (0 when it wrote none).
func (c *Collection[T]) MutateMany(ctx context.Context, by string, names []string, fn func(name string, cur *T) (next *T, write bool, err error)) (int, int64, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	var err error
	for _, name := range names {
		var ok bool
		if ok, err = c.mutateOne(ctx, by, name, fn); err != nil {
			break
		}
		if ok {
			written++
		}
	}
	if written == 0 {
		return 0, 0, err
	}
	c.notify()
	cl, _ := c.h.target()
	// The writes were made without a refresh each; one makes them all
	// visible to the other servers' listings before they are told.
	if rerr := cl.Do(ctx, http.MethodPost, "/"+url.PathEscape(c.h.index())+"/_refresh", nil, nil); rerr != nil {
		c.h.log.Debug("could not refresh the shared settings after a batch of changes", "err", rerr)
	}
	seq, berr := c.h.bump(ctx, c.watch, nil)
	if berr != nil {
		c.h.log.Warn("saved, but the other servers may not see it for up to 5 minutes", "kind", c.kind, "err", berr)
		seq = 0
	}
	return written, seq, err
}

// mutateOne is one item of MutateMany; c.wmu is held. It reports whether
// it wrote the item.
func (c *Collection[T]) mutateOne(ctx context.Context, by, name string, fn func(string, *T) (*T, bool, error)) (bool, error) {
	id := c.ItemID(name)
	var last error
	for try := range store.ModifyTries {
		if try > 0 {
			if err := retryWait(ctx, try); err != nil {
				return false, err
			}
		}
		base, err := c.usable(id)
		if err != nil {
			return false, err
		}
		var cur *T
		if base != nil && !base.env.Deleted {
			if cur, err = decodeBody[T](base.env.Body); err != nil {
				return false, err
			}
		}
		next, write, err := fn(name, cur)
		if err != nil || !write {
			return false, err
		}
		if next == nil && cur == nil {
			return false, nil
		}
		e, err := c.envelope(id, base, by, next)
		if err != nil {
			return false, err
		}
		err = c.writeQuiet(ctx, id, base, e)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrExists) {
			return false, err
		}
		// Another server wrote it since this one read it: read it and
		// work the change out again.
		last = err
		if err := c.readOne(ctx, id); err != nil {
			return false, err
		}
	}
	return false, last
}

// writeQuiet writes e over base (create when base is nil) without a
// refresh, and applies it, but neither notifies nor bumps.
func (c *Collection[T]) writeQuiet(ctx context.Context, id string, base *entry, e *Envelope) error {
	cl, _ := c.h.target()
	uuid, err := c.h.indexUUID(ctx)
	if err != nil {
		return err
	}
	var ver store.Version
	if base == nil {
		ver, err = cl.Create(ctx, c.h.index(), id, e, false)
	} else {
		ver, err = cl.PutIf(ctx, c.h.index(), id, e, base.ver, false)
	}
	if err != nil {
		return err
	}
	src, _ := json.Marshal(e)
	c.set(id, &entry{env: *e, src: src, ver: ver, uuid: uuid})
	return nil
}
