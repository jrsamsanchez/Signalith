package shared

import (
	"context"
	"errors"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// A document that only one server tracks (its nodecfg) is read and
// changed by the others on demand, such as when a Settings page shows or
// saves another server's own settings: a Remote reads it straight from
// OpenSearch (a GET by id is real-time), checks its MAC, kind and format as
// the watcher does, and writes it with a compare-and-set. It keeps no copy
// and applies no revision floor, so it is for display and for changes
// only; the server the document belongs to follows it with its own Doc,
// which does both.

// Remote is a document of body type T (which embeds Extra) that this
// server reads and changes without tracking it.
type Remote[T any] struct {
	h      *Hub
	id     string
	kind   string
	format int
	// Validate, when set, checks a body read or about to be written; a
	// body it refuses is not used.
	Validate func(*T) error
}

// NewRemote returns the document id, of kind and up to format, on h. It
// is not tracked.
func NewRemote[T any](h *Hub, id, kind string, format int) *Remote[T] {
	return &Remote[T]{h: h, id: id, kind: kind, format: format}
}

// RemoteNodeCfg returns the nodecfg document of server nodeID.
func RemoteNodeCfg(h *Hub, nodeID string) *Remote[NodeCfg] {
	return NewRemote[NodeCfg](h, NodeCfgID(nodeID), NodeCfgKind, 1)
}

// doc is a Doc for the document that is not tracked, to make envelopes
// with.
func (r *Remote[T]) doc() *Doc[T] {
	return &Doc[T]{h: r.h, id: r.id, kind: r.kind, format: r.format, Validate: r.Validate}
}

// read reads the document now: its entry, nil when there is none. A copy
// that fails its checks gives a *ProblemError, and one changed outside
// Signalith is logged as such.
func (r *Remote[T]) read(ctx context.Context) (*entry, *T, error) {
	c, _ := r.h.target()
	if c == nil {
		return nil, nil, errors.New("this server is not connected to OpenSearch")
	}
	uuid, err := r.h.indexUUID(ctx)
	if err != nil {
		return nil, nil, err
	}
	src, ver, found, err := c.Get(ctx, r.h.index(), r.id)
	if err != nil || !found {
		return nil, nil, err
	}
	e, p := r.h.open(r.id, r.kind, r.format, src)
	var v *T
	if p == nil {
		if v, err = r.doc().decode(e); err != nil {
			p = &Problem{Kind: ProblemInvalid, Reason: err.Error()}
		}
	}
	if p != nil {
		p.ID, p.At = r.id, r.h.clock.Now()
		if p.Kind == ProblemTamper {
			r.h.log.Error("config.tamper: a shared setting was changed in OpenSearch outside Signalith; it is not used",
				"audit", true, "doc", r.id, "reason", p.Reason, "seq_no", ver.SeqNo)
		}
		return nil, nil, &ProblemError{Problem: *p}
	}
	return &entry{env: *e, src: src, ver: ver, uuid: uuid}, v, nil
}

// Read reads the document now. It returns its body (an empty one, with
// an empty ETag, when there is none), its ETag and who changed it last. A
// copy that fails its checks gives a *ProblemError.
func (r *Remote[T]) Read(ctx context.Context) (*T, string, By, error) {
	cur, v, err := r.read(ctx)
	if err != nil {
		return nil, "", By{}, err
	}
	if cur == nil {
		return new(T), "", By{}, nil
	}
	return v, cur.etag(), cur.env.UpdatedBy, nil
}

// Mutate changes the document with fn, as Doc.Mutate does: fn gets a copy
// of the latest body (an empty one when there is none), may return an
// error to change nothing, and runs again on the newer copy when the
// document changed in between, up to 10 times. A copy that fails its
// checks is never written over: it gives a *ProblemError.
func (r *Remote[T]) Mutate(ctx context.Context, by string, fn func(*T) error) error {
	d := r.doc()
	c, _ := r.h.target()
	var last error
	for try := range store.ModifyTries {
		if try > 0 {
			if err := retryWait(ctx, try); err != nil {
				return err
			}
		}
		base, v, err := r.read(ctx)
		if err != nil {
			return err
		}
		if base == nil {
			v = new(T)
		}
		if err := fn(v); err != nil {
			return err
		}
		e, err := d.envelope(base, by, v)
		if err != nil {
			return err
		}
		if base == nil {
			_, err = c.Create(ctx, r.h.index(), r.id, e, false)
			if errors.Is(err, store.ErrExists) {
				err = store.ErrConflict
			}
		} else {
			_, err = c.PutIf(ctx, r.h.index(), r.id, e, base.ver, false)
		}
		if !errors.Is(err, store.ErrConflict) {
			return err
		}
		last = err
	}
	return last
}
