// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterlib

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Kinds and watch document of the shared asset and identity lists. A
// list is too big for one document (up to a million rows), so its CSV is
// kept in chunks (shared.PutChunks) and a small watched head,
// lookup:<name>, names the generation in use.
const (
	LookupKind      = "lookup"
	LookupChunkKind = "lookupchunk"
	LookupWatch     = "lookups"
)

// LookupNames are the shared lists.
var LookupNames = []string{assets.KindAssets, assets.KindIdentities}

// RetireAfter is how long the chunks of a list replaced since are kept,
// for a server that was reading them when the list changed.
const RetireAfter = 10 * time.Minute

// LookupHead is the body of lookup:<name>: the generation of the list
// in use, and the generations replaced since and not deleted yet.
type LookupHead struct {
	Gen    int64  `json:"gen"`
	Chunks int    `json:"chunks"`
	Rows   int    `json:"rows"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	// Retired are generations replaced since, whose chunks are deleted
	// RetireAfter after At.
	Retired      []RetiredGen `json:"retired,omitempty"`
	From         *From        `json:"from,omitempty"`
	shared.Extra `json:"-"`
}

// RetiredGen is a generation of a list replaced at At.
type RetiredGen struct {
	Gen    int64     `json:"gen"`
	Chunks int       `json:"chunks"`
	At     time.Time `json:"at"`
}

func (h *LookupHead) check(name string) error {
	if !slices.Contains(LookupNames, name) {
		return fmt.Errorf("unknown list %q", name)
	}
	if h.Gen <= 0 || h.Chunks <= 0 || len(h.SHA256) != 64 {
		return errors.New("it does not name a version of the list")
	}
	return nil
}

func (h *LookupHead) ref(name string) shared.ChunkRef {
	return shared.ChunkRef{Kind: LookupChunkKind, Name: name, Gen: h.Gen, N: h.Chunks}
}

// Lookups keeps an assets.Store's lists in the shared settings: it is
// the store's assets.Backend.
type Lookups struct {
	Docs *Docs
	// Node is this server's name.
	Node string
	// Writable refuses changes while the shared settings cannot be
	// changed (shared.Runtime.Writable); nil allows them.
	Writable func() error
	// Source is where a change comes from, FromPage when "".
	Source string
	Now    func() time.Time
}

func (b *Lookups) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// NoList is the version of a list that was never uploaded, for If-Match:
// a page that showed no list does not replace one uploaded meanwhile.
const NoList = "none"

// ETag returns the version of the list kind in use, NoList when there is
// none.
func (b *Lookups) ETag(kind string) string {
	if _, etag, ok := b.Docs.Lookups().Get(kind); ok {
		return etag
	}
	return NoList
}

// Head returns the head of the list kind, nil when there is none.
func (b *Lookups) Head(kind string) *LookupHead {
	h, _, _ := b.Docs.Lookups().Get(kind)
	return h
}

// Put replaces the list kind with data, which has rows rows, read at
// etag ("" for the latest): the chunks of a new generation first, then
// the head, so a reader never sees half a list. A change made since etag
// gives a *shared.StaleError naming who made it.
func (b *Lookups) Put(ctx context.Context, by, kind string, data []byte, etag string) error {
	if b.Writable != nil {
		if err := b.Writable(); err != nil {
			return err
		}
	}
	c, hub := b.Docs.Lookups(), b.Docs.Hub()
	if c == nil || hub == nil {
		return &shared.PausedError{Why: "the shared settings are not read yet"}
	}
	if etag != "" {
		// Refused before the chunks are written, when it is plain already.
		if b.ETag(kind) != etag {
			by, node, at := whoOf(c, kind)
			return &shared.StaleError{By: by, Node: node, At: at}
		}
	}
	rows, err := countRows(kind, data)
	if err != nil {
		return err
	}
	now := b.now()
	// A generation newer than the one in use, and never written before:
	// one already there (two uploads within the clock's resolution) is
	// skipped.
	gen := now.UnixNano()
	if h := b.Head(kind); h != nil {
		gen = max(gen, h.Gen+1)
	}
	var ref shared.ChunkRef
	var sum string
	for try := 0; ; try++ {
		ref, sum, err = hub.PutChunks(ctx, by, shared.ChunkRef{Kind: LookupChunkKind, Name: kind, Gen: gen}, data)
		if !errors.Is(err, store.ErrExists) || try == 3 {
			break
		}
		gen += 1 + rand.Int64N(1000)
	}
	if err != nil {
		return err
	}
	source := b.Source
	if source == "" {
		source = FromPage
	}
	set := func(cur *LookupHead) {
		if cur.Gen != 0 {
			cur.Retired = append(cur.Retired, RetiredGen{Gen: cur.Gen, Chunks: cur.Chunks, At: now.UTC()})
		}
		cur.Gen, cur.Chunks, cur.Rows, cur.SHA256, cur.Bytes = ref.Gen, ref.N, rows, sum, len(data)
		cur.From = stamp(source, b.Node, now)
	}
	err = b.writeHead(ctx, by, kind, etag, set)
	if err != nil {
		// The head names the generation before: these chunks are no use.
		_ = hub.DeleteChunks(context.WithoutCancel(ctx), ref)
	}
	return err
}

// writeHead changes the head of the list kind with set, read at etag (""
// for the latest), making it when there is none.
func (b *Lookups) writeHead(ctx context.Context, by, kind, etag string, set func(*LookupHead)) error {
	c := b.Docs.Lookups()
	for range store.ModifyTries {
		if _, _, ok := c.Get(kind); (!ok && etag == "") || etag == NoList {
			h := &LookupHead{}
			set(h)
			_, err := c.Create(ctx, by, kind, h)
			if errors.Is(err, store.ErrExists) && etag == NoList {
				_ = c.Refresh(ctx, kind)
				by, node, at := whoOf(c, kind)
				return &shared.StaleError{By: by, Node: node, At: at}
			}
			if !errors.Is(err, store.ErrExists) {
				return err
			}
			// Another server made it meanwhile: change that one.
			if err := c.Refresh(ctx, kind); err != nil {
				return err
			}
			continue
		}
		var err error
		if etag != "" {
			_, err = c.MutateIf(ctx, by, kind, etag, func(h *LookupHead) error { set(h); return nil })
		} else {
			_, err = c.Mutate(ctx, by, kind, func(h *LookupHead) error { set(h); return nil })
		}
		if !errors.Is(err, store.ErrNotFound) || etag != "" {
			return err
		}
	}
	return errors.New("the list kept changing; try again")
}

// Read returns the list kind in use and its head; nil, nil, nil when
// there is none. A list replaced while it was read is read again from
// the newer head.
func (b *Lookups) Read(ctx context.Context, kind string) ([]byte, *LookupHead, error) {
	hub := b.Docs.Hub()
	var err error
	for try := range 2 {
		if try > 0 {
			if rerr := b.Docs.Lookups().Refresh(ctx, kind); rerr != nil {
				return nil, nil, rerr
			}
		}
		h := b.Head(kind)
		if h == nil {
			return nil, nil, nil
		}
		var data []byte
		if data, err = hub.ReadChunks(ctx, h.ref(kind), h.SHA256); err == nil {
			return data, h, nil
		}
		if !errors.Is(err, shared.ErrChunkMissing) {
			return nil, nil, err
		}
	}
	return nil, nil, err
}

// Housekeep deletes the chunks of the generations retired more than
// RetireAfter ago, and drops them from their heads. Every server may run
// it: deleting chunks already gone is no error, and the heads change by
// compare-and-set.
func (b *Lookups) Housekeep(ctx context.Context, by string) error {
	c, hub := b.Docs.Lookups(), b.Docs.Hub()
	if c == nil || hub == nil {
		return nil
	}
	if b.Writable != nil && b.Writable() != nil {
		return nil
	}
	cut := b.now().Add(-RetireAfter)
	var errs []error
	for _, name := range LookupNames {
		h := b.Head(name)
		if h == nil {
			continue
		}
		var done []int64
		for _, r := range h.Retired {
			if r.At.After(cut) {
				continue
			}
			if err := hub.DeleteChunks(ctx, shared.ChunkRef{Kind: LookupChunkKind, Name: name, Gen: r.Gen, N: r.Chunks}); err != nil {
				errs = append(errs, err)
				continue
			}
			done = append(done, r.Gen)
		}
		if len(done) == 0 {
			continue
		}
		_, err := c.Mutate(ctx, by, name, func(h *LookupHead) error {
			h.Retired = slices.DeleteFunc(h.Retired, func(r RetiredGen) bool { return slices.Contains(done, r.Gen) })
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// countRows checks data as the list kind and returns its rows.
func countRows(kind string, data []byte) (int, error) {
	switch kind {
	case assets.KindAssets:
		as, err := assets.ParseAssets(data)
		return len(as), err
	case assets.KindIdentities:
		ids, err := assets.ParseIdentities(data)
		return len(ids), err
	}
	return 0, fmt.Errorf("unknown list %q", kind)
}
