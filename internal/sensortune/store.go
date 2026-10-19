// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sensortune

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Docs is what the store needs from OpenSearch. *store.Client has it.
type Docs interface {
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
}

// Store keeps the tuning as one document in <prefix>_endpoints, next to
// the endpoint settings: every server on the same OpenSearch reads the
// same one, and a save made from a stale copy is refused
// (store.ErrConflict). It holds no secret: SIDs, thresholds and rules.
type Store struct {
	Docs  Docs
	Index string
	Now   func() time.Time

	mu     sync.Mutex
	cached *cached
}

type cached struct {
	t       Tuning
	v       store.Version
	fetched time.Time
}

// docID is the tuning's document, and kind its kind field, as the
// endpoint store marks its documents.
const (
	docID = "sensor-tuning"
	kind  = "sensor_tuning"
)

// cacheFor is how long a read is trusted: sensors fetch every 10
// minutes, and the page every 30 seconds.
const cacheFor = 15 * time.Second

// NewStore returns a store using index "<prefix>_endpoints".
func NewStore(d Docs, prefix string) *Store {
	return &Store{Docs: d, Index: prefix + "_endpoints"}
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type doc struct {
	Kind   string `json:"kind"`
	Tuning Tuning `json:"tuning"`
}

// Get reads the tuning and its version (zero: never saved, an empty
// tuning). It reads OpenSearch at most every cacheFor; when the read
// fails, the last copy read is returned, so sensors keep getting what
// they had.
func (s *Store) Get(ctx context.Context) (Tuning, store.Version, error) {
	s.mu.Lock()
	c := s.cached
	s.mu.Unlock()
	if c != nil && s.now().Sub(c.fetched) < cacheFor {
		return c.t, c.v, nil
	}
	t, v, err := s.Read(ctx)
	if err != nil {
		if c != nil {
			return c.t, c.v, nil
		}
		return Tuning{}, store.Version{}, err
	}
	s.mu.Lock()
	s.cached = &cached{t: t, v: v, fetched: s.now()}
	s.mu.Unlock()
	return t, v, nil
}

// Read reads the tuning from OpenSearch, without the cache.
func (s *Store) Read(ctx context.Context) (Tuning, store.Version, error) {
	src, v, found, err := s.Docs.Get(ctx, s.Index, docID)
	if err != nil {
		return Tuning{}, store.Version{}, err
	}
	if !found {
		return Tuning{}, store.Version{}, nil
	}
	var d doc
	if err := json.Unmarshal(src, &d); err != nil {
		return Tuning{}, store.Version{}, err
	}
	return d.Tuning, v, nil
}

// Save normalizes, checks and saves a tuning read at version v (zero:
// never saved). It returns what was saved: a *LineError when a line is
// refused, store.ErrConflict when someone saved since v.
func (s *Store) Save(ctx context.Context, t Tuning, v store.Version, by string) (Tuning, store.Version, error) {
	t = t.Normalize()
	if err := t.Validate(); err != nil {
		return Tuning{}, store.Version{}, err
	}
	t.UpdatedBy, t.UpdatedAt = by, s.now().UTC().Truncate(time.Second)
	body := doc{Kind: kind, Tuning: t}
	var nv store.Version
	var err error
	if v.IsZero() {
		nv, err = s.Docs.Create(ctx, s.Index, docID, body, true)
		if errors.Is(err, store.ErrExists) {
			err = store.ErrConflict
		}
	} else {
		nv, err = s.Docs.PutIf(ctx, s.Index, docID, body, v, true)
	}
	if err != nil {
		return Tuning{}, store.Version{}, err
	}
	s.mu.Lock()
	s.cached = &cached{t: t, v: nv, fetched: s.now()}
	s.mu.Unlock()
	return t, nv, nil
}
