// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package reportkeys

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The cluster's list: one shared document per key, reportkey:<id>.
const (
	Kind   = "reportkey"
	Watch  = "reportkeys"
	Format = 1
	// ImportName names the importer of a joining server's own keys.
	ImportName = "report-keys"
)

// KeyBody is a key as the shared settings keep it.
type KeyBody struct {
	Key
	shared.Extra `json:"-"`
}

func validate(b *KeyBody) error {
	if !ValidID(b.ID) || (b.Source != FromCluster && b.Source != FromMaster) {
		return errors.New("not a report key")
	}
	if _, err := b.PublicKey(); err != nil {
		return err
	}
	if _, err := CheckReason(b.Reason); err != nil {
		return err
	}
	return nil
}

func validateItem(name string, b *KeyBody) error {
	if name != b.ID {
		return fmt.Errorf("the report key %q is filed under the wrong ID", name)
	}
	return nil
}

// Shared keeps the list of a cluster in its shared settings, made again
// on each hub the runtime builds (Track).
type Shared struct {
	// Writable says why the shared settings cannot be changed on this
	// server now; nil allows changes.
	Writable func() error

	mu sync.Mutex
	c  *shared.Collection[KeyBody]
}

// NewShared returns the holder; Track makes the collection.
func NewShared(writable func() error) *Shared { return &Shared{Writable: writable} }

// Track makes the collection on h.
func (s *Shared) Track(h *shared.Hub) {
	c := shared.NewCollection[KeyBody](h, Kind, Watch, Format)
	c.Validate, c.ValidateItem = validate, validateItem
	s.mu.Lock()
	s.c = c
	s.mu.Unlock()
}

// Reset is for the runtime's tracker interface.
func (s *Shared) Reset() {}

var errClosed = errors.New("the shared settings are not open")

func (s *Shared) coll() (*shared.Collection[KeyBody], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.c == nil {
		return nil, errClosed
	}
	return s.c, nil
}

func (s *Shared) List(context.Context) ([]Key, error) {
	c, err := s.coll()
	if err != nil {
		return nil, err
	}
	var out []Key
	for _, it := range c.List() {
		if it.Value != nil {
			out = append(out, it.Value.Key)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].FirstUsed.Before(out[j].FirstUsed) })
	return out, nil
}

func (s *Shared) writable() error {
	if s.Writable != nil {
		return s.Writable()
	}
	return nil
}

func (s *Shared) Use(ctx context.Context, pub ed25519.PublicKey, source string, now time.Time) error {
	c, err := s.coll()
	if err != nil {
		return err
	}
	ks, err := s.List(ctx)
	if err != nil {
		return err
	}
	next, changed := Apply(ks, pub, source, now)
	if !changed {
		return nil
	}
	if err := s.writable(); err != nil {
		return err
	}
	return s.save(ctx, c, ks, next)
}

func (s *Shared) Revoke(ctx context.Context, id, by, reason string, now time.Time) error {
	if err := s.writable(); err != nil {
		return err
	}
	c, err := s.coll()
	if err != nil {
		return err
	}
	ks, err := s.List(ctx)
	if err != nil {
		return err
	}
	next, err := RevokeIn(ks, id, by, reason, now)
	if err != nil {
		return err
	}
	return s.save(ctx, c, ks, next)
}

// save writes the keys of next that differ from before. A key another
// server added at the same moment is kept (ErrExists); a key changed
// meanwhile is changed again on the newer copy.
func (s *Shared) save(ctx context.Context, c *shared.Collection[KeyBody], before, next []Key) error {
	old := map[string]Key{}
	for _, k := range before {
		old[k.ID] = k
	}
	for _, k := range next {
		o, had := old[k.ID]
		switch {
		case !had:
			body := &KeyBody{Key: k}
			if _, err := c.Create(ctx, "signalith", k.ID, body); err != nil && !errors.Is(err, store.ErrExists) {
				return err
			}
		case !sameKey(o, k):
			k := k
			if _, err := c.Mutate(ctx, "signalith", k.ID, func(b *KeyBody) error {
				// Revoked or retired stays so: take the earlier time.
				if k.Retired != nil && b.Retired == nil {
					b.Retired = k.Retired
				}
				if k.Revoked != nil && b.Revoked == nil {
					b.Revoked, b.RevokedBy, b.Reason = k.Revoked, k.RevokedBy, k.Reason
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func sameKey(a, b Key) bool {
	return (a.Retired == nil) == (b.Retired == nil) && (a.Revoked == nil) == (b.Revoked == nil)
}

// Importer copies a server's own keys (the file at path, read when it
// runs) into the shared list when it founds or joins a cluster, as
// retired, so its older reports still verify there.
func Importer(s *Shared, path func() string) shared.Importer {
	return shared.Importer{
		Name: ImportName,
		Source: func() (string, error) {
			ks, err := Read(path())
			if err != nil || len(ks) == 0 {
				return "", err
			}
			return fmt.Sprintf("keys:%d:%s", len(ks), ks[len(ks)-1].ID), nil
		},
		Run: func(ctx context.Context, by string) error {
			ks, err := Read(path())
			if err != nil {
				return err
			}
			c, err := s.coll()
			if err != nil {
				return err
			}
			now := time.Now().UTC().Truncate(time.Second)
			for _, k := range ks {
				if k.Retired == nil && k.Revoked == nil {
					k.Retired = &now
				}
				body := &KeyBody{Key: k}
				if validate(body) != nil {
					continue
				}
				if _, err := c.Create(ctx, by, k.ID, body); err != nil && !errors.Is(err, store.ErrExists) {
					return fmt.Errorf("report key %s: %w", k.ID, err)
				}
			}
			return nil
		},
	}
}

// Exporter writes the cluster's list as the file of a server on its own
// (path, its own), for signalith cluster export, so the cluster's reports
// still verify there.
func Exporter(s *Shared, path func() string) shared.Exporter {
	return shared.Exporter{Name: ImportName, Run: func(ctx context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
		dest := path()
		ks, err := s.List(ctx)
		if dest == "" || err != nil || len(ks) == 0 {
			return nil, err
		}
		out := t.Under(dest)
		if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
			return nil, err
		}
		if err := write(out, ks); err != nil {
			return nil, err
		}
		return []shared.ExportedFile{{Path: out, Dest: dest}}, nil
	}}
}
