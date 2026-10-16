package clusterarchive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// maxIDs is how many archive IDs of one index Reserve tries.
const maxIDs = 10000

// PendingAge is how long a manifest may stay pending before Housekeep
// takes it for one whose server stopped while writing it, and removes it
// with its files. Writing and checking even a large archive takes far
// less.
const PendingAge = 6 * time.Hour

// Manifests keeps archive manifests in the runtime index, for
// retention.Archive. It implements retention.ManifestStore.
type Manifests struct {
	Client Client
	Prefix string
	// Server and NodeID name this server in the manifests it writes.
	Server, NodeID string
	Now            func() time.Time
}

func (s *Manifests) index() string { return cluster.RuntimeIndex(s.Prefix) }

func (s *Manifests) doc(m retention.Manifest) (doc, error) {
	body, err := json.Marshal(m)
	return doc{Kind: KindArchive, Name: m.ID, Node: s.Server, NodeID: s.NodeID, State: m.State, At: now(s.Now), Body: body}, err
}

// Reserve implements retention.ManifestStore: the first ID of the index
// whose document _create makes, so of two servers each gets its own.
func (s *Manifests) Reserve(ctx context.Context, m retention.Manifest, skip func(string) bool) (string, error) {
	m.Server, m.State = s.Server, retention.ManifestPending
	for n := 1; n <= maxIDs; n++ {
		id := retention.ArchiveID(m.Index, n)
		if skip != nil && skip(id) {
			continue
		}
		m.ID, m.File = id, id+".ndjson.gz"
		d, err := s.doc(m)
		if err != nil {
			return "", err
		}
		_, err = s.Client.Create(ctx, s.index(), ArchiveDocID(id), d, true)
		if errors.Is(err, store.ErrExists) {
			continue
		}
		if err != nil {
			return "", err
		}
		return id, nil
	}
	return "", fmt.Errorf("%s has %d archives already", m.Index, maxIDs)
}

// Complete implements retention.ManifestStore.
func (s *Manifests) Complete(ctx context.Context, m retention.Manifest) error {
	cur, v, found, err := read(ctx, s.Client, s.Prefix, ArchiveDocID(m.ID))
	switch {
	case err != nil:
		return err
	case !found:
		return fmt.Errorf("the reserved archive %s is gone", m.ID)
	case cur.State != retention.ManifestPending || cur.NodeID != s.NodeID:
		return fmt.Errorf("the archive %s is no longer this server's to finish", m.ID)
	}
	m.Server, m.State = s.Server, retention.ManifestComplete
	d, err := s.doc(m)
	if err != nil {
		return err
	}
	_, err = s.Client.PutIf(ctx, s.index(), ArchiveDocID(m.ID), d, v, true)
	return err
}

// Abandon implements retention.ManifestStore: only a pending manifest is
// removed.
func (s *Manifests) Abandon(ctx context.Context, id string) error {
	cur, v, found, err := read(ctx, s.Client, s.Prefix, ArchiveDocID(id))
	if err != nil || !found || cur.State != retention.ManifestPending {
		return err
	}
	err = s.Client.DeleteIf(ctx, s.index(), ArchiveDocID(id), v, true)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// all reads every manifest document.
func (s *Manifests) all(ctx context.Context) ([]retention.Manifest, []string, error) {
	docs, err := s.Client.SearchDocs(ctx, s.index(), map[string]any{"term": map[string]any{"kind": KindArchive}})
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 404 {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var out []retention.Manifest
	var problems []string
	for _, sd := range docs {
		var d doc
		var m retention.Manifest
		if json.Unmarshal(sd.Source, &d) != nil || json.Unmarshal(d.Body, &m) != nil || sd.ID != ArchiveDocID(m.ID) {
			problems = append(problems, sd.ID+": not a valid archive manifest")
			continue
		}
		if m.State == "" {
			m.State = d.State
		}
		out = append(out, m)
	}
	return out, problems, nil
}

// List implements retention.ManifestStore: complete manifests, newest day
// first.
func (s *Manifests) List(ctx context.Context) ([]retention.Manifest, []string, error) {
	all, problems, err := s.all(ctx)
	if err != nil {
		return nil, nil, err
	}
	var out []retention.Manifest
	for _, m := range all {
		if m.State == retention.ManifestComplete {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Day != out[j].Day {
			return out[i].Day > out[j].Day
		}
		return out[i].ID < out[j].ID
	})
	return out, problems, nil
}

// Get implements retention.ManifestStore.
func (s *Manifests) Get(ctx context.Context, id string) (retention.Manifest, error) {
	d, _, found, err := read(ctx, s.Client, s.Prefix, ArchiveDocID(id))
	if err != nil {
		return retention.Manifest{}, err
	}
	var m retention.Manifest
	if !found || json.Unmarshal(d.Body, &m) != nil || m.ID != id || d.State != retention.ManifestComplete {
		return retention.Manifest{}, retention.ErrArchiveNotFound
	}
	m.State = d.State
	return m, nil
}

// Import records a manifest read from a file, as complete, unless one of
// that ID exists: it reports whether it did.
func (s *Manifests) Import(ctx context.Context, m retention.Manifest) (bool, error) {
	m.State = retention.ManifestComplete
	d, err := s.doc(m)
	if err != nil {
		return false, err
	}
	d.Node, d.NodeID = m.Server, ""
	_, err = s.Client.Create(ctx, s.index(), ArchiveDocID(m.ID), d, true)
	if errors.Is(err, store.ErrExists) {
		return false, nil
	}
	return err == nil, err
}

// Housekeep removes the manifests left pending for longer than
// PendingAge, by a server that stopped while writing the archive, and
// the files of those archives in dir (the shared archive folder). It
// returns how many.
func (s *Manifests) Housekeep(ctx context.Context, dir string) (int, error) {
	docs, err := s.Client.SearchDocs(ctx, s.index(), map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"kind": KindArchive}},
		map[string]any{"term": map[string]any{"state": retention.ManifestPending}},
	}}})
	if err != nil {
		return 0, err
	}
	cut := now(s.Now).Add(-PendingAge)
	n := 0
	for _, sd := range docs {
		var d doc
		if json.Unmarshal(sd.Source, &d) != nil || d.State != retention.ManifestPending || !d.At.Before(cut) {
			continue
		}
		if dir != "" && d.Name != "" && filepath.Base(d.Name) == d.Name {
			for _, ext := range []string{".ndjson.gz", ".json"} {
				if err := os.Remove(filepath.Join(dir, d.Name+ext)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return n, err
				}
			}
		}
		if err := s.Client.DeleteIf(ctx, s.index(), sd.ID, sd.Version, true); err != nil && !errors.Is(err, store.ErrNotFound) {
			return n, err
		}
		n++
	}
	return n, nil
}
