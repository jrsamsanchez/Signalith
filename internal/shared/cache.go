package shared

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// cache.enc keeps the last shared configuration this server applied, in
// its state folder, sealed under its master key: the documents as stored,
// with their MACs and versions, and the revisions applied. A server that
// starts while OpenSearch cannot be reached runs from it, and it can put
// the documents back if the config index is lost (signalith cluster
// import --from-cache). The file is a small JSON object with one sealed
// field, so "signalith secrets rotate-master" re-seals it like the other
// files that keep secrets.

// cacheField is the field the cache of a cluster and index prefix is
// sealed under, so a cache.enc relabelled with another cluster or prefix
// does not open.
func cacheField(clusterID, prefix string) string { return "cluster.cache/" + clusterID + "/" + prefix }

// CacheMaxAge is how old a cache may be and still be used: the age at
// which tombstones are removed, after which a cache could bring back
// deleted items.
const CacheMaxAge = TombstoneAge

// CacheRefresh is how long a cache may go unwritten while the shared
// settings do not change: it is written again then, so the cache of a
// server that keeps reading OpenSearch never gets older than CacheMaxAge.
const CacheRefresh = 24 * time.Hour

// CachePath is where cache.enc is kept in the state folder.
func CachePath(stateDir string) string { return filepath.Join(stateDir, "cluster", "cache.enc") }

// CacheDoc is one document in the cache, as OpenSearch had it.
type CacheDoc struct {
	ID     string          `json:"id"`
	Seq    int64           `json:"seq"`
	Term   int64           `json:"term"`
	Source json.RawMessage `json:"source"`
}

// CacheData is what the cache keeps.
type CacheData struct {
	IndexUUID  string           `json:"index_uuid"`
	AppliedSeq int64            `json:"applied_seq"`
	Docs       []CacheDoc       `json:"docs"`
	Floors     map[string]int64 `json:"floors"`
	MaxRev     int64            `json:"max_rev"`
	WrittenAt  time.Time        `json:"written_at"`
}

// cacheFile is cache.enc as stored.
type cacheFile struct {
	Format    int    `json:"format"`
	ClusterID string `json:"cluster_id"`
	Prefix    string `json:"prefix"`
	Sealed    string `json:"sealed"`
}

// Cache is the cache.enc of one cluster and index prefix.
type Cache struct {
	Path      string
	Master    Sealer
	ClusterID string
	Prefix    string
}

var (
	// ErrCacheOld is a cache older than CacheMaxAge, which is not used.
	ErrCacheOld = errors.New("the copy of the shared settings is older than 30 days, so it is not used")
	// ErrCacheOther is a cache of another cluster or index prefix.
	ErrCacheOther = errors.New("the copy of the shared settings is of another cluster or index prefix")
)

// CacheHeader says which cluster and index prefix a cache.enc is of,
// without opening it; an error wrapping fs.ErrNotExist when there is none.
func CacheHeader(path string) (clusterID, prefix string, err error) {
	var f cacheFile
	if err := readJSON(path, &f); err != nil {
		return "", "", err
	}
	return f.ClusterID, f.Prefix, nil
}

// Write replaces the cache with d.
func (c Cache) Write(d CacheData) error {
	plain, err := json.Marshal(d)
	if err != nil {
		return err
	}
	sealed, err := c.Master.Seal(cacheField(c.ClusterID, c.Prefix), string(plain))
	clear(plain)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cacheFile{Format: 1, ClusterID: c.ClusterID, Prefix: c.Prefix, Sealed: sealed}, "", "  ")
	if err != nil {
		return err
	}
	if err := securefile.MkdirPrivate(filepath.Dir(c.Path)); err != nil {
		return err
	}
	p, err := securefile.PreparePrivate(c.Path, append(data, '\n'))
	if err != nil {
		return err
	}
	return p.Commit()
}

// Read opens the cache: an error wrapping fs.ErrNotExist when there is
// none, ErrCacheOther when it is another cluster's, ErrCacheOld when it
// was written more than CacheMaxAge before now. With ErrCacheOld it still
// returns the revisions applied (Floors and MaxRev) and the cluster
// document, which says what cluster key they are of, but no other
// document: revisions only go up, so an old cache's are still lower
// bounds that refuse a copy written back from before.
func (c Cache) Read(now time.Time) (CacheData, error) {
	var f cacheFile
	if err := readJSON(c.Path, &f); err != nil {
		return CacheData{}, err
	}
	if f.Format != 1 {
		return CacheData{}, fmt.Errorf("%s was written by a newer version of Signalith", c.Path)
	}
	if f.Prefix != c.Prefix || c.ClusterID != "" && f.ClusterID != c.ClusterID {
		return CacheData{}, ErrCacheOther
	}
	plain, err := c.Master.Open(cacheField(f.ClusterID, f.Prefix), f.Sealed)
	if err != nil {
		return CacheData{}, fmt.Errorf("%s: %w", c.Path, err)
	}
	var d CacheData
	if err := json.Unmarshal([]byte(plain), &d); err != nil {
		return CacheData{}, fmt.Errorf("%s is damaged: %w", c.Path, err)
	}
	if now.Sub(d.WrittenAt) > CacheMaxAge {
		old := CacheData{Floors: d.Floors, MaxRev: d.MaxRev, WrittenAt: d.WrittenAt}
		for _, cd := range d.Docs {
			if cd.ID == ClusterDocID {
				old.Docs = append(old.Docs, cd)
			}
		}
		return old, ErrCacheOld
	}
	return d, nil
}

// Remove deletes the cache, as when it is too old to use.
func (c Cache) Remove() error {
	err := os.Remove(c.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// ResealCacheFile passes the sealed part of cache.enc's text through fn,
// for "signalith secrets" (see config.SecretFile).
func ResealCacheFile(data []byte, fn secrets.Reseal) ([]byte, int, error) {
	var f cacheFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, 0, fmt.Errorf("not valid JSON: %w", err)
	}
	v, err := fn(secrets.Stored{Field: cacheField(f.ClusterID, f.Prefix), Label: "copy of the shared settings", Value: f.Sealed})
	if err != nil || v == f.Sealed {
		return data, 0, err
	}
	f.Sealed = v
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	return append(out, '\n'), 1, nil
}

// CacheWriter writes the hub's documents to the cache after a change, at
// most once per Timing.CacheEvery.
type CacheWriter struct {
	hub   *Hub
	cache Cache
	kick  chan struct{}

	mu      sync.Mutex
	lastErr error
}

// NewCacheWriter returns a writer of h's documents to c; Run starts it.
func NewCacheWriter(h *Hub, c Cache) *CacheWriter {
	w := &CacheWriter{hub: h, cache: c, kick: make(chan struct{}, 1)}
	h.OnApplied(w.Changed)
	return w
}

// Changed says something new was applied.
func (w *CacheWriter) Changed() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// Err returns the error of the last write, or nil.
func (w *CacheWriter) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

// Flush writes the cache now.
func (w *CacheWriter) Flush() error {
	err := w.cache.Write(w.hub.Snapshot())
	w.mu.Lock()
	w.lastErr = err
	w.mu.Unlock()
	if err != nil {
		w.hub.log.Warn("could not save the copy of the shared settings", "path", w.cache.Path, "err", err)
	}
	return err
}

// Run writes the cache after each change, waiting Timing.CacheEvery
// between writes, until ctx ends; then it writes what is left. Without a
// change it writes the cache again every CacheRefresh, as long as the hub
// read the shared settings from OpenSearch in that time, so that the
// cache does not get too old to use.
func (w *CacheWriter) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			select {
			case <-w.kick:
				_ = w.Flush()
			default:
			}
			return
		case <-w.kick:
		case <-w.hub.clock.After(CacheRefresh):
			if w.hub.clock.Now().Sub(w.hub.Confirmed()) > CacheRefresh {
				continue
			}
		}
		_ = w.Flush()
		select {
		case <-ctx.Done():
		case <-w.hub.clock.After(w.hub.opts.Timing.CacheEvery):
		}
	}
}

// RestoreFromCache writes the documents of a cache.enc back into the
// config index, as "signalith cluster import --from-cache" does after the
// index was lost: each with _create, as it was stored, with its MAC and
// revision, so it verifies under the same key on every member and is not
// taken for a rollback. A document that is there already is left alone.
// It returns the ids written and those left alone.
func RestoreFromCache(ctx context.Context, c *store.Client, prefix string, d CacheData) (written, there []string, err error) {
	if err := EnsureConfig(ctx, c, prefix); err != nil {
		return nil, nil, err
	}
	index := ConfigIndex(prefix)
	var errs []error
	for _, cd := range d.Docs {
		var e Envelope
		if err := json.Unmarshal(cd.Source, &e); err != nil || e.ID != cd.ID || e.MAC == "" {
			errs = append(errs, fmt.Errorf("%s: the copy is not a signed document", cd.ID))
			continue
		}
		// The store's mark of the write that made the copy is not part of
		// it; a new one is added.
		e.WriteID = ""
		_, err := c.Create(ctx, index, cd.ID, &e, false)
		switch {
		case errors.Is(err, store.ErrExists):
			there = append(there, cd.ID)
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", cd.ID, err))
		default:
			written = append(written, cd.ID)
		}
	}
	// A server whose index was made again reads everything again by
	// itself (the index uuid changed); collections are listed again in
	// full at the next resync.
	return written, there, errors.Join(errs...)
}
