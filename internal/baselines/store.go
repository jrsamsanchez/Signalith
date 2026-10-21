// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package baselines

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Client is what the baselines need from OpenSearch: *store.Client.
type Client interface {
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	MGet(ctx context.Context, refs []store.Ref) ([]store.Doc, error)
	Do(ctx context.Context, method, path string, body any, out any) error
}

// Store keeps the baselines in the index "<prefix>_baselines": the
// settings, where learning got to, the IP database and one profile per
// check and entity. The index is outside the event indices' pattern, so
// retention never touches it; forgotten profiles are removed instead.
type Store struct {
	Client Client
	Index  string
}

// NewStore returns the store of a prefix.
func NewStore(c Client, prefix string) *Store {
	return &Store{Client: c, Index: prefix + "_baselines"}
}

// Document IDs of the store's own documents.
const (
	settingsID = "settings"
	stateID    = "state"
	ipdbID     = "ipdb"
	ipdbMetaID = "ipdb_meta"
)

// EnsureIndex creates the index if it is not there.
func (s *Store) EnsureIndex(ctx context.Context) error {
	kw := map[string]any{"type": "keyword"}
	date := map[string]any{"type": "date"}
	body := map[string]any{
		"settings": map[string]any{"number_of_shards": 1, "auto_expand_replicas": "0-1", "refresh_interval": "1s"},
		"mappings": map[string]any{"dynamic": "false", "properties": map[string]any{
			"kind": kw, "check": kw, "entity": kw,
			"first_seen": date, "last_seen": date, "through": date,
		}},
	}
	err := s.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index), body, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == http.StatusBadRequest && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// get reads one of the store's own documents into v. It reports whether
// the document is there, and its version.
func (s *Store) get(ctx context.Context, id string, v any) (store.Version, bool, error) {
	src, ver, found, err := s.Client.Get(ctx, s.Index, id)
	if err != nil || !found {
		return store.Version{}, false, err
	}
	return ver, true, json.Unmarshal(src, v)
}

// put writes one of the store's own documents: created when ver is zero,
// otherwise only over that version (store.ErrConflict when it changed).
func (s *Store) put(ctx context.Context, id string, doc any, ver store.Version) (store.Version, error) {
	if ver.IsZero() {
		nv, err := s.Client.Create(ctx, s.Index, id, doc, true)
		if errors.Is(err, store.ErrExists) {
			return store.Version{}, store.ErrConflict
		}
		return nv, err
	}
	return s.Client.PutIf(ctx, s.Index, id, doc, ver, true)
}

// Settings returns the saved settings (the defaults when none were
// saved) and their version, zero when never saved.
func (s *Store) Settings(ctx context.Context) (Settings, store.Version, error) {
	var d settingsDoc
	v, found, err := s.get(ctx, settingsID, &d)
	if err != nil || !found {
		return Settings{}, store.Version{}, err
	}
	return d.Settings, v, nil
}

type settingsDoc struct {
	Kind string `json:"kind"`
	Settings
}

// SaveSettings saves settings over the version read (zero when none were
// saved yet); store.ErrConflict when they changed in between.
func (s *Store) SaveSettings(ctx context.Context, st Settings, ver store.Version) (store.Version, error) {
	return s.put(ctx, settingsID, settingsDoc{Kind: "settings", Settings: st}, ver)
}

// State is where learning got to, kept by the server that runs the
// background jobs.
type State struct {
	Kind string `json:"kind"`
	// Through is the end of the last hour learned from; LiveFrom the
	// time the baselines first ran. Hours that ended before it are only
	// learned from, so the history already stored when baselines are
	// first turned on teaches them without raising anything.
	Through  time.Time `json:"through"`
	LiveFrom time.Time `json:"live_from"`
	// Checks has each check's counts.
	Checks map[string]*CheckState `json:"checks,omitempty"`
	// LastRun is when an hour was last learned from, LastError the last
	// round's error.
	LastRun   time.Time `json:"last_run,omitzero"`
	LastError string    `json:"last_error,omitempty"`
	Epoch     int64     `json:"epoch"`
	Node      string    `json:"node,omitempty"`
}

// CheckState is one check's counts.
type CheckState struct {
	// Raised counts the risk events raised, Excepted those an exception
	// held back and Capped those over the most one hour may raise.
	Raised     int64     `json:"raised"`
	Excepted   int64     `json:"excepted"`
	Capped     int64     `json:"capped"`
	LastRaised time.Time `json:"last_raised,omitzero"`
	// Truncated is the last hour whose search had more rows than were
	// read, Full the last hour a new entity was not learned because the
	// check already had MaxProfiles.
	Truncated time.Time `json:"truncated,omitzero"`
	Full      time.Time `json:"full,omitzero"`
	// TruncatedAfter is the last user or host the truncated search read:
	// those after it in name order were not learned that hour.
	TruncatedAfter string `json:"truncated_after,omitempty"`
	// Started is when the check started learning: when baselines first
	// ran, or when it was turned on or reset since.
	Started time.Time `json:"started,omitzero"`
	// Behind is the next hour the check learns from when it is behind
	// the others: after one of its searches failed, or while it learns
	// the history after it was turned on or reset. Zero when it keeps
	// up. LiveFrom is when it was turned on or reset: the hours before
	// only teach it. It stays once the check caught up.
	Behind   time.Time `json:"behind,omitzero"`
	LiveFrom time.Time `json:"live_from,omitzero"`
	// Unlearned is when the newest value asked to be forgotten was
	// (ForgetValue.At), once it was.
	Unlearned time.Time `json:"unlearned,omitzero"`
	// DataFrom is the first hour the check had data to learn from (new
	// country: sign-ins from the internet).
	DataFrom time.Time `json:"data_from,omitzero"`
	// Error is why it last could not learn an hour, ErrorAt when; empty
	// once it learned one again.
	Error   string    `json:"error,omitempty"`
	ErrorAt time.Time `json:"error_at,omitzero"`
	// Skipped is the end of the hours it skipped because it could not
	// learn from them for over a week.
	Skipped time.Time `json:"skipped,omitzero"`
}

// ErrStale refuses a state write over one a newer job holder made.
var ErrStale = errors.New("another server now runs the behavior baselines")

// State returns the state and its version; found is false before the
// baselines first ran.
func (s *Store) State(ctx context.Context) (State, store.Version, bool, error) {
	var st State
	v, found, err := s.get(ctx, stateID, &st)
	return st, v, found, err
}

// SaveState writes the state over ver, unless a server with a newer job
// lease wrote it since.
func (s *Store) SaveState(ctx context.Context, st State, ver store.Version) (store.Version, error) {
	st.Kind = "state"
	nv, err := s.put(ctx, stateID, st, ver)
	if !errors.Is(err, store.ErrConflict) {
		return nv, err
	}
	cur, cv, found, gerr := s.State(ctx)
	if gerr != nil {
		return store.Version{}, gerr
	}
	if found && cur.Epoch > st.Epoch {
		return store.Version{}, ErrStale
	}
	return s.put(ctx, stateID, st, cv)
}

// Profiles reads the profiles of entities of a check; missing ones are
// nil.
func (s *Store) Profiles(ctx context.Context, check string, entities []string) ([]*Profile, error) {
	refs := make([]store.Ref, len(entities))
	for i, e := range entities {
		refs[i] = store.Ref{Index: s.Index, ID: ProfileID(check, e)}
	}
	docs, err := s.Client.MGet(ctx, refs)
	if err != nil {
		return nil, err
	}
	out := make([]*Profile, len(entities))
	for i, d := range docs {
		if i >= len(out) || !d.Found {
			continue
		}
		var p Profile
		if err := json.Unmarshal(d.Source, &p); err != nil {
			return nil, fmt.Errorf("profile %s: %w", d.ID, err)
		}
		if p.Check == check && p.Entity == entities[i] {
			out[i] = &p
		}
	}
	return out, nil
}

// WriteProfiles stores profiles, replacing what was there.
func (s *Store) WriteProfiles(ctx context.Context, ps []*Profile) error {
	if len(ps) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, p := range ps {
		if err := enc.Encode(map[string]any{"index": map[string]any{"_index": s.Index, "_id": ProfileID(p.Check, p.Entity)}}); err != nil {
			return err
		}
		if err := enc.Encode(p); err != nil {
			return err
		}
	}
	var out struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Error *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := s.Client.Do(ctx, http.MethodPost, "/_bulk", buf.Bytes(), &out); err != nil {
		return err
	}
	if out.Errors {
		n, first := 0, ""
		for _, item := range out.Items {
			for _, r := range item {
				if r.Error != nil {
					n++
					if first == "" {
						first = r.Error.Type + ": " + r.Error.Reason
					}
				}
			}
		}
		if n > 0 {
			return fmt.Errorf("%d baseline profiles were not stored: %s", n, first)
		}
	}
	return nil
}

// Count returns how many profiles a check has.
func (s *Store) Count(ctx context.Context, check string) (int64, error) {
	body := map[string]any{"size": 0, "track_total_hits": true, "query": map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"kind": profileKind}},
		map[string]any{"term": map[string]any{"check": check}},
	}}}}
	var out struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
	}
	path := "/" + url.PathEscape(s.Index) + "/_search?ignore_unavailable=true&allow_no_indices=true"
	if err := s.Client.Do(ctx, http.MethodPost, path, body, &out); err != nil {
		return 0, err
	}
	return out.Hits.Total.Value, nil
}

// deleteProfiles removes the profiles that match filters.
func (s *Store) deleteProfiles(ctx context.Context, filters ...any) error {
	body := map[string]any{"query": map[string]any{"bool": map[string]any{"filter": append([]any{
		map[string]any{"term": map[string]any{"kind": profileKind}},
	}, filters...)}}}
	path := "/" + url.PathEscape(s.Index) + "/_delete_by_query?conflicts=proceed&refresh=true&ignore_unavailable=true&allow_no_indices=true"
	return s.Client.Do(ctx, http.MethodPost, path, body, nil)
}

// Forget removes the profiles of entities not seen since before.
func (s *Store) Forget(ctx context.Context, before time.Time) error {
	return s.deleteProfiles(ctx, map[string]any{"range": map[string]any{"last_seen": map[string]any{"lt": before.UTC().Format(time.RFC3339)}}})
}

// Reset removes every profile of a check, so it learns again.
func (s *Store) Reset(ctx context.Context, check string) error {
	checks := []any{check}
	if check == RareProcess {
		checks = append(checks, prevalenceCheck)
	}
	return s.deleteProfiles(ctx, map[string]any{"terms": map[string]any{"check": checks}})
}

// IPDBStatus is how the IP database stands.
type IPDBStatus struct {
	Kind string `json:"kind"`
	// Source is where the stored copy came from, FetchedAt when, and
	// Rows how many address ranges it has.
	Source    string    `json:"source,omitempty"`
	FetchedAt time.Time `json:"fetched_at,omitzero"`
	Rows      int       `json:"rows"`
	// TriedAt is the last download tried, and Error why it failed.
	TriedAt time.Time `json:"tried_at,omitzero"`
	Error   string    `json:"error,omitempty"`
}

type ipdbDoc struct {
	Kind      string    `json:"kind"`
	FetchedAt time.Time `json:"fetched_at"`
	Data      string    `json:"data"`
}

// IPDBStatus returns how the IP database stands, and the version of that
// record.
func (s *Store) IPDBStatus(ctx context.Context) (IPDBStatus, store.Version, error) {
	var st IPDBStatus
	v, _, err := s.get(ctx, ipdbMetaID, &st)
	return st, v, err
}

func (s *Store) saveIPDBStatus(ctx context.Context, st IPDBStatus) error {
	st.Kind = "ipdb_meta"
	_, v, err := s.IPDBStatus(ctx)
	if err != nil {
		return err
	}
	_, err = s.put(ctx, ipdbMetaID, st, v)
	return err
}

// saveIPDB keeps a copy of the database.
func (s *Store) saveIPDB(ctx context.Context, db *IPDB, at time.Time) error {
	z, err := db.encode(ctx)
	if err != nil {
		return err
	}
	if len(z) > maxIPDBStored {
		return fmt.Errorf("the IP database is too large to keep: %d MB compressed, at most %d MB", len(z)>>20, maxIPDBStored>>20)
	}
	var old ipdbDoc
	v, _, err := s.get(ctx, ipdbID, &old)
	if err != nil {
		return err
	}
	_, err = s.put(ctx, ipdbID, ipdbDoc{Kind: "ipdb", FetchedAt: at, Data: base64.StdEncoding.EncodeToString(z)}, v)
	return err
}

// loadIPDB reads the kept copy; nil when there is none.
func (s *Store) loadIPDB(ctx context.Context) (*IPDB, time.Time, error) {
	var d ipdbDoc
	_, found, err := s.get(ctx, ipdbID, &d)
	if err != nil || !found {
		return nil, time.Time{}, err
	}
	z, err := base64.StdEncoding.DecodeString(d.Data)
	if err != nil {
		return nil, time.Time{}, err
	}
	db, err := ParseIPDB(&ctxReader{ctx: ctx, r: bytes.NewReader(z)})
	return db, d.FetchedAt, err
}
