// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package casefiles

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Store keeps the files.
type Store interface {
	// Put stores a new file with its bytes.
	Put(ctx context.Context, f *File, data []byte) error
	// Get returns a file of a case and its bytes.
	Get(ctx context.Context, caseID, id string) (*File, []byte, error)
	// Stat returns a file of a case without its bytes.
	Stat(ctx context.Context, caseID, id string) (*File, error)
	// Delete removes a file of a case; one already gone is not an error.
	Delete(ctx context.Context, caseID, id string) error
}

// Doer sends OpenSearch REST requests.
type Doer interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// OpenSearch keeps the files in one index, "<prefix>_case_files", one
// document each, its bytes base64 in a field that is neither indexed nor
// searched.
type OpenSearch struct {
	Client Doer
	Index  string
	// Replicas are the index's replicas settings; nil is auto.
	Replicas map[string]any
}

// NewOpenSearch returns a store using index "<prefix>_case_files".
func NewOpenSearch(c Doer, prefix string) *OpenSearch {
	return &OpenSearch{Client: c, Index: prefix + "_case_files"}
}

type doc struct {
	*File
	Data string `json:"data"`
}

func notFound(err error) bool {
	var oe *store.Error
	return errors.As(err, &oe) && oe.Status == 404
}

// EnsureIndex creates the index if it does not exist. Put calls it each
// time, so the index exists once a file was attached, and a file is
// never written to an index OpenSearch made by itself (with every field
// searchable) after the index was deleted.
func (s *OpenSearch) EnsureIndex(ctx context.Context) error {
	kw := map[string]any{"type": "keyword"}
	body := map[string]any{
		"settings": store.SmallIndexSettings(s.Replicas),
		"mappings": map[string]any{"dynamic": "false", "properties": map[string]any{
			"id": kw, "case_id": kw, "sha256": kw, "added_by": kw, "content_type": kw,
			"name":  map[string]any{"type": "keyword", "index": false},
			"size":  map[string]any{"type": "long"},
			"added": map[string]any{"type": "date"},
			"data":  map[string]any{"type": "binary"},
		}},
	}
	err := s.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index), body, nil)
	var oe *store.Error
	if err == nil || errors.As(err, &oe) && oe.Status == 400 && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

func (s *OpenSearch) Put(ctx context.Context, f *File, data []byte) error {
	if err := s.EnsureIndex(ctx); err != nil {
		return err
	}
	return s.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index)+"/_create/"+url.PathEscape(f.ID)+"?refresh=wait_for",
		doc{File: f, Data: base64.StdEncoding.EncodeToString(data)}, nil)
}

func (s *OpenSearch) Get(ctx context.Context, caseID, id string) (*File, []byte, error) {
	if !ValidID(id) {
		return nil, nil, ErrNotFound
	}
	var out struct {
		Found  bool `json:"found"`
		Source struct {
			File
			Data string `json:"data"`
		} `json:"_source"`
	}
	err := s.Client.Do(ctx, http.MethodGet, "/"+url.PathEscape(s.Index)+"/_doc/"+url.PathEscape(id), nil, &out)
	if notFound(err) || err == nil && (!out.Found || out.Source.CaseID != caseID) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	data, err := base64.StdEncoding.DecodeString(out.Source.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("file %s: %w", id, err)
	}
	f := out.Source.File
	return &f, data, nil
}

func (s *OpenSearch) Stat(ctx context.Context, caseID, id string) (*File, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	var out struct {
		Found  bool `json:"found"`
		Source File `json:"_source"`
	}
	err := s.Client.Do(ctx, http.MethodGet, "/"+url.PathEscape(s.Index)+"/_doc/"+url.PathEscape(id)+"?_source_excludes=data", nil, &out)
	if notFound(err) || err == nil && (!out.Found || out.Source.CaseID != caseID) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out.Source, nil
}

func (s *OpenSearch) Delete(ctx context.Context, caseID, id string) error {
	if !ValidID(id) {
		return nil
	}
	err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_delete_by_query?refresh=true",
		map[string]any{"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"id": id}},
			map[string]any{"term": map[string]any{"case_id": caseID}},
		}}}}, nil)
	if notFound(err) {
		return nil
	}
	return err
}

// PruneGrace is how old a file must be before Prune deletes it for not
// being on its case's timeline: an upload stores the file a moment before
// it names it there. It is a day, not minutes, as the file's time is the
// clock of the server that stored it, and Prune runs on another one.
const PruneGrace = 24 * time.Hour

// prunePage is how many files Prune looks at a time.
const prunePage = 1000

// Prune deletes the files no case names any more: those of cases that
// were deleted (by retention or with sample data), and those whose
// timeline entry is gone (removed while OpenSearch could not delete the
// file, or never added because the server stopped between storing the
// file and naming it), once they are PruneGrace old. caseIndex is the
// cases index. It returns how many files it deleted.
func (s *OpenSearch) Prune(ctx context.Context, caseIndex string, now time.Time) (int64, error) {
	var deleted int64
	var after []any
	for {
		var page struct {
			Hits struct {
				Hits []struct {
					Source File  `json:"_source"`
					Sort   []any `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		q := map[string]any{
			"size": prunePage, "_source": []string{"id", "case_id"},
			"query": map[string]any{"range": map[string]any{"added": map[string]any{"lt": now.Add(-PruneGrace).UTC().Format(time.RFC3339Nano)}}},
			"sort":  []any{map[string]any{"added": "asc"}, map[string]any{"id": "asc"}},
		}
		if after != nil {
			q["search_after"] = after
		}
		err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_search", q, &page)
		if notFound(err) {
			return deleted, nil
		}
		if err != nil {
			return deleted, err
		}
		hits := page.Hits.Hits
		if len(hits) == 0 {
			return deleted, nil
		}
		byCase := map[string][]string{}
		for _, h := range hits {
			byCase[h.Source.CaseID] = append(byCase[h.Source.CaseID], h.Source.ID)
		}
		n, err := s.pruneCases(ctx, caseIndex, byCase)
		deleted += n
		if err != nil || len(hits) < prunePage {
			return deleted, err
		}
		after = hits[len(hits)-1].Sort
	}
}

// pruneCases deletes the files of byCase (case ID to file IDs) that their
// case does not name.
func (s *OpenSearch) pruneCases(ctx context.Context, caseIndex string, byCase map[string][]string) (int64, error) {
	ids := make([]string, 0, len(byCase))
	for id := range byCase {
		ids = append(ids, id)
	}
	var mget struct {
		Docs []struct {
			ID     string `json:"_id"`
			Found  bool   `json:"found"`
			Error  any    `json:"error"`
			Source struct {
				Entries []struct {
					FileID string `json:"file_id"`
				} `json:"entries"`
			} `json:"_source"`
		} `json:"docs"`
	}
	if err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(caseIndex)+"/_mget?_source_includes=entries.file_id", map[string]any{"ids": ids}, &mget); err != nil {
		return 0, err
	}
	found := false
	for _, d := range mget.Docs {
		found = found || d.Found
	}
	if !found {
		// None of the cases is there: keep the files if the cases index
		// is empty, as one deleted and made again would be, rather than
		// delete every file. Files of cases all gone wait for a new case.
		var count struct {
			Count int64 `json:"count"`
		}
		if err := s.Client.Do(ctx, http.MethodGet, "/"+url.PathEscape(caseIndex)+"/_count", nil, &count); err != nil {
			return 0, err
		}
		if count.Count == 0 {
			return 0, nil
		}
	}
	var gone []string
	for _, d := range mget.Docs {
		files, ok := byCase[d.ID]
		// Only what OpenSearch answered for: an error keeps the files.
		if !ok || d.Error != nil {
			continue
		}
		named := map[string]bool{}
		if d.Found {
			for _, e := range d.Source.Entries {
				named[e.FileID] = true
			}
		}
		for _, f := range files {
			if !named[f] {
				gone = append(gone, f)
			}
		}
	}
	if len(gone) == 0 {
		return 0, nil
	}
	var out struct {
		Deleted int64 `json:"deleted"`
	}
	err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_delete_by_query?refresh=true&conflicts=proceed",
		map[string]any{"query": map[string]any{"terms": map[string]any{"id": gone}}}, &out)
	return out.Deleted, err
}

// Memory keeps files in memory, for tests.
type Memory struct {
	mu    sync.Mutex
	files map[string]*File
	data  map[string][]byte
}

// NewMemory returns an empty store.
func NewMemory() *Memory { return &Memory{files: map[string]*File{}, data: map[string][]byte{}} }

func (m *Memory) Put(_ context.Context, f *File, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[f.ID]; ok {
		return store.ErrExists
	}
	c := *f
	m.files[f.ID], m.data[f.ID] = &c, slices.Clone(data)
	return nil
}

func (m *Memory) Get(_ context.Context, caseID, id string) (*File, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[id]
	if !ok || f.CaseID != caseID {
		return nil, nil, ErrNotFound
	}
	c := *f
	return &c, slices.Clone(m.data[id]), nil
}

func (m *Memory) Stat(_ context.Context, caseID, id string) (*File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[id]
	if !ok || f.CaseID != caseID {
		return nil, ErrNotFound
	}
	c := *f
	return &c, nil
}

func (m *Memory) Delete(_ context.Context, caseID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.files[id]; ok && f.CaseID == caseID {
		delete(m.files, id)
		delete(m.data, id)
	}
	return nil
}

// Tamper replaces a file's bytes, for tests of the integrity check.
func (m *Memory) Tamper(id string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[id] = data
}
