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

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Store keeps the files.
type Store interface {
	// Put stores a new file with its bytes.
	Put(ctx context.Context, f *File, data []byte) error
	// Get returns a file of a case and its bytes.
	Get(ctx context.Context, caseID, id string) (*File, []byte, error)
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

	mu    sync.Mutex
	ready bool
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

// EnsureIndex creates the index if it does not exist. Put calls it the
// first time, so the index exists only once a file was attached.
func (s *OpenSearch) EnsureIndex(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready {
		return nil
	}
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
		s.ready = true
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

// Prune deletes the files of cases that no longer exist, after retention
// deleted resolved and closed cases. caseIndex is the cases index. It
// returns how many files it deleted.
func (s *OpenSearch) Prune(ctx context.Context, caseIndex string) (int64, error) {
	var agg struct {
		Aggregations struct {
			Cases struct {
				Buckets []struct {
					Key string `json:"key"`
				} `json:"buckets"`
			} `json:"cases"`
		} `json:"aggregations"`
	}
	err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_search",
		map[string]any{"size": 0, "aggs": map[string]any{"cases": map[string]any{"terms": map[string]any{"field": "case_id", "size": 10000}}}}, &agg)
	if notFound(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var ids []string
	for _, b := range agg.Aggregations.Cases.Buckets {
		ids = append(ids, b.Key)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	var mget struct {
		Docs []struct {
			ID    string `json:"_id"`
			Found bool   `json:"found"`
			Error any    `json:"error"`
		} `json:"docs"`
	}
	if err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(caseIndex)+"/_mget?_source=false", map[string]any{"ids": ids}, &mget); err != nil {
		return 0, err
	}
	var gone []string
	for _, d := range mget.Docs {
		// Only a case OpenSearch says is not there; an error keeps its files.
		if !d.Found && d.Error == nil && slices.Contains(ids, d.ID) {
			gone = append(gone, d.ID)
		}
	}
	if len(gone) == 0 {
		return 0, nil
	}
	var out struct {
		Deleted int64 `json:"deleted"`
	}
	err = s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_delete_by_query?refresh=true&conflicts=proceed",
		map[string]any{"query": map[string]any{"terms": map[string]any{"case_id": gone}}}, &out)
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
