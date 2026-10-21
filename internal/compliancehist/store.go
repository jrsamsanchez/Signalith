// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package compliancehist

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// MaxList caps the records one list returns: over eight years of monthly
// ones, with room for those taken by hand.
const MaxList = 200

// Store keeps the records. Records are only ever added: none is changed
// or deleted through Signalith.
type Store interface {
	// Create adds a record; store.ErrExists when one has its ID.
	Create(ctx context.Context, s *Signed) error
	// Get returns one record.
	Get(ctx context.Context, id string) (*Signed, error)
	// List returns the newest records first, at most MaxList.
	List(ctx context.Context) ([]*Signed, error)
}

// Doer sends OpenSearch REST requests.
type Doer interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// OpenSearch keeps the records in "<prefix>_compliance_history", one
// document each, its data in a field that is neither indexed nor searched.
type OpenSearch struct {
	Client   Doer
	Index    string
	Replicas map[string]any
}

// NewOpenSearch returns a store using index "<prefix>_compliance_history".
func NewOpenSearch(c Doer, prefix string) *OpenSearch {
	return &OpenSearch{Client: c, Index: prefix + "_compliance_history"}
}

func statusOf(err error) int {
	var oe *store.Error
	if errors.As(err, &oe) {
		return oe.Status
	}
	return 0
}

// EnsureIndex creates the index if it does not exist. Create calls it
// each time, so a record is never written to an index OpenSearch made by
// itself after the index was deleted.
func (s *OpenSearch) EnsureIndex(ctx context.Context) error {
	kw := map[string]any{"type": "keyword"}
	body := map[string]any{
		"settings": store.SmallIndexSettings(s.Replicas),
		"mappings": map[string]any{"dynamic": "false", "properties": map[string]any{
			"id": kw, "sha256": kw, "key_id": kw,
			"taken":   map[string]any{"type": "date"},
			"payload": map[string]any{"type": "binary"},
			"sig":     map[string]any{"type": "keyword", "index": false, "doc_values": false},
		}},
	}
	err := s.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index), body, nil)
	var oe *store.Error
	if err == nil || errors.As(err, &oe) && oe.Status == 400 && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

func (s *OpenSearch) Create(ctx context.Context, rec *Signed) error {
	if !ValidID(rec.ID) {
		return errors.New("not a compliance history record ID")
	}
	if err := s.EnsureIndex(ctx); err != nil {
		return err
	}
	err := s.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index)+"/_create/"+url.PathEscape(rec.ID)+"?refresh=wait_for", rec, nil)
	if statusOf(err) == http.StatusConflict {
		return store.ErrExists
	}
	return err
}

func (s *OpenSearch) Get(ctx context.Context, id string) (*Signed, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	var out struct {
		Found  bool   `json:"found"`
		Source Signed `json:"_source"`
	}
	err := s.Client.Do(ctx, http.MethodGet, "/"+url.PathEscape(s.Index)+"/_doc/"+url.PathEscape(id), nil, &out)
	if statusOf(err) == http.StatusNotFound || err == nil && !out.Found {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out.Source, nil
}

func (s *OpenSearch) List(ctx context.Context) ([]*Signed, error) {
	var page struct {
		Hits struct {
			Hits []struct {
				ID     string `json:"_id"`
				Source Signed `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_search", map[string]any{
		"size": MaxList, "sort": []any{map[string]any{"taken": "desc"}, map[string]any{"id": "desc"}},
	}, &page)
	if statusOf(err) == http.StatusNotFound {
		return []*Signed{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]*Signed, 0, len(page.Hits.Hits))
	for _, h := range page.Hits.Hits {
		rec := h.Source
		// A document stored under another ID than it names is checked as
		// changed, not shown as the record its ID says.
		if h.ID != rec.ID {
			rec.ID = h.ID
		}
		out = append(out, &rec)
	}
	return out, nil
}

// Memory keeps records in memory, for tests.
type Memory struct {
	mu   sync.Mutex
	recs map[string]Signed
}

// NewMemory returns an empty store.
func NewMemory() *Memory { return &Memory{recs: map[string]Signed{}} }

func (m *Memory) Create(_ context.Context, s *Signed) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.recs[s.ID]; ok {
		return store.ErrExists
	}
	m.recs[s.ID] = *s
	return nil
}

func (m *Memory) Get(_ context.Context, id string) (*Signed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.recs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &s, nil
}

func (m *Memory) List(context.Context) ([]*Signed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*Signed{}
	for _, s := range m.recs {
		out = append(out, &s)
	}
	slices.SortFunc(out, func(a, b *Signed) int {
		if c := b.Taken.Compare(a.Taken); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	})
	if len(out) > MaxList {
		out = out[:MaxList]
	}
	return out, nil
}

// Tamper replaces a record's data, for tests of the check.
func (m *Memory) Tamper(id, payload string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.recs[id]
	s.Payload = payload
	m.recs[id] = s
}

// Due reports whether the month of now still lacks its monthly record.
func Due(ctx context.Context, st Store, now time.Time) (bool, error) {
	_, err := st.Get(ctx, MonthID(now))
	if errors.Is(err, ErrNotFound) {
		return true, nil
	}
	return false, err
}
