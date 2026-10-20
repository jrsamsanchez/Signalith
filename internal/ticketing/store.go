// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Link states.
const (
	// StatePending is a ticket an analyst asked for on a server that does
	// not run the background jobs; the one that does opens it.
	StatePending = "pending"
	// StateCreating is a ticket being opened. One left like this by a
	// server that stopped may or may not exist, so it is never opened
	// again by itself; an analyst may try again once it is stale.
	StateCreating = "creating"
	// StateLinked is a ticket that exists and is kept in step.
	StateLinked = "linked"
	// StateFailed is a ticket that could not be opened; Error says why.
	StateFailed = "failed"
	// StateGone is a ticket that was deleted in its system.
	StateGone = "gone"
)

// Link is one ticket of one case, kept in <prefix>_ticket_sync: the claim
// that it is opened once, and what the sync last sent and saw, so it never
// sends back what it took from the ticket, or takes back what it sent.
type Link struct {
	// ID is LinkID(connection, case).
	ID             string `json:"id"`
	CaseID         string `json:"case_id"`
	Connection     string `json:"connection"`
	ConnectionName string `json:"connection_name"`
	System         string `json:"system"`
	State          string `json:"state"`
	// Active links are polled. A link of a case closed long ago, whose
	// ticket agrees, stops being polled until the case changes again.
	Active bool `json:"active"`
	// Auto is a ticket a connection opened by itself (AutoCreate).
	Auto bool `json:"auto,omitempty"`

	Key       string    `json:"key,omitempty"`
	RemoteID  string    `json:"remote_id,omitempty"`
	URL       string    `json:"url,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	// Attempts counts the tries to open the ticket.
	Attempts int `json:"attempts,omitempty"`
	// MayExist marks a ticket an earlier try may have opened without
	// recording it: the server stopped while opening it, or the try failed
	// in a way that does not say whether the system made it. The next try
	// looks for it by its marker before opening another.
	MayExist bool `json:"may_exist,omitempty"`
	// Error is the last problem, for people; "" once the next sync
	// succeeds.
	Error    string    `json:"error,omitempty"`
	ErrorAt  time.Time `json:"error_at,omitzero"`
	SyncedAt time.Time `json:"synced_at,omitzero"`
	// StatusError is why the ticket could not be moved to the case's
	// status in a way trying again cannot fix (no such transition or
	// state). It stays shown until the case's status changes or a move
	// succeeds.
	StatusError string `json:"status_error,omitempty"`
	Server      string `json:"server,omitempty"`

	// What the ticket was last told of the case, and what the case was
	// last told of the ticket. CaseStatus is "" until the first sync, so
	// a ticket opened for a case that is already being worked moves to
	// match it.
	CaseStatus    string       `json:"case_status,omitempty"`
	CaseTitle     string       `json:"case_title,omitempty"`
	CaseSeverity  string       `json:"case_severity,omitempty"`
	RemoteStatus  RemoteStatus `json:"remote_status"`
	RemoteUpdated string       `json:"remote_updated,omitempty"`
	// Notes are the case notes already sent to the ticket or taken from
	// it, by entry ID; Comments the ticket's comments already taken or
	// written by Signalith, by comment ID.
	Notes    []string `json:"notes,omitempty"`
	Comments []string `json:"comments,omitempty"`
	// Imported counts the ticket's comments added to the case as notes,
	// for maxImportLink. Backlog marks a ticket with comments left for
	// the next pass (maxImportPass), so it is read again then.
	Imported int  `json:"imported,omitempty"`
	Backlog  bool `json:"backlog,omitempty"`
	// Warning says why some of the ticket's comments were not added to
	// the case, for people. It stays until comments are added again.
	Warning string `json:"warning,omitempty"`
}

// maxSeen bounds the comment IDs a link remembers; a case holds at most
// cases.MaxEntries notes, so Notes needs no bound of its own.
const maxSeen = 5000

// LinkID is the ID of a case's link to a connection: one ticket for each
// connection and case.
func LinkID(connection, caseID string) string { return connection + ":" + caseID }

// Stored is a link as read, with its version for a conditional write.
type Stored struct {
	Link
	Version store.Version
}

// ErrNotFound is a link that does not exist.
var ErrNotFound = errors.New("there is no ticket link with this ID")

// Store keeps the links.
type Store interface {
	// Create writes a new link: store.ErrExists when it is already there.
	Create(ctx context.Context, l *Link) (store.Version, error)
	// Get reads one link in real time: ErrNotFound when it is not there.
	Get(ctx context.Context, id string) (Stored, error)
	// Update writes a link only if it is still at version v:
	// store.ErrConflict when it changed.
	Update(ctx context.Context, l *Link, v store.Version) (store.Version, error)
	// ForCases returns the links of some cases.
	ForCases(ctx context.Context, caseIDs []string) ([]Stored, error)
	// Due returns the links the sync works on: pending ones, active
	// linked ones, and failed or being-opened ones a connection opened by
	// itself that may be tried again.
	Due(ctx context.Context) ([]Stored, error)
}

// Docs is what OpenSearch keeps links with; *store.Client is one.
type Docs interface {
	Do(ctx context.Context, method, path string, body any, out any) error
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
}

// OpenSearch keeps links in one index, "<prefix>_ticket_sync". Its name
// uses "_" rather than "-" so event searches over "<prefix>-*" never
// include it.
type OpenSearch struct {
	Client Docs
	Index  string
	// Replicas are the index's replicas settings (opensearch.replicas,
	// see config.Replicas.IndexSettings); nil is auto.
	Replicas map[string]any
}

// NewOpenSearch returns the links index of prefix.
func NewOpenSearch(c Docs, prefix string) *OpenSearch {
	return &OpenSearch{Client: c, Index: prefix + "_ticket_sync"}
}

func properties() map[string]any {
	kw := map[string]any{"type": "keyword"}
	date := map[string]any{"type": "date"}
	b := map[string]any{"type": "boolean"}
	return map[string]any{
		"id": kw, "case_id": kw, "connection": kw, "system": kw, "state": kw, "key": kw, "remote_id": kw,
		"created_by": kw, "server": kw, "active": b, "auto": b, "attempts": map[string]any{"type": "integer"},
		"created": date, "updated": date, "error_at": date, "synced_at": date,
		"error": map[string]any{"type": "text", "index": false},
	}
}

// EnsureIndex creates the index if it does not exist. Any server may.
func (o *OpenSearch) EnsureIndex(ctx context.Context) error {
	body := map[string]any{
		"settings": store.SmallIndexSettings(o.Replicas),
		"mappings": map[string]any{"dynamic": "false", "properties": properties()},
	}
	err := o.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(o.Index), body, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 400 && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// Replicate gives the index, when it was made with no copy on another
// node, the replicas settings new indices get (see store.Replicate). Only
// the server that runs the background jobs does, when it starts running
// them; doing it again changes nothing.
func (o *OpenSearch) Replicate(ctx context.Context) error {
	return store.Replicate(ctx, o.Client, o.Index, o.Replicas)
}

func (o *OpenSearch) Create(ctx context.Context, l *Link) (store.Version, error) {
	return o.Client.Create(ctx, o.Index, l.ID, l, true)
}

func (o *OpenSearch) Get(ctx context.Context, id string) (Stored, error) {
	src, v, found, err := o.Client.Get(ctx, o.Index, id)
	if err != nil {
		return Stored{}, err
	}
	if !found {
		return Stored{}, ErrNotFound
	}
	var l Link
	if err := json.Unmarshal(src, &l); err != nil {
		return Stored{}, err
	}
	return Stored{Link: l, Version: v}, nil
}

func (o *OpenSearch) Update(ctx context.Context, l *Link, v store.Version) (store.Version, error) {
	return o.Client.PutIf(ctx, o.Index, l.ID, l, v, true)
}

func (o *OpenSearch) search(ctx context.Context, q map[string]any) ([]Stored, error) {
	docs, err := o.Client.SearchDocs(ctx, o.Index, q)
	if err != nil {
		return nil, err
	}
	out := make([]Stored, 0, len(docs))
	for _, d := range docs {
		var l Link
		if err := json.Unmarshal(d.Source, &l); err != nil {
			continue
		}
		out = append(out, Stored{Link: l, Version: d.Version})
	}
	sortLinks(out)
	return out, nil
}

func (o *OpenSearch) ForCases(ctx context.Context, caseIDs []string) ([]Stored, error) {
	var out []Stored
	for len(caseIDs) > 0 {
		n := min(len(caseIDs), 500)
		got, err := o.search(ctx, map[string]any{"terms": map[string]any{"case_id": caseIDs[:n]}})
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
		caseIDs = caseIDs[n:]
	}
	return out, nil
}

func (o *OpenSearch) Due(ctx context.Context) ([]Stored, error) {
	term := func(f string, v any) map[string]any { return map[string]any{"term": map[string]any{f: v}} }
	q := map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
		term("state", StatePending),
		map[string]any{"bool": map[string]any{"filter": []any{term("state", StateLinked), term("active", true)}}},
		map[string]any{"bool": map[string]any{"filter": []any{map[string]any{"terms": map[string]any{"state": []string{StateFailed, StateCreating}}}, term("auto", true),
			map[string]any{"range": map[string]any{"attempts": map[string]any{"lt": maxAutoAttempts}}}}}},
	}}}
	return o.search(ctx, q)
}

// sortLinks orders links oldest first.
func sortLinks(list []Stored) {
	sort.SliceStable(list, func(i, j int) bool {
		if !list[i].Created.Equal(list[j].Created) {
			return list[i].Created.Before(list[j].Created)
		}
		return list[i].ID < list[j].ID
	})
}

// Memory keeps links in memory, for tests and for a server without
// OpenSearch.
type Memory struct {
	mu   sync.Mutex
	docs map[string]Stored
	seq  int64
}

// NewMemory returns an empty Memory.
func NewMemory() *Memory { return &Memory{docs: map[string]Stored{}} }

func (m *Memory) next() store.Version {
	m.seq++
	return store.Version{SeqNo: m.seq, PrimaryTerm: 1, Version: m.seq}
}

func copyLink(l Link) Link {
	l.Notes = slices.Clone(l.Notes)
	l.Comments = slices.Clone(l.Comments)
	return l
}

func (m *Memory) Create(_ context.Context, l *Link) (store.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.docs[l.ID]; ok {
		return store.Version{}, store.ErrExists
	}
	v := m.next()
	m.docs[l.ID] = Stored{Link: copyLink(*l), Version: v}
	return v, nil
}

func (m *Memory) Get(_ context.Context, id string) (Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.docs[id]
	if !ok {
		return Stored{}, ErrNotFound
	}
	return Stored{Link: copyLink(s.Link), Version: s.Version}, nil
}

func (m *Memory) Update(_ context.Context, l *Link, v store.Version) (store.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.docs[l.ID]
	if !ok || !s.Version.Same(v) {
		return store.Version{}, store.ErrConflict
	}
	nv := m.next()
	m.docs[l.ID] = Stored{Link: copyLink(*l), Version: nv}
	return nv, nil
}

func (m *Memory) list(keep func(Link) bool) []Stored {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Stored
	for _, s := range m.docs {
		if keep(s.Link) {
			out = append(out, Stored{Link: copyLink(s.Link), Version: s.Version})
		}
	}
	sortLinks(out)
	return out
}

func (m *Memory) ForCases(_ context.Context, caseIDs []string) ([]Stored, error) {
	return m.list(func(l Link) bool { return slices.Contains(caseIDs, l.CaseID) }), nil
}

func (m *Memory) Due(_ context.Context) ([]Stored, error) {
	return m.list(func(l Link) bool {
		return l.State == StatePending || (l.State == StateLinked && l.Active) ||
			((l.State == StateFailed || l.State == StateCreating) && l.Auto && l.Attempts < maxAutoAttempts)
	}), nil
}
