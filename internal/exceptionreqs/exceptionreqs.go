// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package exceptionreqs keeps exceptions that analysts propose from a
// finding ("this host's backup job is not an attack") until an admin
// approves or declines them. Exceptions change what a detection raises, so
// only an admin adds one; a request lets the analyst who knows the noise
// ask without waiting for an admin to be free.
//
// The requests live in one document of the runtime index
// (<prefix>_runtime/exceptionrequests), written with its version so two
// people deciding at once cannot both win. A tenant's server has its own
// prefix, so a tenant's requests stay with the tenant's data.
package exceptionreqs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Statuses of a request.
const (
	Pending  = "pending"
	Approved = "approved"
	Declined = "declined"
	Expired  = "expired"
)

// Limits on what is kept.
const (
	// MaxPending is how many requests may wait at once, and
	// MaxPendingPerUser how many of them one person's.
	MaxPending        = 200
	MaxPendingPerUser = 50
	// KeepDecided is how many decided or expired requests are kept for
	// the record; the audit log has every decision.
	KeepDecided = 100
	// ExpireAfter is how long a request waits before it expires, so an
	// old ask is not approved by surprise months later.
	ExpireAfter = 14 * 24 * time.Hour
	MaxNote     = 1000
)

// Request is one proposed exception.
type Request struct {
	ID             string            `json:"id"`
	DetectionID    string            `json:"detection_id"`
	DetectionTitle string            `json:"detection_title,omitempty"`
	FindingID      string            `json:"finding_id,omitempty"`
	FindingTitle   string            `json:"finding_title,omitempty"`
	Match          map[string]string `json:"match"`
	// For is how long the exception lasts once approved, such as 7d;
	// empty keeps it until it is removed.
	For     string    `json:"for,omitempty"`
	Comment string    `json:"comment,omitempty"`
	By      string    `json:"by"`
	Created time.Time `json:"created"`
	Status  string    `json:"status"`
	// DecidedBy, Decided and Note record the admin's decision; ExceptionID
	// is the exception an approval added.
	DecidedBy   string     `json:"decided_by,omitempty"`
	Decided     *time.Time `json:"decided,omitempty"`
	Note        string     `json:"note,omitempty"`
	ExceptionID string     `json:"exception_id,omitempty"`
}

// Expires is when a pending request expires.
func (r *Request) Expires() time.Time { return r.Created.Add(ExpireAfter) }

// SameAsk is true when two requests ask for the same exception.
func (r *Request) SameAsk(o *Request) bool {
	return r.DetectionID == o.DetectionID && maps.Equal(r.Match, o.Match)
}

var idPattern = regexp.MustCompile(`^er-[0-9a-f]{16}$`)

// ValidID is true for an ID NewID could have made.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// NewID makes a request ID.
func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "er-" + hex.EncodeToString(b)
}

// ErrNotFound is a request that is not there; ErrDecided one already
// approved, declined or expired.
var (
	ErrNotFound = errors.New("no such exception request")
	ErrDecided  = errors.New("this exception request was already decided or has expired")
)

// Tidy marks pending requests past their time as expired, sorts the
// requests newest first and drops the oldest decided ones past
// KeepDecided.
func Tidy(rs []Request, now time.Time) []Request {
	out := slices.Clone(rs)
	for i := range out {
		if out[i].Status == Pending && !now.Before(out[i].Expires()) {
			out[i].Status = Expired
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	kept := out[:0]
	decided := 0
	for _, r := range out {
		if r.Status != Pending {
			if decided++; decided > KeepDecided {
				continue
			}
		}
		kept = append(kept, r)
	}
	return kept
}

// Add checks a new request against the ones there: not too many waiting,
// and not the same ask twice.
func Add(rs []Request, r Request) ([]Request, error) {
	pending, mine := 0, 0
	for i := range rs {
		if rs[i].Status != Pending {
			continue
		}
		if rs[i].SameAsk(&r) {
			return nil, fmt.Errorf("%s already proposed this exception; it waits for an admin", rs[i].By)
		}
		pending++
		if rs[i].By == r.By {
			mine++
		}
	}
	switch {
	case pending >= MaxPending:
		return nil, fmt.Errorf("%d exception requests already wait for an admin; ask one to go through them", pending)
	case mine >= MaxPendingPerUser:
		return nil, fmt.Errorf("you have %d exception requests waiting; ask an admin to go through them first", mine)
	}
	return append([]Request{r}, rs...), nil
}

// Decide sets the outcome of a pending request.
func Decide(rs []Request, id, status, by, note, exceptionID string, now time.Time) ([]Request, *Request, error) {
	i := slices.IndexFunc(rs, func(r Request) bool { return r.ID == id })
	if i < 0 {
		return nil, nil, ErrNotFound
	}
	if rs[i].Status != Pending {
		return nil, nil, ErrDecided
	}
	out := slices.Clone(rs)
	t := now.UTC()
	out[i].Status, out[i].DecidedBy, out[i].Decided, out[i].Note, out[i].ExceptionID = status, by, &t, note, exceptionID
	r := out[i]
	return out, &r, nil
}

// Store keeps the requests.
type Store interface {
	// List returns the requests, tidied.
	List(ctx context.Context) ([]Request, error)
	// Modify changes the requests: fn gets them tidied and returns the
	// new list, or an error that leaves them as they were.
	Modify(ctx context.Context, fn func([]Request) ([]Request, error)) error
}

// Memory keeps the requests in memory, for a server without OpenSearch and
// for tests.
type Memory struct {
	mu  sync.Mutex
	rs  []Request
	Now func() time.Time
}

func (m *Memory) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Memory) List(context.Context) ([]Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Tidy(m.rs, m.now()), nil
}

func (m *Memory) Modify(_ context.Context, fn func([]Request) ([]Request, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rs, err := fn(Tidy(m.rs, m.now()))
	if err != nil {
		return err
	}
	m.rs = rs
	return nil
}

// Docs reads and writes a document with its version. *store.Client has
// it.
type Docs interface {
	cluster.Doer
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
}

// OpenSearch keeps the requests in the runtime index.
type OpenSearch struct {
	Docs   Docs
	Prefix string

	mu    sync.Mutex
	ready bool // the runtime index is known to be there
}

const (
	kind  = "exception_requests"
	docID = "exceptionrequests"
)

// doc is the requests as the runtime index keeps them: the fields it maps
// (kind, at), and the requests in body, which it keeps without indexing.
type doc struct {
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
	Body struct {
		Requests []Request `json:"requests"`
	} `json:"body"`
}

func (o *OpenSearch) index() string { return cluster.RuntimeIndex(o.Prefix) }

func (o *OpenSearch) List(ctx context.Context) ([]Request, error) {
	rs, _, err := o.read(ctx)
	return Tidy(rs, time.Now()), err
}

func (o *OpenSearch) read(ctx context.Context) ([]Request, store.Version, error) {
	raw, v, found, err := o.Docs.Get(ctx, o.index(), docID)
	if err != nil || !found {
		return nil, v, err
	}
	var d doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, v, err
	}
	return d.Body.Requests, v, nil
}

// Modify reads, changes and writes the requests with their version; a
// write that raced another reads again and tries again.
func (o *OpenSearch) Modify(ctx context.Context, fn func([]Request) ([]Request, error)) error {
	var err error
	for range 5 {
		var (
			rs []Request
			v  store.Version
		)
		if rs, v, err = o.read(ctx); err != nil {
			return err
		}
		if rs, err = fn(Tidy(rs, time.Now())); err != nil {
			return err
		}
		d := doc{Kind: kind, At: time.Now().UTC()}
		d.Body.Requests = rs
		if v.IsZero() {
			if err = o.ensure(ctx); err != nil {
				return err
			}
			_, err = o.Docs.Create(ctx, o.index(), docID, d, true)
		} else {
			_, err = o.Docs.PutIf(ctx, o.index(), docID, d, v, true)
		}
		if !errors.Is(err, store.ErrExists) && !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}

// ensure makes the runtime index once, so the first request on a new
// install does not land in an index OpenSearch guessed the fields of.
func (o *OpenSearch) ensure(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ready {
		return nil
	}
	if err := cluster.EnsureRuntime(ctx, o.Docs, o.Prefix); err != nil {
		return err
	}
	o.ready = true
	return nil
}
