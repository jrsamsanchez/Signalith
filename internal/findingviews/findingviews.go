// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package findingviews keeps each user's saved views of the findings
// queue: a name and the queue's filters, as the page writes them in its
// address (status=new&owner=__none&urgency=critical).
//
// Views belong to one user and follow them from browser to browser, so
// they live in OpenSearch, in one document of the runtime index
// (<prefix>_runtime/findingviews:<user>). A tenant's server has its own
// prefix, so a tenant's users keep theirs with the tenant's data.
package findingviews

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Limits on what a user keeps.
const (
	MaxViews    = 30
	MaxName     = 60
	MaxQuery    = 1000
	maxValueLen = 500
)

// Keys are the filters a view may hold: the ones the queue writes in its
// address.
var Keys = []string{"status", "owner", "q", "since", "detection", "urgency", "sort", "group", "entity"}

// View is one saved view.
type View struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Query string `json:"query"`
}

var viewID = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// Validate checks views a user sent and tidies them: names trimmed, the
// query in a fixed key order.
func Validate(vs []View) ([]View, error) {
	if len(vs) > MaxViews {
		return nil, fmt.Errorf("keep at most %d saved views", MaxViews)
	}
	out := make([]View, 0, len(vs))
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, v := range vs {
		v.Name = strings.TrimSpace(v.Name)
		switch {
		case !viewID.MatchString(v.ID):
			return nil, errors.New("a saved view has an ID that is not valid")
		case ids[v.ID]:
			return nil, errors.New("two saved views have the same ID")
		case v.Name == "" || utf8.RuneCountInString(v.Name) > MaxName || strings.ContainsFunc(v.Name, isControl):
			return nil, fmt.Errorf("a saved view needs a name of 1 to %d characters", MaxName)
		case names[strings.ToLower(v.Name)]:
			return nil, fmt.Errorf("there is already a saved view named %q", v.Name)
		case len(v.Query) > MaxQuery:
			return nil, errors.New("a saved view's filters are too long")
		}
		q, err := url.ParseQuery(v.Query)
		if err != nil {
			return nil, fmt.Errorf("saved view %q: its filters cannot be read", v.Name)
		}
		tidy := url.Values{}
		for k, vals := range q {
			if !slices.Contains(Keys, k) || len(vals) != 1 || len(vals[0]) > maxValueLen || strings.ContainsFunc(vals[0], isControl) {
				return nil, fmt.Errorf("saved view %q: %q is not a queue filter", v.Name, k)
			}
			tidy.Set(k, vals[0])
		}
		v.Query = tidy.Encode()
		ids[v.ID], names[strings.ToLower(v.Name)] = true, true
		out = append(out, v)
	}
	return out, nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// Store keeps the users' views.
type Store interface {
	// Get returns user's views; a user with none has none.
	Get(ctx context.Context, user string) ([]View, error)
	// Put replaces user's views.
	Put(ctx context.Context, user string, vs []View) error
}

// Memory keeps the views in memory, for a server without OpenSearch and
// for tests.
type Memory struct {
	mu sync.Mutex
	m  map[string][]View
}

func (m *Memory) Get(_ context.Context, user string) ([]View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.m[key(user)]), nil
}

func (m *Memory) Put(_ context.Context, user string, vs []View) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string][]View{}
	}
	m.m[key(user)] = slices.Clone(vs)
	return nil
}

func key(user string) string { return strings.ToLower(user) }

// Docs reads and writes a document with its version. *store.Client has
// it.
type Docs interface {
	cluster.Doer
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
}

// OpenSearch keeps the views in the runtime index.
type OpenSearch struct {
	Docs   Docs
	Prefix string

	mu    sync.Mutex
	ready bool // the runtime index is known to be there
}

const kind = "finding_views"

// doc is a user's views as the runtime index keeps them: the fields the
// index maps (kind, user, at), and the views in body, which it keeps
// without indexing.
type doc struct {
	Kind string    `json:"kind"`
	User string    `json:"user"`
	At   time.Time `json:"at"`
	Body struct {
		Views []View `json:"views"`
	} `json:"body"`
}

func docID(user string) string { return "findingviews:" + key(user) }

func (o *OpenSearch) index() string { return cluster.RuntimeIndex(o.Prefix) }

func (o *OpenSearch) Get(ctx context.Context, user string) ([]View, error) {
	vs, _, err := o.read(ctx, user)
	return vs, err
}

func (o *OpenSearch) read(ctx context.Context, user string) ([]View, store.Version, error) {
	raw, v, found, err := o.Docs.Get(ctx, o.index(), docID(user))
	if err != nil || !found {
		return nil, v, err
	}
	var d doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, v, err
	}
	return d.Body.Views, v, nil
}

// Put writes the views over whatever is there: the user's latest list
// wins. A write that races another (the same user in two browsers)
// reads again and tries once more.
func (o *OpenSearch) Put(ctx context.Context, user string, vs []View) error {
	d := doc{Kind: kind, User: key(user), At: time.Now().UTC()}
	d.Body.Views = vs
	var err error
	for range 3 {
		var v store.Version
		if _, v, err = o.read(ctx, user); err != nil {
			return err
		}
		if v.IsZero() {
			if err = o.ensure(ctx); err != nil {
				return err
			}
			_, err = o.Docs.Create(ctx, o.index(), docID(user), d, false)
		} else {
			_, err = o.Docs.PutIf(ctx, o.index(), docID(user), d, v, false)
		}
		if !errors.Is(err, store.ErrExists) && !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}

// ensure makes the runtime index once, so the first view on a new
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
