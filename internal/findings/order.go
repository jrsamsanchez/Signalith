// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package findings

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
)

// Orders a search can return findings in. Every order ends with the
// finding ID, so it is total and a page can continue after any finding.
const (
	// OrderNewest is newest first, the default.
	OrderNewest = "newest"
	OrderOldest = "oldest"
	// OrderUrgency is most urgent first, newest first within an urgency.
	OrderUrgency = "urgency"
	// OrderUrgencyAsc is least urgent first, newest first within one.
	OrderUrgencyAsc = "urgency_asc"
)

// Orders lists the valid orders.
var Orders = []string{OrderNewest, OrderOldest, OrderUrgency, OrderUrgencyAsc}

// UrgencyRank is the rank an order by urgency uses: informational 0 up
// to critical 4, and -1 for a value that is none of them.
func UrgencyRank(u string) int { return slices.Index(Severities, u) }

// Cursor is a finding's place in an order: a search with it as After
// continues with the findings after that one.
type Cursor struct {
	Rank    int    `json:"r,omitempty"`
	Created int64  `json:"c"` // milliseconds since the epoch, as OpenSearch sorts dates
	ID      string `json:"i"`
}

// CursorOf is f's place in any order.
func CursorOf(f *Finding) Cursor {
	return Cursor{Rank: UrgencyRank(f.EffectiveUrgency()), Created: f.Created.UnixMilli(), ID: f.ID}
}

// cursorID is what a finding ID in a cursor may hold, checked before
// the value goes into a query.
var cursorID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,200}$`)

// errCursor is the error of a cursor that cannot be read.
var errCursor = errors.New("the page cursor is not valid; load the list again")

// Encode writes c for a URL.
func (c Cursor) Encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor reads a cursor Encode wrote.
func DecodeCursor(s string) (*Cursor, error) {
	if len(s) > 400 {
		return nil, errCursor
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errCursor
	}
	var c Cursor
	if err := json.Unmarshal(b, &c); err != nil || !cursorID.MatchString(c.ID) || c.Rank < -1 || c.Rank >= len(Severities) {
		return nil, errCursor
	}
	return &c, nil
}

// ValidOrder reports whether o is an order a search takes; empty is the
// default.
func ValidOrder(o string) bool { return o == "" || slices.Contains(Orders, o) }

// before reports whether a comes before b in order o.
func before(o string, a, b Cursor) bool {
	cmp := func(x, y int64) int {
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	}
	ids := func() int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	}
	var c int
	switch o {
	case OrderOldest:
		if c = cmp(a.Created, b.Created); c == 0 {
			c = ids()
		}
		return c < 0
	case OrderUrgency, OrderUrgencyAsc:
		c = cmp(int64(a.Rank), int64(b.Rank))
		if o == OrderUrgency {
			c = -c
		}
		if c != 0 {
			return c < 0
		}
	}
	if c = cmp(a.Created, b.Created); c == 0 {
		c = ids()
	}
	return c > 0
}

// osSort is the OpenSearch sort of order o, and the search_after values
// of a cursor in it.
func osSort(o string, after *Cursor) ([]any, []any) {
	newest := []any{map[string]any{"created": "desc"}, map[string]any{"id": "desc"}}
	var vals []any
	if after != nil {
		vals = []any{after.Created, after.ID}
	}
	switch o {
	case OrderOldest:
		return []any{map[string]any{"created": "asc"}, map[string]any{"id": "asc"}}, vals
	case OrderUrgency, OrderUrgencyAsc:
		dir := "desc"
		if o == OrderUrgencyAsc {
			dir = "asc"
		}
		rank := map[string]any{}
		for i, s := range Severities {
			rank[s] = i
		}
		script := map[string]any{"_script": map[string]any{"type": "number", "order": dir, "script": map[string]any{
			"lang": "painless",
			// Findings from before urgency existed sort by severity, as
			// the queue shows them.
			"source": "String u = doc['urgency'].size() > 0 ? doc['urgency'].value : (doc['severity'].size() > 0 ? doc['severity'].value : '');" +
				" return params.rank.containsKey(u) ? params.rank[u] : -1;",
			"params": map[string]any{"rank": rank},
		}}}
		if after != nil {
			vals = append([]any{after.Rank}, vals...)
		}
		return append([]any{script}, newest...), vals
	}
	return newest, vals
}

// UrgencyCounter is a store that counts the findings of each urgency
// that pass a filter, for the queue's urgency pills.
type UrgencyCounter interface {
	UrgencyCounts(ctx context.Context, flt Filter) (map[string]int, error)
}

// Fields a queue can be grouped by.
const (
	GroupDetection = "detection"
	GroupEntity    = "entity"
)

// MaxGroups is how many groups a grouping returns, largest first.
const MaxGroups = 100

// Group is the findings that share a detection or an entity value.
type Group struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
	// Urgency is the highest urgency among them.
	Urgency string `json:"urgency"`
}

// Grouper is a store that groups the findings that pass a filter by a
// detection or an entity value, for the queue's group-by.
type Grouper interface {
	Groups(ctx context.Context, flt Filter, by string) ([]Group, error)
}

// topUrgency is the highest of urgencies.
func topUrgency(us []string) string {
	best := ""
	for _, u := range us {
		if UrgencyRank(u) > UrgencyRank(best) {
			best = u
		}
	}
	return best
}

// sortGroups orders groups largest first, then by key, and keeps
// MaxGroups.
func sortGroups(gs []Group) []Group {
	slices.SortFunc(gs, func(a, b Group) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.Key, b.Key)
	})
	if len(gs) > MaxGroups {
		gs = gs[:MaxGroups]
	}
	return gs
}
