package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Page sizes for Search.
const (
	DefaultSize = 50
	MaxSize     = 500
)

// Searcher runs a search against an index pattern, as store.Client.Search
// does (which also lets a pattern that matches no index answer nothing).
type Searcher interface {
	Search(ctx context.Context, index string, body map[string]any) (map[string]any, error)
}

// Query selects audit events. Zero fields select everything.
type Query struct {
	// From and To bound the events' time (From included, To not).
	From, To time.Time
	// Server, User and Action must match exactly; an Action ending in "."
	// matches every action it starts, such as "users." for users.create.
	Server, User, Action string
	// Text is searched for in the message, the user and the target.
	Text string
	// Size is the page size (50 when 0, at most 500), and After the Next
	// of the page before, for the page after it.
	Size  int
	After []any
}

// Hit is one event found, with its document ID and index.
type Hit struct {
	Event
	ID    string `json:"id"`
	Index string `json:"index"`
}

// Page is one page of events, newest first. Next, when set, is the
// Query.After of the next page; Total counts every event the query
// matches.
type Page struct {
	Events []Hit
	Next   []any
	Total  int64
}

// Search returns one page of the audit events q selects, newest first.
// With no audit index yet, the page is empty.
func Search(ctx context.Context, c Searcher, prefix string, q Query) (*Page, error) {
	size := q.Size
	if size <= 0 {
		size = DefaultSize
	}
	size = min(size, MaxSize)
	body := map[string]any{
		"query":            map[string]any{"bool": map[string]any{"filter": filters(q)}},
		"size":             size,
		"sort":             []any{map[string]any{"@timestamp": "desc"}, map[string]any{"node_id": "desc"}, map[string]any{"seq": "desc"}},
		"track_total_hits": true,
	}
	if len(q.After) > 0 {
		body["search_after"] = q.After
	}
	res, err := c.Search(ctx, Pattern(prefix), body)
	if missing(err) {
		return &Page{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out struct {
		Hits struct {
			Total struct {
				Value json.Number `json:"value"`
			} `json:"total"`
			Hits []struct {
				Index  string          `json:"_index"`
				ID     string          `json:"_id"`
				Source json.RawMessage `json:"_source"`
				Sort   []any           `json:"sort"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := remarshal(res, &out); err != nil {
		return nil, fmt.Errorf("audit search: %w", err)
	}
	p := &Page{Events: []Hit{}}
	p.Total, _ = out.Hits.Total.Value.Int64()
	for _, h := range out.Hits.Hits {
		var ev Event
		if err := json.Unmarshal(h.Source, &ev); err != nil {
			return nil, fmt.Errorf("audit search: event %s: %w", h.ID, err)
		}
		p.Events = append(p.Events, Hit{Event: ev, ID: h.ID, Index: h.Index})
	}
	if n := len(out.Hits.Hits); n == size {
		p.Next = out.Hits.Hits[n-1].Sort
	}
	return p, nil
}

func filters(q Query) []any {
	f := []any{}
	term := func(field, v string) {
		if v != "" {
			f = append(f, map[string]any{"term": map[string]any{field: v}})
		}
	}
	term("server", q.Server)
	term("user", q.User)
	if strings.HasSuffix(q.Action, ".") {
		f = append(f, map[string]any{"prefix": map[string]any{"action": q.Action}})
	} else {
		term("action", q.Action)
	}
	if !q.From.IsZero() || !q.To.IsZero() {
		r := map[string]any{}
		if !q.From.IsZero() {
			r["gte"] = q.From.UTC().Format(time.RFC3339Nano)
		}
		if !q.To.IsZero() {
			r["lt"] = q.To.UTC().Format(time.RFC3339Nano)
		}
		f = append(f, map[string]any{"range": map[string]any{"@timestamp": r}})
	}
	if q.Text != "" {
		f = append(f, map[string]any{"simple_query_string": map[string]any{
			"query": q.Text, "fields": []string{"message", "user", "target"}, "default_operator": "and"}})
	}
	return f
}

// Servers returns the names of the servers with audit events, at most
// 100 of them.
func Servers(ctx context.Context, c Searcher, prefix string) ([]string, error) {
	res, err := c.Search(ctx, Pattern(prefix), map[string]any{
		"size": 0,
		"aggs": map[string]any{"servers": map[string]any{"terms": map[string]any{"field": "server", "size": 100}}},
	})
	if missing(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out struct {
		Aggregations struct {
			Servers struct {
				Buckets []struct {
					Key string `json:"key"`
				} `json:"buckets"`
			} `json:"servers"`
		} `json:"aggregations"`
	}
	if err := remarshal(res, &out); err != nil {
		return nil, fmt.Errorf("audit servers: %w", err)
	}
	names := []string{}
	for _, b := range out.Aggregations.Servers.Buckets {
		names = append(names, b.Key)
	}
	return names, nil
}

// missing reports whether err says no audit index exists.
func missing(err error) bool {
	var oe *store.Error
	return errors.As(err, &oe) && oe.Status == http.StatusNotFound && strings.Contains(oe.Body, "index_not_found_exception")
}

func remarshal(in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(out)
}
