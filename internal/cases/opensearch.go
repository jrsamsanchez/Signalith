package cases

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Doer sends OpenSearch REST requests.
type Doer interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// OpenSearch stores cases in one index. Its name uses "_" rather than "-"
// so event searches over "<prefix>-*" never include cases.
type OpenSearch struct {
	Client Doer
	Index  string
}

// NewOpenSearch returns a store using index "<prefix>_cases".
func NewOpenSearch(c Doer, prefix string) *OpenSearch {
	return &OpenSearch{Client: c, Index: prefix + "_cases"}
}

// properties are the cases index's fields.
func properties() map[string]any {
	kw := map[string]any{"type": "keyword"}
	off := map[string]any{"type": "object", "enabled": false}
	return map[string]any{
		"id": kw, "status": kw, "severity": kw, "owner": kw, "findings": kw, "entity_values": kw, "created_by": kw, "sample": kw,
		"title":       map[string]any{"type": "text", "fields": map[string]any{"raw": kw}},
		"description": map[string]any{"type": "text"},
		"resolution":  map[string]any{"type": "text"},
		"created":     map[string]any{"type": "date"},
		"updated":     map[string]any{"type": "date"},
		"entities":    off, "entries": off, "history": off,
	}
}

// EnsureIndex creates the cases index if it does not exist. Any server
// may, at any time; changes to an index that exists are Upgrade's.
func (s *OpenSearch) EnsureIndex(ctx context.Context) error {
	body := map[string]any{
		"settings": map[string]any{"number_of_shards": 1, "number_of_replicas": 0},
		"mappings": map[string]any{"dynamic": "false", "properties": properties()},
	}
	err := s.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index), body, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 400 && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// Upgrade adds fields introduced since the index was created. Only the
// server that runs the background jobs does, once it holds them.
func (s *OpenSearch) Upgrade(ctx context.Context) error {
	return s.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index)+"/_mapping", map[string]any{"properties": properties()}, nil)
}

// EnsureSampleField maps the sample-data marker (the "sample" field) on an
// index made before it existed. The sample-data load needs it to find its
// own cases again and calls this itself, on whichever server it runs:
// adding one field is quick and changes nothing for servers of an older
// version, so it does not wait for Upgrade on the server that runs the
// background jobs.
func (s *OpenSearch) EnsureSampleField(ctx context.Context) error {
	return s.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index)+"/_mapping",
		map[string]any{"properties": map[string]any{"sample": properties()["sample"]}}, nil)
}

type doc struct {
	*Case
	EntityValues []string `json:"entity_values,omitempty"`
}

// put writes a case; op is "_doc" to create or replace it, or "_create"
// to create it only if its ID is new.
func (s *OpenSearch) put(ctx context.Context, c *Case, op string) error {
	return s.Client.Do(ctx, http.MethodPut,
		"/"+url.PathEscape(s.Index)+"/"+op+"/"+url.PathEscape(c.ID)+"?refresh=wait_for",
		doc{Case: c, EntityValues: c.EntityValues()}, nil)
}

// Create never replaces an existing case: OpenSearch answers 409 when the
// ID is taken.
func (s *OpenSearch) Create(ctx context.Context, c *Case) error {
	err := s.put(ctx, c, "_create")
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == http.StatusConflict {
		return ErrExists
	}
	return err
}

func (s *OpenSearch) Save(ctx context.Context, c *Case) error { return s.put(ctx, c, "_doc") }

// Delete removes one case; a missing one is not an error.
func (s *OpenSearch) Delete(ctx context.Context, id string) error {
	err := s.Client.Do(ctx, http.MethodDelete,
		"/"+url.PathEscape(s.Index)+"/_doc/"+url.PathEscape(id)+"?refresh=wait_for", nil, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 404 {
		return nil
	}
	return err
}

func (s *OpenSearch) Get(ctx context.Context, id string) (*Case, error) {
	var out struct {
		Found  bool `json:"found"`
		Source Case `json:"_source"`
	}
	err := s.Client.Do(ctx, http.MethodGet, "/"+url.PathEscape(s.Index)+"/_doc/"+url.PathEscape(id), nil, &out)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 404 {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !out.Found {
		return nil, ErrNotFound
	}
	return &out.Source, nil
}

func filterQuery(flt Filter) map[string]any {
	var fs []any
	if len(flt.Status) > 0 {
		fs = append(fs, map[string]any{"terms": map[string]any{"status": flt.Status}})
	}
	if flt.Owner != "" {
		fs = append(fs, map[string]any{"term": map[string]any{"owner": flt.Owner}})
	}
	if flt.FindingID != "" {
		fs = append(fs, map[string]any{"term": map[string]any{"findings": flt.FindingID}})
	}
	if flt.Sample != nil {
		if *flt.Sample == "" {
			// No marker is empty: a search for the empty one finds
			// nothing, never everything.
			return map[string]any{"match_none": map[string]any{}}
		}
		fs = append(fs, map[string]any{"term": map[string]any{"sample": *flt.Sample}})
	}
	if t := strings.TrimSpace(flt.Text); t != "" {
		fs = append(fs, map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
			map[string]any{"match": map[string]any{"title": t}},
			map[string]any{"match": map[string]any{"description": t}},
			map[string]any{"term": map[string]any{"entity_values": t}},
			map[string]any{"term": map[string]any{"id": t}},
		}}})
	}
	if len(fs) == 0 {
		return map[string]any{"match_all": map[string]any{}}
	}
	return map[string]any{"bool": map[string]any{"filter": fs}}
}

func (s *OpenSearch) Search(ctx context.Context, flt Filter) ([]*Case, int, error) {
	limit := flt.Limit
	if limit <= 0 {
		limit = 200
	}
	body := map[string]any{
		"query":            filterQuery(flt),
		"size":             min(limit, 10000),
		"sort":             []any{map[string]any{"updated": "desc"}},
		"track_total_hits": true,
		"_source":          map[string]any{"excludes": []string{"entries", "history"}},
	}
	var out struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source Case `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_search", body, &out); err != nil {
		return nil, 0, err
	}
	res := make([]*Case, 0, len(out.Hits.Hits))
	for i := range out.Hits.Hits {
		res = append(res, &out.Hits.Hits[i].Source)
	}
	return res, out.Hits.Total.Value, nil
}
