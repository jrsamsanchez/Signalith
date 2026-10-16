package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Doer is what the OpenSearch backend needs from the client.
type Doer interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// OpenSearch stores indicators in one index, "<prefix>_intel". The "_"
// keeps it out of the "<prefix>-*" pattern event searches use.
type OpenSearch struct {
	Client Doer
	Index  string
	// Replicas are the index's replicas settings (opensearch.replicas,
	// see config.Replicas.IndexSettings); nil is auto.
	Replicas map[string]any
}

// NewOpenSearch returns a backend using index "<prefix>_intel".
func NewOpenSearch(c Doer, prefix string) *OpenSearch {
	return &OpenSearch{Client: c, Index: prefix + "_intel"}
}

// bulkSize is how many indicators go in one bulk request.
const bulkSize = 5000

// properties are the intel index's fields.
func properties() map[string]any {
	kw := map[string]any{"type": "keyword"}
	date := map[string]any{"type": "date"}
	return map[string]any{
		"id": kw, "type": kw, "value": kw, "source": kw, "tags": kw,
		"description": map[string]any{"type": "text"},
		"weight":      map[string]any{"type": "double"},
		"first_seen":  date, "last_seen": date, "expires": date, "updated": date,
	}
}

// EnsureIndex creates the index if it does not exist. Any server may, at
// any time; changes to an index that exists are Upgrade's.
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

// Replicate gives the threat intel index, when it was made with no copy on
// another node, the replicas settings new indices get (see
// store.Replicate). Only the server that runs the background jobs does,
// when it starts running them; doing it again changes nothing.
func (o *OpenSearch) Replicate(ctx context.Context) error {
	return store.Replicate(ctx, o.Client, o.Index, o.Replicas)
}

// Upgrade adds fields introduced since the index was created. Only the
// server that runs the background jobs does, once it holds them.
func (o *OpenSearch) Upgrade(ctx context.Context) error {
	return o.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(o.Index)+"/_mapping", map[string]any{"properties": properties()}, nil)
}

func (o *OpenSearch) bulk(ctx context.Context, body []byte, n int) error {
	var out struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
			Error  *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := o.Client.Do(ctx, http.MethodPost, "/_bulk?refresh=wait_for", body, &out); err != nil {
		return err
	}
	if !out.Errors {
		return nil
	}
	failed, first := 0, ""
	for _, item := range out.Items {
		for action, r := range item {
			if r.Error == nil || (action == "delete" && r.Status == http.StatusNotFound) {
				continue
			}
			failed++
			if first == "" {
				first = r.Error.Type + ": " + r.Error.Reason
			}
		}
	}
	if failed == 0 {
		return nil
	}
	return fmt.Errorf("%d of %d indicators were rejected: %s", failed, n, first)
}

// Put indexes indicators by ID, replacing existing ones.
func (o *OpenSearch) Put(ctx context.Context, inds []Indicator) error {
	for start := 0; start < len(inds); start += bulkSize {
		chunk := inds[start:min(start+bulkSize, len(inds))]
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, ind := range chunk {
			if err := enc.Encode(map[string]any{"index": map[string]any{"_index": o.Index, "_id": ind.ID}}); err != nil {
				return err
			}
			if err := enc.Encode(ind); err != nil {
				return err
			}
		}
		if err := o.bulk(ctx, buf.Bytes(), len(chunk)); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes indicators by ID.
func (o *OpenSearch) Delete(ctx context.Context, ids []string) error {
	for start := 0; start < len(ids); start += bulkSize {
		chunk := ids[start:min(start+bulkSize, len(ids))]
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, id := range chunk {
			if err := enc.Encode(map[string]any{"delete": map[string]any{"_index": o.Index, "_id": id}}); err != nil {
				return err
			}
		}
		if err := o.bulk(ctx, buf.Bytes(), len(chunk)); err != nil {
			return err
		}
	}
	return nil
}

// All reads every indicator, a page at a time.
func (o *OpenSearch) All(ctx context.Context) ([]Indicator, error) {
	var out []Indicator
	var after []any
	for {
		body := map[string]any{
			"size":             10000,
			"sort":             []any{map[string]any{"id": "asc"}},
			"track_total_hits": false,
		}
		if after != nil {
			body["search_after"] = after
		}
		var resp struct {
			Hits struct {
				Hits []struct {
					Source Indicator `json:"_source"`
					Sort   []any     `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		path := "/" + url.PathEscape(o.Index) + "/_search?ignore_unavailable=true&allow_no_indices=true"
		if err := o.Client.Do(ctx, http.MethodPost, path, body, &resp); err != nil {
			return nil, err
		}
		hits := resp.Hits.Hits
		for _, h := range hits {
			out = append(out, h.Source)
		}
		if len(hits) < 10000 {
			return out, nil
		}
		after = hits[len(hits)-1].Sort
	}
}

// SourceIDs lists the IDs of every stored indicator of a source, a page
// at a time.
func (o *OpenSearch) SourceIDs(ctx context.Context, source string) ([]string, error) {
	var out []string
	var after []any
	for {
		body := map[string]any{
			"size":             10000,
			"query":            map[string]any{"term": map[string]any{"source": source}},
			"_source":          []string{"id"},
			"sort":             []any{map[string]any{"id": "asc"}},
			"track_total_hits": false,
		}
		if after != nil {
			body["search_after"] = after
		}
		var resp struct {
			Hits struct {
				Hits []struct {
					ID   string `json:"_id"`
					Sort []any  `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		path := "/" + url.PathEscape(o.Index) + "/_search?ignore_unavailable=true&allow_no_indices=true"
		if err := o.Client.Do(ctx, http.MethodPost, path, body, &resp); err != nil {
			return nil, err
		}
		hits := resp.Hits.Hits
		for _, h := range hits {
			out = append(out, h.ID)
		}
		if len(hits) < 10000 {
			return out, nil
		}
		after = hits[len(hits)-1].Sort
	}
}

// Version is the indicator count and the latest update time.
func (o *OpenSearch) Version(ctx context.Context) (string, error) {
	body := map[string]any{
		"size":             0,
		"track_total_hits": true,
		"aggs":             map[string]any{"updated": map[string]any{"max": map[string]any{"field": "updated"}}},
	}
	var resp struct {
		Hits struct {
			Total struct {
				Value json.Number `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations struct {
			Updated struct {
				Value any `json:"value"`
			} `json:"updated"`
		} `json:"aggregations"`
	}
	path := "/" + url.PathEscape(o.Index) + "/_search?ignore_unavailable=true&allow_no_indices=true"
	if err := o.Client.Do(ctx, http.MethodPost, path, body, &resp); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%v", resp.Hits.Total.Value, resp.Aggregations.Updated.Value), nil
}
