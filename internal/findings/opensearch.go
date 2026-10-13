package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Doer sends OpenSearch REST requests.
type Doer interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// OpenSearch stores findings in one index. Its name uses "_" rather than
// "-" so event searches over "<prefix>-*" never include findings.
type OpenSearch struct {
	Client Doer
	Index  string
}

// NewOpenSearch returns a store using index "<prefix>_findings".
func NewOpenSearch(c Doer, prefix string) *OpenSearch {
	return &OpenSearch{Client: c, Index: prefix + "_findings"}
}

var notIndexed = map[string]any{"type": "object", "enabled": false}

// properties are the findings index's fields.
func properties() map[string]any {
	kw := map[string]any{"type": "keyword"}
	return map[string]any{
		"id": kw, "detection_id": kw, "severity": kw, "urgency": kw, "status": kw, "owner": kw,
		"disposition": kw, "mitre": kw, "group_key": kw, "entity_values": kw, "case_id": kw, "sample": kw,
		"title":       map[string]any{"type": "text", "fields": map[string]any{"raw": kw}},
		"description": map[string]any{"type": "text"},
		"created":     map[string]any{"type": "date"},
		"updated":     map[string]any{"type": "date"},
		"result":      notIndexed, "entities": notIndexed, "comments": notIndexed, "history": notIndexed,
		"context": notIndexed,
		"query":   map[string]any{"type": "keyword", "index": false},
	}
}

// EnsureIndex creates the findings index if it does not exist. Any server
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

// Upgrade adds fields introduced since the index was created and fills
// urgency on findings raised before it existed. Only the server that runs
// the background jobs does, once it holds them.
func (s *OpenSearch) Upgrade(ctx context.Context) error {
	idx := "/" + url.PathEscape(s.Index)
	if err := s.Client.Do(ctx, http.MethodPut, idx+"/_mapping", map[string]any{"properties": properties()}, nil); err != nil {
		return err
	}
	return s.Client.Do(ctx, http.MethodPost, idx+"/_update_by_query?conflicts=proceed&refresh=true", map[string]any{
		"query":  map[string]any{"bool": map[string]any{"must_not": []any{map[string]any{"exists": map[string]any{"field": "urgency"}}}}},
		"script": map[string]any{"lang": "painless", "source": "ctx._source.urgency = ctx._source.severity"},
	}, nil)
}

// EnsureSampleField maps the sample-data marker (the "sample" field) on an
// index made before it existed. The sample-data load needs it to find its
// own findings again and calls this itself, on whichever server it runs:
// adding one field is quick and changes nothing for servers of an older
// version, so it does not wait for Upgrade on the server that runs the
// background jobs.
func (s *OpenSearch) EnsureSampleField(ctx context.Context) error {
	return s.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index)+"/_mapping",
		map[string]any{"properties": map[string]any{"sample": properties()["sample"]}}, nil)
}

type doc struct {
	*Finding
	EntityValues []string `json:"entity_values,omitempty"`
}

func entityValues(f *Finding) []string {
	var out []string
	for _, v := range f.Entities {
		if s := fmt.Sprint(v); s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func (s *OpenSearch) put(ctx context.Context, f *Finding) error {
	if f.Urgency == "" {
		f.Urgency = f.Severity
	}
	return s.Client.Do(ctx, http.MethodPut,
		"/"+url.PathEscape(s.Index)+"/_doc/"+url.PathEscape(f.ID)+"?refresh=wait_for",
		doc{Finding: f, EntityValues: entityValues(f)}, nil)
}

func (s *OpenSearch) Create(ctx context.Context, f *Finding) error { return s.put(ctx, f) }
func (s *OpenSearch) Save(ctx context.Context, f *Finding) error   { return s.put(ctx, f) }

// Delete removes one finding; a missing one is not an error.
func (s *OpenSearch) Delete(ctx context.Context, id string) error {
	err := s.Client.Do(ctx, http.MethodDelete,
		"/"+url.PathEscape(s.Index)+"/_doc/"+url.PathEscape(id)+"?refresh=wait_for", nil, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 404 {
		return nil
	}
	return err
}

func (s *OpenSearch) Get(ctx context.Context, id string) (*Finding, error) {
	var out struct {
		Found  bool    `json:"found"`
		Source Finding `json:"_source"`
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
	if len(flt.Severity) > 0 {
		fs = append(fs, map[string]any{"terms": map[string]any{"severity": flt.Severity}})
	}
	if len(flt.Urgency) > 0 {
		fs = append(fs, map[string]any{"terms": map[string]any{"urgency": flt.Urgency}})
	}
	if flt.Owner != "" {
		fs = append(fs, map[string]any{"term": map[string]any{"owner": flt.Owner}})
	}
	if flt.DetectionID != "" {
		fs = append(fs, map[string]any{"term": map[string]any{"detection_id": flt.DetectionID}})
	}
	if flt.Sample != nil {
		if *flt.Sample == "" {
			// No marker is empty: a search for the empty one finds
			// nothing, never everything.
			return map[string]any{"match_none": map[string]any{}}
		}
		fs = append(fs, map[string]any{"term": map[string]any{"sample": *flt.Sample}})
	}
	if len(flt.EntityValues) > 0 {
		fs = append(fs, map[string]any{"terms": map[string]any{"entity_values": flt.EntityValues}})
	}
	if !flt.Since.IsZero() {
		fs = append(fs, map[string]any{"range": map[string]any{"created": map[string]any{"gte": flt.Since.UTC().Format(time.RFC3339Nano)}}})
	}
	if !flt.UpdatedSince.IsZero() {
		fs = append(fs, map[string]any{"range": map[string]any{"updated": map[string]any{"gte": flt.UpdatedSince.UTC().Format(time.RFC3339Nano)}}})
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

type searchResp struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source Finding `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
	Aggregations json.RawMessage `json:"aggregations"`
}

func (s *OpenSearch) Search(ctx context.Context, flt Filter) ([]*Finding, int, error) {
	limit := flt.Limit
	if limit <= 0 {
		limit = 200
	}
	// OpenSearch returns at most 10000 hits per request by default.
	limit = min(limit, 10000)
	body := map[string]any{
		"query":            filterQuery(flt),
		"size":             limit,
		"sort":             []any{map[string]any{"created": "desc"}},
		"track_total_hits": true,
	}
	var out searchResp
	if err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_search", body, &out); err != nil {
		return nil, 0, err
	}
	res := make([]*Finding, 0, len(out.Hits.Hits))
	for i := range out.Hits.Hits {
		res = append(res, &out.Hits.Hits[i].Source)
	}
	return res, out.Hits.Total.Value, nil
}

func (s *OpenSearch) Exists(ctx context.Context, detectionID, groupKey string, since time.Time) (bool, error) {
	body := map[string]any{"query": map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"detection_id": detectionID}},
		map[string]any{"term": map[string]any{"group_key": groupKey}},
		map[string]any{"range": map[string]any{"created": map[string]any{"gte": since.UTC().Format(time.RFC3339Nano)}}},
	}}}}
	var out struct {
		Count int `json:"count"`
	}
	if err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_count", body, &out); err != nil {
		return false, err
	}
	return out.Count > 0, nil
}

func (s *OpenSearch) Summary(ctx context.Context) (*Summary, error) {
	body := map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"status": map[string]any{"terms": map[string]any{"field": "status", "size": 20}},
			"open": map[string]any{
				"filter": map[string]any{"bool": map[string]any{"must_not": []any{
					map[string]any{"terms": map[string]any{"status": []string{StatusResolved, StatusClosed}}},
				}}},
				"aggs": map[string]any{
					"severity": map[string]any{"terms": map[string]any{"field": "severity", "size": 20}},
					"urgency":  map[string]any{"terms": map[string]any{"field": "urgency", "size": 20}},
				},
			},
		},
	}
	var out struct {
		Aggregations struct {
			Status struct {
				Buckets []struct {
					Key   string `json:"key"`
					Count int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"status"`
			Open struct {
				Count    int `json:"doc_count"`
				Severity struct {
					Buckets []struct {
						Key   string `json:"key"`
						Count int    `json:"doc_count"`
					} `json:"buckets"`
				} `json:"severity"`
				Urgency struct {
					Buckets []struct {
						Key   string `json:"key"`
						Count int    `json:"doc_count"`
					} `json:"buckets"`
				} `json:"urgency"`
			} `json:"open"`
		} `json:"aggregations"`
	}
	if err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_search", body, &out); err != nil {
		return nil, err
	}
	sm := &Summary{Open: out.Aggregations.Open.Count, ByStatus: map[string]int{}, BySeverity: map[string]int{}, ByUrgency: map[string]int{}}
	for _, b := range out.Aggregations.Status.Buckets {
		sm.ByStatus[b.Key] = b.Count
	}
	for _, b := range out.Aggregations.Open.Severity.Buckets {
		sm.BySeverity[b.Key] = b.Count
	}
	for _, b := range out.Aggregations.Open.Urgency.Buckets {
		sm.ByUrgency[b.Key] = b.Count
	}
	return sm, nil
}
