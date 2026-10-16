package notebooks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Doer sends OpenSearch REST requests.
type Doer interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// OpenSearch stores notebooks in one index. Its name uses "_" rather than
// "-" so event searches over "<prefix>-*" never include notebooks.
type OpenSearch struct {
	Client Doer
	Index  string
	// Replicas are the index's replicas settings (opensearch.replicas);
	// nil is auto.
	Replicas map[string]any
}

// NewOpenSearch returns a store using index "<prefix>_notebooks".
func NewOpenSearch(c Doer, prefix string) *OpenSearch {
	return &OpenSearch{Client: c, Index: prefix + "_notebooks"}
}

func properties() map[string]any {
	kw := map[string]any{"type": "keyword"}
	return map[string]any{
		"id": kw, "owner": kw, "owner_key": kw, "sharing": kw, "techniques": kw, "cases": kw, "from": kw, "updated_by": kw,
		"title":        map[string]any{"type": "text", "fields": map[string]any{"raw": kw}},
		"description":  map[string]any{"type": "text"},
		"created":      map[string]any{"type": "date"},
		"updated":      map[string]any{"type": "date"},
		"last_run":     map[string]any{"type": "date"},
		"cell_count":   map[string]any{"type": "integer"},
		"search_count": map[string]any{"type": "integer"},
		"cells":        map[string]any{"type": "object", "enabled": false},
	}
}

// EnsureIndex creates the notebooks index if it does not exist.
func (s *OpenSearch) EnsureIndex(ctx context.Context) error {
	body := map[string]any{
		"settings": store.SmallIndexSettings(s.Replicas),
		"mappings": map[string]any{"dynamic": "false", "properties": properties()},
	}
	err := s.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index), body, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 400 && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// Replicate gives the index the replicas settings new indices get, when
// it was made with no copy on another node (see store.Replicate).
func (s *OpenSearch) Replicate(ctx context.Context) error {
	return store.Replicate(ctx, s.Client, s.Index, s.Replicas)
}

// Upgrade adds fields introduced since the index was created.
func (s *OpenSearch) Upgrade(ctx context.Context) error {
	return s.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index)+"/_mapping", map[string]any{"properties": properties()}, nil)
}

// doc is a notebook as it is indexed, with the fields the list searches
// and shows without reading the cells.
type doc struct {
	*Notebook
	OwnerKey    string     `json:"owner_key"`
	CellCount   int        `json:"cell_count"`
	SearchCount int        `json:"search_count"`
	LastRun     *time.Time `json:"last_run,omitempty"`
}

func docOf(n *Notebook) doc {
	sum := Summarize(n)
	d := doc{Notebook: n, OwnerKey: strings.ToLower(n.Owner), CellCount: sum.Cells, SearchCount: sum.Searches}
	if !sum.LastRun.IsZero() {
		d.LastRun = &sum.LastRun
	}
	return d
}

// Create never replaces an existing notebook: OpenSearch answers 409 when
// the ID is taken.
func (s *OpenSearch) Create(ctx context.Context, n *Notebook) error {
	err := s.Client.Do(ctx, http.MethodPut,
		"/"+url.PathEscape(s.Index)+"/_create/"+url.PathEscape(n.ID)+"?refresh=wait_for", docOf(n), nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == http.StatusConflict {
		return ErrExists
	}
	return err
}

func (s *OpenSearch) Get(ctx context.Context, id string) (*Notebook, error) {
	var out struct {
		Found  bool     `json:"found"`
		Source Notebook `json:"_source"`
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

// versioned is the part of *store.Client that reads and writes documents
// with their versions.
type versioned interface {
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
}

// Modify writes the notebook back only if it is still at the version read,
// so a change made meanwhile on another server, or in another tab, is
// never overwritten: change runs again on the newer copy.
func (s *OpenSearch) Modify(ctx context.Context, id string, change func(n *Notebook) (bool, error)) (*Notebook, error) {
	vc, ok := s.Client.(versioned)
	if !ok {
		return nil, errors.New("notebooks: the OpenSearch client cannot write with versions")
	}
	var out *Notebook
	err := store.RetryConflicts(ctx, func() error {
		src, v, found, err := vc.Get(ctx, s.Index, id)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		var n Notebook
		if err := json.Unmarshal(src, &n); err != nil {
			return err
		}
		changed, err := change(&n)
		if err != nil {
			return changeError{err}
		}
		if changed {
			if _, err := vc.PutIf(ctx, s.Index, id, docOf(&n), v, true); err != nil {
				return err
			}
		}
		out = &n
		return nil
	})
	if err != nil {
		return nil, modifyResult(err)
	}
	return out, nil
}

// Delete removes one notebook; a missing one is not an error.
func (s *OpenSearch) Delete(ctx context.Context, id string) error {
	err := s.Client.Do(ctx, http.MethodDelete,
		"/"+url.PathEscape(s.Index)+"/_doc/"+url.PathEscape(id)+"?refresh=wait_for", nil, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 404 {
		return nil
	}
	return err
}

func filterQuery(f Filter) map[string]any {
	var fs []any
	if !f.Admin {
		fs = append(fs, map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
			map[string]any{"term": map[string]any{"owner_key": strings.ToLower(f.User)}},
			map[string]any{"terms": map[string]any{"sharing": []string{Read, Edit}}},
		}}})
	}
	if f.Owner != "" {
		fs = append(fs, map[string]any{"term": map[string]any{"owner_key": strings.ToLower(f.Owner)}})
	}
	if f.Case != "" {
		fs = append(fs, map[string]any{"term": map[string]any{"cases": f.Case}})
	}
	if t := strings.ToUpper(strings.TrimSpace(f.Technique)); t != "" {
		fs = append(fs, map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
			map[string]any{"term": map[string]any{"techniques": t}},
			map[string]any{"prefix": map[string]any{"techniques": t + "."}},
		}}})
	}
	if t := strings.TrimSpace(f.Text); t != "" {
		fs = append(fs, map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
			map[string]any{"match": map[string]any{"title": t}},
			map[string]any{"match": map[string]any{"description": t}},
			map[string]any{"term": map[string]any{"id": t}},
		}}})
	}
	if len(fs) == 0 {
		return map[string]any{"match_all": map[string]any{}}
	}
	return map[string]any{"bool": map[string]any{"filter": fs}}
}

func (s *OpenSearch) Search(ctx context.Context, f Filter) ([]*Summary, int, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	body := map[string]any{
		"query":            filterQuery(f),
		"size":             min(limit, 10000),
		"sort":             []any{map[string]any{"updated": "desc"}},
		"track_total_hits": true,
		"_source":          map[string]any{"excludes": []string{"cells"}},
	}
	var out struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source doc `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_search", body, &out); err != nil {
		return nil, 0, err
	}
	res := make([]*Summary, 0, len(out.Hits.Hits))
	for _, h := range out.Hits.Hits {
		d := h.Source
		if d.Notebook == nil {
			continue
		}
		sum := Summarize(d.Notebook)
		sum.Cells, sum.Searches = d.CellCount, d.SearchCount
		if d.LastRun != nil {
			sum.LastRun = *d.LastRun
		}
		res = append(res, sum)
	}
	return res, out.Hits.Total.Value, nil
}
