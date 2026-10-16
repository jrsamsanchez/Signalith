package respond

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

// Store is the audit log of runs.
type Store interface {
	// Put writes a run: when it starts (done false), and again when it
	// ends (done true), which also makes it visible to searches at once.
	Put(ctx context.Context, run *Run, done bool) error
	// List returns runs, newest first.
	List(ctx context.Context, flt Filter) ([]*Run, error)
}

// Filter selects runs.
type Filter struct {
	FindingID string
	CaseID    string
	Action    string
	Limit     int // default 50, at most 500
}

// staleAfter is when a run still marked running must have been left so by
// a server that stopped: the longest script timeout and then some.
const staleAfter = MaxScriptTimeout*time.Second + 5*time.Minute

// markStale reports a run left running by a stopped server as interrupted.
func markStale(r *Run, now time.Time) {
	if r.Status == StatusRunning && now.Sub(r.Started) > staleAfter {
		r.Status = StatusInterrupted
		r.Error = "The Signalith server stopped while this ran, so it may or may not have finished. Check the target."
	}
}

func limitOf(flt Filter) int {
	switch {
	case flt.Limit <= 0:
		return 50
	case flt.Limit > 500:
		return 500
	}
	return flt.Limit
}

// Doer sends OpenSearch REST requests.
type Doer interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// OpenSearch keeps runs in one index. Its name uses "_" rather than "-"
// so event searches over "<prefix>-*" never include it.
type OpenSearch struct {
	Client Doer
	Index  string
	// Replicas are the index's replicas settings (opensearch.replicas,
	// see config.Replicas.IndexSettings); nil is auto.
	Replicas map[string]any
}

// NewOpenSearch returns a store using index "<prefix>_actions".
func NewOpenSearch(c Doer, prefix string) *OpenSearch {
	return &OpenSearch{Client: c, Index: prefix + "_actions"}
}

func properties() map[string]any {
	kw := map[string]any{"type": "keyword"}
	date := map[string]any{"type": "date"}
	return map[string]any{
		"id": kw, "action": kw, "action_label": kw, "kind": kw, "target": kw, "target_kind": kw,
		"actor": kw, "automatic": map[string]any{"type": "boolean"}, "approved_by": kw,
		"finding_id": kw, "case_id": kw, "status": kw, "server": kw,
		"reason":  map[string]any{"type": "text"},
		"summary": map[string]any{"type": "text"},
		"error":   map[string]any{"type": "text"},
		"output":  map[string]any{"type": "text", "index": false},
		"started": date, "finished": date,
		"duration_ms": map[string]any{"type": "long"},
	}
}

// EnsureIndex creates the index if it does not exist. Any server may, at
// any time.
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

// Replicate gives the response actions index, when it was made with no
// copy on another node, the replicas settings new indices get (see
// store.Replicate). Only the server that runs the background jobs does,
// when it starts running them; doing it again changes nothing.
func (s *OpenSearch) Replicate(ctx context.Context) error {
	return store.Replicate(ctx, s.Client, s.Index, s.Replicas)
}

func (s *OpenSearch) Put(ctx context.Context, run *Run, done bool) error {
	path := "/" + url.PathEscape(s.Index) + "/_doc/" + url.PathEscape(run.ID)
	if done {
		path += "?refresh=wait_for"
	}
	return s.Client.Do(ctx, http.MethodPut, path, run, nil)
}

func (s *OpenSearch) List(ctx context.Context, flt Filter) ([]*Run, error) {
	var fs []any
	for _, t := range []struct{ field, v string }{{"finding_id", flt.FindingID}, {"case_id", flt.CaseID}, {"action", flt.Action}} {
		if t.v != "" {
			fs = append(fs, map[string]any{"term": map[string]any{t.field: t.v}})
		}
	}
	q := map[string]any{"match_all": map[string]any{}}
	if len(fs) > 0 {
		q = map[string]any{"bool": map[string]any{"filter": fs}}
	}
	body := map[string]any{"query": q, "size": limitOf(flt), "sort": []any{map[string]any{"started": "desc"}}}
	var out struct {
		Hits struct {
			Hits []struct {
				Source Run `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	err := s.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(s.Index)+"/_search", body, &out)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 404 {
		return []*Run{}, nil
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	res := make([]*Run, 0, len(out.Hits.Hits))
	for i := range out.Hits.Hits {
		r := &out.Hits.Hits[i].Source
		markStale(r, now)
		res = append(res, r)
	}
	return res, nil
}

// Memory keeps runs in memory, for tests and servers without OpenSearch.
type Memory struct {
	mu   sync.Mutex
	runs []*Run
	// Fail makes Put return this error, to test a broken audit log.
	Fail error
}

func (m *Memory) Put(_ context.Context, run *Run, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	c := *run
	c.RecordErrors = slices.Clone(run.RecordErrors)
	for i, r := range m.runs {
		if r.ID == run.ID {
			m.runs[i] = &c
			return nil
		}
	}
	m.runs = append(m.runs, &c)
	return nil
}

func (m *Memory) List(_ context.Context, flt Filter) ([]*Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*Run{}
	for i := len(m.runs) - 1; i >= 0 && len(out) < limitOf(flt); i-- {
		r := *m.runs[i]
		if (flt.FindingID != "" && r.FindingID != flt.FindingID) || (flt.CaseID != "" && r.CaseID != flt.CaseID) ||
			(flt.Action != "" && r.Action != flt.Action) {
			continue
		}
		markStale(&r, time.Now())
		out = append(out, &r)
	}
	return out, nil
}
