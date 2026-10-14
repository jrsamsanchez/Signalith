package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// mappedIndices is an OpenSearch that keeps each index's mapped field
// paths, objects counted, with the known fields mapped up front as the
// template does, and refuses a document that would take an index past
// 2,000 fields, as OpenSearch does.
type mappedIndices struct {
	mu      sync.Mutex
	paths   map[string]map[string]bool
	refused int
	max     int // the most fields any index had
}

func (m *mappedIndices) indexLocked(name string) map[string]bool {
	if m.paths == nil {
		m.paths = map[string]map[string]bool{}
	}
	ix := m.paths[name]
	if ix == nil {
		ix = map[string]bool{}
		for k := range knownFields {
			addPaths(ix, k)
		}
		m.paths[name] = ix
	}
	return ix
}

func addPaths(ix map[string]bool, name string) int {
	added := 0
	parts := strings.Split(name, ".")
	for i := 1; i <= len(parts); i++ {
		p := strings.Join(parts[:i], ".")
		if !ix[p] {
			ix[p] = true
			added++
		}
	}
	return added
}

func (m *mappedIndices) Bulk(_ context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []store.BulkItemError
	for i, d := range docs {
		ix := m.indexLocked(d.Index)
		var add []string
		for k := range d.Doc {
			add = append(add, k)
		}
		trial := map[string]bool{}
		n := 0
		for _, k := range add {
			parts := strings.Split(k, ".")
			for j := 1; j <= len(parts); j++ {
				p := strings.Join(parts[:j], ".")
				if !ix[p] && !trial[p] {
					trial[p] = true
					n++
				}
			}
		}
		if len(ix)+n > 2000 {
			m.refused++
			errs = append(errs, store.BulkItemError{Index: d.Index, Pos: i, Status: 400, Type: "illegal_argument_exception",
				Reason: "Limit of total fields [2000] has been exceeded"})
			continue
		}
		for p := range trial {
			ix[p] = true
		}
		m.max = max(m.max, len(ix))
	}
	return errs, nil
}

func (m *mappedIndices) count(_ context.Context, index string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.indexLocked(index)), nil
}

// newNames sends batches of events, each with one new field name of its
// own, from a pipeline.
func newNames(t *testing.T, p *Pipeline, who string, batches, per int) {
	t.Helper()
	for b := range batches {
		events := make([]Event, per)
		for i := range events {
			events[i] = Event{Time: now, Model: "Other", Fields: map[string]any{
				"message": "x", fmt.Sprintf("%s_%03d_%03d", who, b, i): "v"}}
		}
		if _, err := p.IngestEvents(context.Background(), events); err != nil {
			t.Fatal(err)
		}
	}
}

func namesFrom(m *mappedIndices, who string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, ix := range m.paths {
		for p := range ix {
			if strings.HasPrefix(p, who+"_") {
				n++
			}
		}
	}
	return n
}

func TestTwoServersIngestingNewFieldNamesNeverPass2000FieldsPerIndex(t *testing.T) {
	m := &mappedIndices{}
	var ps []*Pipeline
	for range 2 {
		p := &Pipeline{Store: m, Prefix: "sig", Now: func() time.Time { return now },
			Servers: func() int { return 2 }, FieldCount: m.count}
		p.counter.ttl = -1
		ps = append(ps, p)
	}
	var wg sync.WaitGroup
	for i, p := range ps {
		wg.Go(func() { newNames(t, p, fmt.Sprintf("s%d", i), 20, 50) })
	}
	wg.Wait()
	if m.refused > 0 || m.max > 2000 {
		t.Errorf("refused %d, most fields %d", m.refused, m.max)
	}
	for i := range ps {
		if got := namesFrom(m, fmt.Sprintf("s%d", i)); got != 500 {
			t.Errorf("server %d added %d names, want its share of 500", i, got)
		}
	}
}

func TestManyServersStopAtTheMappingGuard(t *testing.T) {
	m := &mappedIndices{}
	var ps []*Pipeline
	for range 20 {
		p := &Pipeline{Store: m, Prefix: "sig", Now: func() time.Time { return now },
			Servers: func() int { return 20 }, FieldCount: m.count}
		p.counter.ttl = -1
		ps = append(ps, p)
	}
	if namesBudget(20) != 100 {
		t.Fatalf("share of 20 servers: %d", namesBudget(20))
	}
	var wg sync.WaitGroup
	for i, p := range ps {
		wg.Go(func() { newNames(t, p, fmt.Sprintf("s%02d", i), 4, 30) })
	}
	wg.Wait()
	// 20 shares of 100 and the known fields would pass 2,000: the guard
	// stops new names soon after 1,600.
	if m.refused > 0 || m.max > 2000 || m.max < mappingStop {
		t.Errorf("refused %d, most fields %d", m.refused, m.max)
	}
}

func TestAFailingFieldCountFallsBackToTheBudget(t *testing.T) {
	m := &mappedIndices{}
	asked := 0
	p := &Pipeline{Store: m, Prefix: "sig", Now: func() time.Time { return now },
		Servers: func() int { return 4 },
		FieldCount: func(context.Context, string) (int, error) {
			asked++
			return 0, errors.New("no answer")
		}}
	newNames(t, p, "s", 10, 50)
	if got := namesFrom(m, "s"); got != 250 || asked == 0 {
		t.Errorf("names %d, asked %d", got, asked)
	}
	// Without Servers, a server alone keeps the whole budget.
	alone := &Pipeline{Store: &mappedIndices{}, Prefix: "sig", Now: func() time.Time { return now }}
	if alone.servers() != 1 || namesBudget(alone.servers()) != maxNewNamesPerIndex || namesBudget(0) != maxNewNamesPerIndex {
		t.Error("budget alone")
	}
}

func TestFieldCountIsKeptForAWhile(t *testing.T) {
	var c fieldCounter
	calls := 0
	fetch := func(context.Context, string) (int, error) { calls++; return 1700, nil }
	at := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	for range 3 {
		if n, _ := c.count(context.Background(), "i", at, fetch); n != 1700 {
			t.Fatal(n)
		}
	}
	if calls != 1 {
		t.Errorf("fetched %d times within the window", calls)
	}
	c.count(context.Background(), "i", at.Add(mappingTTL), fetch)
	if calls != 2 {
		t.Errorf("not fetched again after the window: %d", calls)
	}
}

func TestMappingFieldCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing/_mapping" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":{"type":"index_not_found_exception","reason":"no such index [missing]"},"status":404}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"sig-other-2026.10.14": map[string]any{"mappings": map[string]any{
			"properties": map[string]any{
				"user": map[string]any{"type": "keyword"},
				"msg":  map[string]any{"type": "text", "fields": map[string]any{"raw": map[string]any{"type": "keyword"}}},
				"a":    map[string]any{"properties": map[string]any{"b": map[string]any{"type": "keyword"}, "c": map[string]any{"type": "long"}}},
			}}}})
	}))
	defer srv.Close()
	count := MappingFieldCount(store.New(store.Config{URL: srv.URL}))
	// user, msg, msg.raw, a, a.b, a.c
	if n, err := count(context.Background(), "sig-other-2026.10.14"); err != nil || n != 6 {
		t.Errorf("count %d %v", n, err)
	}
	if n, err := count(context.Background(), "missing"); err != nil || n != 0 {
		t.Errorf("missing %d %v", n, err)
	}
}

// A count that could not be had is asked for again by the next write, and
// one writer going away does not cut the shared fetch short.
func TestAFailedFieldCountIsNotKept(t *testing.T) {
	var c fieldCounter
	calls := 0
	fail := true
	fetch := func(ctx context.Context, _ string) (int, error) {
		calls++
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if fail {
			return 0, errors.New("no answer")
		}
		return 1700, nil
	}
	at := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	if _, err := c.count(context.Background(), "i", at, fetch); err == nil {
		t.Fatal("the failure was not reported")
	}
	fail = false
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := c.count(gone, "i", at, fetch); err != nil || n != 1700 {
		t.Errorf("after a failure: %d %v", n, err)
	}
	if calls != 2 {
		t.Errorf("fetched %d times", calls)
	}
}
