package summary

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeEvent is one raw event of the fake.
type fakeEvent struct {
	model string
	t     time.Time
	f     map[string]any
}

// fakeDoc is a document of the fake's runtime index.
type fakeDoc struct {
	raw json.RawMessage
	v   store.Version
}

// fakeClient is an in-memory stand-in for the OpenSearch calls the builder
// makes: raw events per data model, summary rows, the composite and date
// histogram aggregations over them, _delete_by_query and the runtime
// index's versioned state documents.
type fakeClient struct {
	mu      sync.Mutex
	prefix  string
	events  []fakeEvent
	rows    map[string]store.IndexedDoc // id -> row
	indices map[string]bool             // summary indices created
	extra   []string                    // more index names ListIndices answers
	hidden  map[string]bool             // raw index names ListIndices leaves out
	runtime map[string]fakeDoc
	seq     int64

	// fail, when it returns an error, answers the call named op instead.
	fail     func(op, detail string) error
	bulkErrs []store.BulkItemError
	calls    []string
	deleted  []string // indices deleted
	pages    int      // composite pages answered
	// putBodies are the bodies indices were created with.
	putBodies map[string]map[string]any
}

func newFake(prefix string) *fakeClient {
	return &fakeClient{prefix: prefix, rows: map[string]store.IndexedDoc{}, indices: map[string]bool{},
		hidden: map[string]bool{}, runtime: map[string]fakeDoc{}}
}

func (f *fakeClient) add(model string, t time.Time, fields map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, fakeEvent{model: model, t: t.UTC(), f: fields})
}

func (f *fakeClient) failing(op, detail string) error {
	f.calls = append(f.calls, op+" "+detail)
	if f.fail != nil {
		return f.fail(op, detail)
	}
	return nil
}

func (f *fakeClient) rawIndex(e fakeEvent) string {
	return datamodel.IndexName(f.prefix, e.model, e.t.Format("2006.01.02"))
}

// roundtrip makes v look as if it came over the wire.
func roundtrip(v any) map[string]any {
	b, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// filters reads the time range, model term and generation must_not of a
// query.
type parsed struct {
	gte, lt  float64
	hasGte   bool
	hasLt    bool
	model    string
	notGen   string
	hasModel bool
}

func parseQuery(q map[string]any) parsed {
	var p parsed
	b, _ := dig(q, "bool").(map[string]any)
	fs, _ := b["filter"].([]any)
	for _, x := range fs {
		m, _ := x.(map[string]any)
		if r, ok := dig(m, "range", "@timestamp").(map[string]any); ok {
			p.gte, p.hasGte = toFloat(r["gte"])
			p.lt, p.hasLt = toFloat(r["lt"])
		}
		if v, ok := dig(m, "term", ModelField).(string); ok {
			p.model, p.hasModel = v, true
		}
	}
	nots, _ := b["must_not"].([]any)
	for _, x := range nots {
		m, _ := x.(map[string]any)
		if v, ok := dig(m, "term", GenField).(string); ok {
			p.notGen = v
		}
	}
	return p
}

func (p parsed) in(t time.Time) bool {
	ms := float64(t.UnixMilli())
	return (!p.hasGte || ms >= p.gte) && (!p.hasLt || ms < p.lt)
}

// modelOf finds the data model whose raw pattern is index.
func (f *fakeClient) modelOf(index string) string {
	for _, m := range Models() {
		if rawPattern(f.prefix, m) == index {
			return m
		}
	}
	return ""
}

func bucketKey(t time.Time, interval string) int64 {
	switch interval {
	case "1d":
		return t.Truncate(24 * time.Hour).UnixMilli()
	case "1h":
		return t.Truncate(time.Hour).UnixMilli()
	default:
		d, _ := time.ParseDuration(interval)
		return t.Truncate(d).UnixMilli()
	}
}

func (f *fakeClient) Search(ctx context.Context, index string, body map[string]any) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body = roundtrip(body)
	aggs, _ := body["aggs"].(map[string]any)
	kind := " h"
	if _, ok := aggs["g"]; ok {
		kind = " g"
	}
	if err := f.failing("search", index+kind); err != nil {
		return nil, err
	}
	q, _ := body["query"].(map[string]any)
	p := parseQuery(q)
	if comp, ok := dig(aggs, "g", "composite").(map[string]any); ok {
		return f.composite(f.modelOf(index), p, comp, dig(aggs, "g", "aggs")), nil
	}
	hist, _ := dig(aggs, "h", "date_histogram").(map[string]any)
	interval, _ := hist["fixed_interval"].(string)
	if ci, ok := hist["calendar_interval"].(string); ok {
		interval = ci
	}
	counts := map[int64]float64{}
	if index == IndexPattern(f.prefix) {
		for _, r := range f.rows {
			ts, _ := time.Parse(time.RFC3339, r.Doc["@timestamp"].(string))
			if r.Doc[ModelField] != p.model || !p.in(ts) {
				continue
			}
			n, _ := toFloat(r.Doc[CountField])
			counts[bucketKey(ts, interval)] += n
		}
	} else {
		m := f.modelOf(index)
		for _, e := range f.events {
			if e.model == m && p.in(e.t) {
				counts[bucketKey(e.t, interval)]++
			}
		}
	}
	var buckets []any
	for _, k := range sortedKeys(counts) {
		b := map[string]any{"key": k, "doc_count": counts[k]}
		if index == IndexPattern(f.prefix) {
			b["doc_count"] = 1
			b["n"] = map[string]any{"value": counts[k]}
		}
		buckets = append(buckets, b)
	}
	return roundtrip(map[string]any{"aggregations": map[string]any{"h": map[string]any{"buckets": buckets}}}), nil
}

type compBucket struct {
	key   map[string]any
	count int64
	sums  []float64
	order string
}

func (f *fakeClient) composite(model string, p parsed, comp map[string]any, sub any) map[string]any {
	f.pages++
	dims := Dims(model)
	ms := Measures(model)
	byKey := map[string]*compBucket{}
	for _, e := range f.events {
		if e.model != model || !p.in(e.t) {
			continue
		}
		key := map[string]any{"t": e.t.Truncate(Slot).UnixMilli()}
		vals := []any{e.t.Truncate(Slot).UnixMilli()}
		for i, d := range dims {
			key[fmt.Sprintf("d%d", i)] = e.f[d]
			vals = append(vals, e.f[d])
		}
		ob, _ := json.Marshal(vals)
		b := byKey[string(ob)]
		if b == nil {
			b = &compBucket{key: key, sums: make([]float64, len(ms)), order: string(ob)}
			byKey[string(ob)] = b
		}
		b.count++
		for i, m := range ms {
			if v, ok := toFloat(e.f[m]); ok {
				b.sums[i] += v
			}
		}
	}
	all := make([]*compBucket, 0, len(byKey))
	for _, b := range byKey {
		all = append(all, b)
	}
	slices.SortFunc(all, func(a, b *compBucket) int { return strings.Compare(a.order, b.order) })
	start := 0
	if after, ok := comp["after"].(map[string]any); ok {
		vals := []any{after["t"]}
		for i := range dims {
			vals = append(vals, after[fmt.Sprintf("d%d", i)])
		}
		ob, _ := json.Marshal(vals)
		for start < len(all) && all[start].order <= string(ob) {
			start++
		}
	}
	size, _ := toFloat(comp["size"])
	end := min(len(all), start+int(size))
	var buckets []any
	for _, b := range all[start:end] {
		bk := map[string]any{"key": b.key, "doc_count": b.count}
		if sub != nil {
			for i := range ms {
				bk[fmt.Sprintf("s%d", i)] = map[string]any{"value": b.sums[i]}
			}
		}
		buckets = append(buckets, bk)
	}
	g := map[string]any{"buckets": buckets}
	if end > start {
		g["after_key"] = all[end-1].key
	}
	return roundtrip(map[string]any{"aggregations": map[string]any{"g": g}})
}

func (f *fakeClient) Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failing("bulk", fmt.Sprint(len(docs))); err != nil {
		return nil, err
	}
	if len(f.bulkErrs) > 0 {
		return f.bulkErrs, nil
	}
	for _, d := range docs {
		d.Doc = roundtrip(d.Doc)
		f.rows[d.ID] = d
		f.indices[d.Index] = true
	}
	return nil, nil
}

func (f *fakeClient) Do(ctx context.Context, method, p string, body any, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failing("do", method+" "+p); err != nil {
		return err
	}
	clean, _, _ := strings.Cut(p, "?")
	switch {
	case strings.HasSuffix(clean, "/_refresh"):
		return nil
	case strings.HasSuffix(clean, "/_delete_by_query"):
		q, _ := roundtrip(body)["query"].(map[string]any)
		pq := parseQuery(q)
		var n int64
		for id, r := range f.rows {
			ts, _ := time.Parse(time.RFC3339, r.Doc["@timestamp"].(string))
			if pq.hasModel && r.Doc[ModelField] != pq.model {
				continue
			}
			if !pq.in(ts) || (pq.notGen != "" && r.Doc[GenField] == pq.notGen) {
				continue
			}
			delete(f.rows, id)
			n++
		}
		b, _ := json.Marshal(map[string]any{"deleted": n})
		return json.Unmarshal(b, out)
	case method == http.MethodPut:
		name := strings.TrimPrefix(clean, "/")
		if f.indices[name] {
			return &store.Error{Status: 400, Body: `{"error":{"type":"resource_already_exists_exception","reason":"exists"}}`}
		}
		f.indices[name] = true
		if f.putBodies == nil {
			f.putBodies = map[string]map[string]any{}
		}
		f.putBodies[name] = roundtrip(body)
		return nil
	case method == http.MethodDelete:
		name := strings.TrimPrefix(clean, "/")
		f.deleted = append(f.deleted, name)
		delete(f.indices, name)
		for id, r := range f.rows {
			if r.Index == name {
				delete(f.rows, id)
			}
		}
		f.extra = slices.DeleteFunc(f.extra, func(s string) bool { return s == name })
		return nil
	}
	return fmt.Errorf("fake: unexpected %s %s", method, p)
}

func (f *fakeClient) ListIndices(ctx context.Context, pattern string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failing("list", pattern); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var names []string
	addName := func(n string) {
		if ok, _ := path.Match(pattern, n); ok && !seen[n] && !f.hidden[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, e := range f.events {
		addName(f.rawIndex(e))
	}
	for n := range f.indices {
		addName(n)
	}
	for _, n := range f.extra {
		addName(n)
	}
	slices.Sort(names)
	return names, nil
}

func (f *fakeClient) Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failing("get", id); err != nil {
		return nil, store.Version{}, false, err
	}
	d, ok := f.runtime[id]
	return d.raw, d.v, ok, nil
}

func (f *fakeClient) put(id string, body any) store.Version {
	raw, _ := json.Marshal(body)
	f.seq++
	v := store.Version{SeqNo: f.seq, PrimaryTerm: 1, Version: f.seq}
	f.runtime[id] = fakeDoc{raw: raw, v: v}
	return v
}

func (f *fakeClient) Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failing("create", id); err != nil {
		return store.Version{}, err
	}
	if _, ok := f.runtime[id]; ok {
		return store.Version{}, store.ErrExists
	}
	return f.put(id, body), nil
}

func (f *fakeClient) PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failing("putif", id); err != nil {
		return store.Version{}, err
	}
	d, ok := f.runtime[id]
	if !ok {
		return store.Version{}, store.ErrNotFound
	}
	if d.v != v {
		return store.Version{}, store.ErrConflict
	}
	return f.put(id, body), nil
}

func (f *fakeClient) SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failing("searchdocs", index); err != nil {
		return nil, err
	}
	var out []store.Doc
	for id, d := range f.runtime {
		out = append(out, store.Doc{Ref: store.Ref{Index: index, ID: id}, Version: d.v, Found: true, Source: d.raw})
	}
	return out, nil
}

// state returns the stored state of model.
func (f *fakeClient) state(model string) (State, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.runtime[stateID(model)]
	if !ok {
		return State{}, false
	}
	var s State
	_ = json.Unmarshal(d.raw, &s)
	return s, true
}

// rowCount sums the counts of model's rows.
func (f *fakeClient) rowCount(model string) (rows int, events int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.Doc[ModelField] == model {
			rows++
			n, _ := toFloat(r.Doc[CountField])
			events += int64(n)
		}
	}
	return rows, events
}
