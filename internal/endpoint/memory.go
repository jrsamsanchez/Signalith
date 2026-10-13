package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// MemoryDocs keeps documents in memory with OpenSearch's versioning rules,
// and answers the term, range and bool filter queries Store sends. Tests
// use it in place of OpenSearch.
type MemoryDocs struct {
	mu   sync.Mutex
	seq  int64
	docs map[string]memDoc
}

type memDoc struct {
	src json.RawMessage
	v   store.Version
}

// NewMemoryDocs returns an empty MemoryDocs.
func NewMemoryDocs() *MemoryDocs { return &MemoryDocs{docs: map[string]memDoc{}} }

func (f *MemoryDocs) next() store.Version {
	f.seq++
	return store.Version{SeqNo: f.seq, PrimaryTerm: 1, Version: f.seq}
}

func (f *MemoryDocs) Do(context.Context, string, string, any, any) error { return nil }

func (f *MemoryDocs) Get(_ context.Context, _, id string) (json.RawMessage, store.Version, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.docs[id]
	return d.src, d.v, ok, nil
}

func (f *MemoryDocs) Create(_ context.Context, _, id string, body any, _ bool) (store.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.docs[id]; ok {
		return store.Version{}, store.ErrExists
	}
	b, err := json.Marshal(body)
	if err != nil {
		return store.Version{}, err
	}
	v := f.next()
	f.docs[id] = memDoc{b, v}
	return v, nil
}

func (f *MemoryDocs) PutIf(_ context.Context, _, id string, body any, v store.Version, _ bool) (store.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.docs[id]
	if !ok || !d.v.Same(v) {
		return store.Version{}, store.ErrConflict
	}
	b, err := json.Marshal(body)
	if err != nil {
		return store.Version{}, err
	}
	nv := f.next()
	f.docs[id] = memDoc{b, nv}
	return nv, nil
}

func (f *MemoryDocs) Update(_ context.Context, _, id string, fields map[string]any, _ bool) (store.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.docs[id]
	if !ok {
		return store.Version{}, store.ErrNotFound
	}
	m := map[string]any{}
	_ = json.Unmarshal(d.src, &m)
	for k, v := range fields {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	nv := f.next()
	f.docs[id] = memDoc{b, nv}
	return nv, nil
}

func (f *MemoryDocs) DeleteIf(_ context.Context, _, id string, v store.Version, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.docs[id]
	if !ok {
		return store.ErrNotFound
	}
	if !d.v.Same(v) {
		return store.ErrConflict
	}
	delete(f.docs, id)
	return nil
}

func (f *MemoryDocs) SearchDocs(_ context.Context, index string, q map[string]any) ([]store.Doc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.Doc
	for id, d := range f.docs {
		m := map[string]any{}
		_ = json.Unmarshal(d.src, &m)
		if matches(q, m) {
			out = append(out, store.Doc{Ref: store.Ref{Index: index, ID: id}, Version: d.v, Found: true, Source: d.src})
		}
	}
	return out, nil
}

func matches(q, doc map[string]any) bool {
	for op, arg := range q {
		a := arg.(map[string]any)
		switch op {
		case "term":
			for k, v := range a {
				if fmt.Sprint(doc[k]) != fmt.Sprint(v) {
					return false
				}
			}
		case "range":
			for k, r := range a {
				for cmp, v := range r.(map[string]any) {
					got, _ := doc[k].(string)
					if cmp != "gt" || !(got > v.(string)) {
						return false
					}
				}
			}
		case "bool":
			for _, sub := range a["filter"].([]any) {
				if !matches(sub.(map[string]any), doc) {
					return false
				}
			}
		default:
			return false // a query Store does not send
		}
	}
	return true
}
