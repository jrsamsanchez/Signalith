package ticketing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// linkDocs is a MemoryDocs that answers every search with all its
// documents (the test checks the query), records Do calls, and fails
// when err is set.
type linkDocs struct {
	*endpoint.MemoryDocs
	mu      sync.Mutex
	ids     []string
	calls   []string
	queries []map[string]any
	doErr   error
	err     error
}

func newLinkDocs() *linkDocs { return &linkDocs{MemoryDocs: endpoint.NewMemoryDocs()} }

func (d *linkDocs) failing() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

func (d *linkDocs) Do(ctx context.Context, method, path string, body, out any) error {
	d.mu.Lock()
	d.calls = append(d.calls, method+" "+path)
	err := d.doErr
	d.mu.Unlock()
	if err != nil {
		return err
	}
	return d.MemoryDocs.Do(ctx, method, path, body, out)
}

func (d *linkDocs) Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	if err := d.failing(); err != nil {
		return nil, store.Version{}, false, err
	}
	return d.MemoryDocs.Get(ctx, index, id)
}

func (d *linkDocs) Create(ctx context.Context, index, id string, body any, r bool) (store.Version, error) {
	v, err := d.MemoryDocs.Create(ctx, index, id, body, r)
	if err == nil {
		d.mu.Lock()
		d.ids = append(d.ids, id)
		d.mu.Unlock()
	}
	return v, err
}

func (d *linkDocs) SearchDocs(ctx context.Context, index string, q map[string]any) ([]store.Doc, error) {
	if err := d.failing(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.queries = append(d.queries, q)
	ids := append([]string(nil), d.ids...)
	d.mu.Unlock()
	var out []store.Doc
	for _, id := range ids {
		src, v, found, err := d.MemoryDocs.Get(ctx, index, id)
		if err != nil || !found {
			continue
		}
		out = append(out, store.Doc{Ref: store.Ref{Index: index, ID: id}, Version: v, Found: true, Source: src})
	}
	return out, nil
}

func TestOpenSearchLinks(t *testing.T) {
	ctx := context.Background()
	d := newLinkDocs()
	o := NewOpenSearch(d, "sig")
	if o.Index != "sig_ticket_sync" {
		t.Fatalf("index %q", o.Index)
	}
	if err := o.EnsureIndex(ctx); err != nil || d.calls[0] != "PUT /sig_ticket_sync" {
		t.Fatalf("ensure = %v %v", err, d.calls)
	}
	d.doErr = &store.Error{Status: 400, Body: "resource_already_exists_exception"}
	if err := o.EnsureIndex(ctx); err != nil {
		t.Errorf("existing = %v", err)
	}
	d.doErr = &store.Error{Status: 500, Body: "x"}
	if err := o.EnsureIndex(ctx); err == nil {
		t.Error("ensure error not returned")
	}
	if err := o.Replicate(ctx); err == nil {
		t.Error("replicate error not returned")
	}
	d.doErr = nil

	now := time.Now().Add(-time.Hour)
	older := &Link{ID: LinkID("jira", "c2"), CaseID: "c2", Connection: "jira", State: StatePending, Created: now.Add(-time.Minute)}
	newer := &Link{ID: LinkID("jira", "c1"), CaseID: "c1", Connection: "jira", State: StateLinked, Active: true, Created: now,
		Notes: []string{"n1"}}
	v1, err := o.Create(ctx, newer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Create(ctx, older); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Create(ctx, newer); !errors.Is(err, store.ErrExists) {
		t.Errorf("second create = %v", err)
	}
	got, err := o.Get(ctx, newer.ID)
	if err != nil || got.CaseID != "c1" || !got.Version.Same(v1) || len(got.Notes) != 1 {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, err := o.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	got.Key = "SOC-1"
	if _, err := o.Update(ctx, &got.Link, got.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Update(ctx, &got.Link, got.Version); !errors.Is(err, store.ErrConflict) {
		t.Errorf("stale update = %v", err)
	}

	// A broken document is skipped by searches and an error for Get.
	if _, err := d.Create(ctx, o.Index, "bad", json.RawMessage(`[]`), true); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Get(ctx, "bad"); err == nil {
		t.Error("broken link read")
	}
	due, err := o.Due(ctx)
	if err != nil || len(due) != 2 || due[0].CaseID != "c2" || due[1].Key != "SOC-1" {
		t.Fatalf("due = %+v %v", due, err)
	}
	q, _ := json.Marshal(d.queries[0])
	for _, want := range []string{`"state":"pending"`, `"active":true`, `"auto":true`, `"minimum_should_match":1`} {
		if !strings.Contains(string(q), want) {
			t.Errorf("due query lacks %s: %s", want, q)
		}
	}

	// Cases are asked for 500 at a time.
	ids := make([]string, 1001)
	for i := range ids {
		ids[i] = "c1"
	}
	d.queries = nil
	list, err := o.ForCases(ctx, ids)
	if err != nil || len(d.queries) != 3 || len(list) != 6 {
		t.Errorf("for cases = %d links, %d queries, %v", len(list), len(d.queries), err)
	}

	boom := errors.New("opensearch down")
	d.err = boom
	if _, err := o.Get(ctx, newer.ID); !errors.Is(err, boom) {
		t.Errorf("get = %v", err)
	}
	if _, err := o.Due(ctx); !errors.Is(err, boom) {
		t.Errorf("due = %v", err)
	}
	if _, err := o.ForCases(ctx, []string{"c1"}); !errors.Is(err, boom) {
		t.Errorf("for cases = %v", err)
	}
}
