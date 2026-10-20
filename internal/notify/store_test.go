// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// osDocs is a small OpenSearch: documents by ID, every request recorded,
// and canned answers to searches sent with Do.
type osDocs struct {
	mu      sync.Mutex
	docs    map[string]json.RawMessage
	vers    map[string]store.Version
	seq     int64
	calls   []string
	bodies  []any
	batches []int
	queries []map[string]any
	answer  string // the JSON Do decodes into out
	doErr   error
	err     error // for every other call
}

func newOSDocs() *osDocs {
	return &osDocs{docs: map[string]json.RawMessage{}, vers: map[string]store.Version{}}
}

func (d *osDocs) Do(_ context.Context, method, path string, body, out any) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, method+" "+path)
	d.bodies = append(d.bodies, body)
	if d.doErr != nil {
		return d.doErr
	}
	if out != nil && d.answer != "" {
		return json.Unmarshal([]byte(d.answer), out)
	}
	return nil
}

func (d *osDocs) put(id string, body any) store.Version {
	b, _ := json.Marshal(body)
	d.seq++
	v := store.Version{SeqNo: d.seq, PrimaryTerm: 1, Version: d.seq}
	d.docs[id], d.vers[id] = b, v
	return v
}

func (d *osDocs) Create(_ context.Context, _, id string, body any, _ bool) (store.Version, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return store.Version{}, d.err
	}
	if _, ok := d.docs[id]; ok {
		return store.Version{}, store.ErrExists
	}
	return d.put(id, body), nil
}

func (d *osDocs) PutIf(_ context.Context, _, id string, body any, v store.Version, _ bool) (store.Version, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return store.Version{}, d.err
	}
	if cur, ok := d.vers[id]; !ok || !cur.Same(v) {
		return store.Version{}, store.ErrConflict
	}
	return d.put(id, body), nil
}

func (d *osDocs) MGetVersions(_ context.Context, refs []store.Ref) (map[store.Ref]store.Version, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.batches = append(d.batches, len(refs))
	if d.err != nil {
		return nil, d.err
	}
	out := map[store.Ref]store.Version{}
	for _, r := range refs {
		if v, ok := d.vers[r.ID]; ok {
			out[r] = v
		}
	}
	return out, nil
}

// SearchDocs returns every document: the query is checked by the test.
func (d *osDocs) SearchDocs(_ context.Context, index string, q map[string]any) ([]store.Doc, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queries = append(d.queries, q)
	if d.err != nil {
		return nil, d.err
	}
	var out []store.Doc
	for id, src := range d.docs {
		out = append(out, store.Doc{Ref: store.Ref{Index: index, ID: id}, Version: d.vers[id], Found: true, Source: src})
	}
	return out, nil
}

func TestOpenSearchDeliveries(t *testing.T) {
	ctx := context.Background()
	d := newOSDocs()
	o := NewOpenSearch(d, "sig")
	if o.Index != "sig_notifications" {
		t.Fatalf("index = %q", o.Index)
	}
	if err := o.EnsureIndex(ctx); err != nil || d.calls[0] != "PUT /sig_notifications" {
		t.Fatalf("ensure = %v %v", err, d.calls)
	}
	m := d.bodies[0].(map[string]any)["mappings"].(map[string]any)
	if m["dynamic"] != "false" || m["properties"].(map[string]any)["message"].(map[string]any)["enabled"] != false {
		t.Errorf("mappings = %v", m)
	}
	d.doErr = &store.Error{Status: 400, Body: "resource_already_exists_exception"}
	if err := o.EnsureIndex(ctx); err != nil {
		t.Errorf("existing index = %v", err)
	}
	d.doErr = &store.Error{Status: 500, Body: "boom"}
	if err := o.EnsureIndex(ctx); err == nil {
		t.Error("a failure was not returned")
	}
	if err := o.Replicate(ctx); err == nil {
		t.Error("replicate failure was not returned")
	}
	d.doErr = nil

	now := time.Now().Add(-time.Hour).UTC()
	past := now.Add(-time.Minute)
	failed := &Delivery{ID: "a", Kind: "finding", Channel: "c1", Status: StatusFailed, NextTry: &past, Created: now, Updated: now}
	sending := &Delivery{ID: "b", Kind: "finding", Channel: "c1", Status: StatusSending, Claimed: past, Created: now, Updated: now}
	v, err := o.Claim(ctx, failed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Claim(ctx, failed); !errors.Is(err, store.ErrExists) {
		t.Errorf("second claim = %v", err)
	}
	if _, err := o.Claim(ctx, sending); err != nil {
		t.Fatal(err)
	}
	failed.Attempts = 2
	if _, err := o.Update(ctx, failed, v); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Update(ctx, failed, v); !errors.Is(err, store.ErrConflict) {
		t.Errorf("stale update = %v", err)
	}
	d.mu.Lock()
	d.docs["bad"], d.vers["bad"] = json.RawMessage(`[]`), store.Version{SeqNo: 99, PrimaryTerm: 1}
	d.mu.Unlock()

	retry, stuck, err := o.Due(ctx, now, now)
	if err != nil || len(retry) != 1 || retry[0].ID != "a" || retry[0].Attempts != 2 || len(stuck) != 1 || stuck[0].ID != "b" {
		t.Fatalf("due = %+v %+v %v", retry, stuck, err)
	}
	q, _ := json.Marshal(d.queries[0])
	for _, want := range []string{`"status":"failed"`, `"status":"sending"`, `"final":true`, `"minimum_should_match":1`, now.Format(time.RFC3339Nano)} {
		if !strings.Contains(string(q), want) {
			t.Errorf("due query lacks %s: %s", want, q)
		}
	}

	// Existing asks in batches of 500.
	ids := make([]string, 1001)
	for i := range ids {
		ids[i] = "x"
	}
	ids[0], ids[1000] = "a", "b"
	got, err := o.Existing(ctx, ids)
	if err != nil || len(got) != 2 || !got["a"] || !got["b"] {
		t.Errorf("existing = %v %v", got, err)
	}
	if len(d.batches) != 3 || d.batches[0] != 500 || d.batches[2] != 1 {
		t.Errorf("batches = %v", d.batches)
	}

	d.answer = `{"hits":{"hits":[{"_source":{"id":"b","status":"sending"}},{"_source":{"id":"a","status":"failed"}}]}}`
	list, err := o.Recent(ctx, 5)
	if err != nil || len(list) != 2 || list[0].ID != "b" {
		t.Errorf("recent = %+v %v", list, err)
	}
	n := len(d.calls)
	if !strings.Contains(d.calls[n-1], "/sig_notifications/_search?ignore_unavailable=true") {
		t.Errorf("recent call = %s", d.calls[n-1])
	}
	if err := o.Purge(ctx, now); err != nil {
		t.Fatal(err)
	}
	if call := d.calls[len(d.calls)-1]; !strings.HasPrefix(call, "POST /sig_notifications/_delete_by_query?conflicts=proceed") {
		t.Errorf("purge call = %s", call)
	}
	b, _ := json.Marshal(d.bodies[len(d.bodies)-1])
	if !strings.Contains(string(b), now.Format(time.RFC3339Nano)) {
		t.Errorf("purge body = %s", b)
	}

	// Failures are returned.
	boom := errors.New("opensearch down")
	d.err, d.doErr = boom, boom
	if _, err := o.Existing(ctx, []string{"a"}); !errors.Is(err, boom) {
		t.Errorf("existing = %v", err)
	}
	if _, _, err := o.Due(ctx, now, now); !errors.Is(err, boom) {
		t.Errorf("due = %v", err)
	}
	if _, err := o.Recent(ctx, 5); !errors.Is(err, boom) {
		t.Errorf("recent = %v", err)
	}
}

func TestMemoryDeliveries(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	now := time.Now().Add(-time.Hour)
	old := &Delivery{ID: "old", Status: StatusSent, Created: now.Add(-48 * time.Hour), Updated: now}
	newer := &Delivery{ID: "new", Status: StatusSent, Created: now, Updated: now}
	for _, d := range []*Delivery{old, newer} {
		if _, err := m.Claim(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Update(ctx, &Delivery{ID: "missing"}, store.Version{}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("update missing = %v", err)
	}
	// Equal times: the later write comes first.
	list, _ := m.Recent(ctx, 1)
	if len(list) != 1 || list[0].ID != "new" {
		t.Errorf("recent = %+v", list)
	}
	got, _ := m.Existing(ctx, []string{"old", "nope"})
	if !got["old"] || got["nope"] {
		t.Errorf("existing = %v", got)
	}
	if err := m.Purge(ctx, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get("old"); ok {
		t.Error("old delivery kept")
	}
	if _, ok := m.Get("new"); !ok {
		t.Error("new delivery purged")
	}
}
