// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package exceptionreqs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeDocs is a runtime index that can fail or lose races.
type fakeDocs struct {
	*endpoint.MemoryDocs
	getErr  error
	doErr   error
	races   int // writes that lose to another server first
	raceErr error
	raw     json.RawMessage
	does    int
}

func newFakeDocs() *fakeDocs { return &fakeDocs{MemoryDocs: endpoint.NewMemoryDocs()} }

func (f *fakeDocs) Do(ctx context.Context, method, path string, body, out any) error {
	f.does++
	if f.doErr != nil {
		return f.doErr
	}
	return f.MemoryDocs.Do(ctx, method, path, body, out)
}

func (f *fakeDocs) Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	if f.getErr != nil {
		return nil, store.Version{}, false, f.getErr
	}
	if f.raw != nil {
		return f.raw, store.Version{SeqNo: 1, PrimaryTerm: 1}, true, nil
	}
	return f.MemoryDocs.Get(ctx, index, id)
}

func (f *fakeDocs) race() error {
	if f.races > 0 {
		f.races--
		return f.raceErr
	}
	return nil
}

func (f *fakeDocs) Create(ctx context.Context, index, id string, body any, r bool) (store.Version, error) {
	if err := f.race(); err != nil {
		return store.Version{}, err
	}
	return f.MemoryDocs.Create(ctx, index, id, body, r)
}

func (f *fakeDocs) PutIf(ctx context.Context, index, id string, body any, v store.Version, r bool) (store.Version, error) {
	if err := f.race(); err != nil {
		return store.Version{}, err
	}
	return f.MemoryDocs.PutIf(ctx, index, id, body, v, r)
}

func TestOpenSearchModifyAndList(t *testing.T) {
	ctx := context.Background()
	d := newFakeDocs()
	o := &OpenSearch{Docs: d, Prefix: "sig"}
	if o.index() != "sig_runtime" {
		t.Errorf("index %q", o.index())
	}
	if rs, err := o.List(ctx); err != nil || len(rs) != 0 {
		t.Fatalf("empty: %+v %v", rs, err)
	}
	now := time.Now()
	a := req("ann", "d1", "web-01", now)
	a.For = "7D"
	if err := o.Modify(ctx, func(rs []Request) ([]Request, error) { return Add(rs, a) }); err != nil {
		t.Fatal(err)
	}
	old := req("bob", "d2", "db-01", now.Add(-ExpireAfter-time.Hour))
	if err := o.Modify(ctx, func(rs []Request) ([]Request, error) { return append(rs, old), nil }); err != nil {
		t.Fatal(err)
	}
	rs, err := o.List(ctx)
	if err != nil || len(rs) != 2 || rs[0].ID != a.ID || rs[0].For != "7d" || rs[1].Status != Expired {
		t.Fatalf("list %+v %v", rs, err)
	}
	if d.does != 1 {
		t.Errorf("the runtime index was made %d times, want once", d.does)
	}
	raw, _, _, _ := d.MemoryDocs.Get(ctx, "", docID)
	var stored doc
	if err := json.Unmarshal(raw, &stored); err != nil || stored.Kind != kind || len(stored.Body.Requests) != 2 {
		t.Errorf("stored %s", raw)
	}
	// An error from fn leaves the requests as they were.
	refused := errors.New("refused")
	if err := o.Modify(ctx, func([]Request) ([]Request, error) { return nil, refused }); !errors.Is(err, refused) {
		t.Errorf("Modify: %v", err)
	}
	if rs, _ := o.List(ctx); len(rs) != 2 {
		t.Errorf("after a refused change: %+v", rs)
	}
}

func TestOpenSearchErrors(t *testing.T) {
	ctx := context.Background()
	down := errors.New("down")
	add := func(rs []Request) ([]Request, error) { return Add(rs, req("ann", "d", "h", time.Now())) }

	d := newFakeDocs()
	d.getErr = down
	o := &OpenSearch{Docs: d, Prefix: "p"}
	if _, err := o.List(ctx); !errors.Is(err, down) {
		t.Errorf("List: %v", err)
	}
	if err := o.Modify(ctx, add); !errors.Is(err, down) {
		t.Errorf("Modify: %v", err)
	}

	d = newFakeDocs()
	d.raw = json.RawMessage("[")
	if _, err := (&OpenSearch{Docs: d, Prefix: "p"}).List(ctx); err == nil {
		t.Error("List of a broken document")
	}

	d = newFakeDocs()
	d.doErr = down
	if err := (&OpenSearch{Docs: d, Prefix: "p"}).Modify(ctx, add); !errors.Is(err, down) {
		t.Errorf("Modify without the runtime index: %v", err)
	}

	for _, raceErr := range []error{store.ErrExists, store.ErrConflict} {
		d = newFakeDocs()
		d.races, d.raceErr = 4, raceErr
		o = &OpenSearch{Docs: d, Prefix: "p"}
		calls := 0
		if err := o.Modify(ctx, func(rs []Request) ([]Request, error) { calls++; return add(rs) }); err != nil {
			t.Errorf("after four lost races (%v): %v", raceErr, err)
		}
		if calls != 5 {
			t.Errorf("fn ran %d times, want 5", calls)
		}
		d.races = 5
		other := func(rs []Request) ([]Request, error) { return Add(rs, req("bob", "d", "other", time.Now())) }
		if err := o.Modify(ctx, other); !errors.Is(err, raceErr) {
			t.Errorf("after five lost races: %v", err)
		}
	}
}

func TestMemoryDefaultClock(t *testing.T) {
	ctx := context.Background()
	m := &Memory{}
	old := req("ann", "d", "h", time.Now().Add(-ExpireAfter-time.Minute))
	if err := m.Modify(ctx, func(rs []Request) ([]Request, error) { return append(rs, old), nil }); err != nil {
		t.Fatal(err)
	}
	rs, _ := m.List(ctx)
	if len(rs) != 1 || rs[0].Status != Expired {
		t.Errorf("list %+v", rs)
	}
	refused := errors.New("refused")
	if err := m.Modify(ctx, func([]Request) ([]Request, error) { return nil, refused }); !errors.Is(err, refused) {
		t.Errorf("Modify: %v", err)
	}
	if rs, _ := m.List(ctx); len(rs) != 1 {
		t.Error("a refused change was kept")
	}
	if r := req("a", "d", "h", time.Now()); !r.Expires().Equal(r.Created.Add(ExpireAfter)) {
		t.Error("Expires")
	}
}

func TestAddRejects(t *testing.T) {
	now := time.Now()
	bad := req("ann", "d", "h", now)
	bad.For = "forever"
	if _, err := Add(nil, bad); err == nil || !strings.Contains(err.Error(), "for must be") {
		t.Errorf("bad for: %v", err)
	}
	// Requests that together pass MaxDocBytes, each under MaxRequestBytes.
	var rs []Request
	big := strings.Repeat("a", MaxRequestBytes-1024)
	for i := 0; i*(MaxRequestBytes-1024) <= MaxDocBytes; i++ {
		r := req(fmt.Sprint("u", i), "d", fmt.Sprint("h", i), now)
		r.Status = Declined
		r.Comment = big
		rs = append(rs, r)
	}
	r := req("ann", "d", "new", now)
	if _, err := Add(rs, r); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("too large: %v", err)
	}
}
