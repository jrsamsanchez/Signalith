// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package casetemplates

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cases"
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

func TestOpenSearchRoundTrip(t *testing.T) {
	ctx := context.Background()
	d := newFakeDocs()
	o := &OpenSearch{Docs: d, Prefix: "sig"}
	if o.index() != "sig_runtime" {
		t.Errorf("index %q", o.index())
	}
	if ts, err := o.Get(ctx); err != nil || len(ts) != 0 {
		t.Fatalf("empty: %+v %v", ts, err)
	}
	one := []Template{{ID: "ot", Name: "OT", Tasks: []string{"Call the plant"}}}
	if err := o.Put(ctx, one); err != nil {
		t.Fatal(err)
	}
	two := append(one, Template{ID: "fraud", Name: "Fraud", Severity: "low"})
	if err := o.Put(ctx, two); err != nil {
		t.Fatal(err)
	}
	got, err := o.Get(ctx)
	if err != nil || len(got) != 2 || got[0].Tasks[0] != "Call the plant" || got[1].Severity != "low" {
		t.Fatalf("got %+v %v", got, err)
	}
	if d.does != 1 {
		t.Errorf("the runtime index was made %d times, want once", d.does)
	}
	raw, _, _, _ := d.MemoryDocs.Get(ctx, "", docID)
	var stored doc
	if err := json.Unmarshal(raw, &stored); err != nil || stored.Kind != kind || stored.At.IsZero() {
		t.Errorf("stored %s", raw)
	}
}

func TestOpenSearchErrors(t *testing.T) {
	ctx := context.Background()
	down := errors.New("down")
	ts := []Template{{ID: "ot", Name: "OT"}}

	d := newFakeDocs()
	d.getErr = down
	o := &OpenSearch{Docs: d, Prefix: "p"}
	if _, err := o.Get(ctx); !errors.Is(err, down) {
		t.Errorf("Get: %v", err)
	}
	if err := o.Put(ctx, ts); !errors.Is(err, down) {
		t.Errorf("Put: %v", err)
	}

	d = newFakeDocs()
	d.raw = json.RawMessage("{")
	if _, err := (&OpenSearch{Docs: d, Prefix: "p"}).Get(ctx); err == nil {
		t.Error("Get of a broken document")
	}

	d = newFakeDocs()
	d.doErr = down
	if err := (&OpenSearch{Docs: d, Prefix: "p"}).Put(ctx, ts); !errors.Is(err, down) {
		t.Errorf("Put without the runtime index: %v", err)
	}

	// Losing a race twice still saves; losing it every time says so.
	for _, raceErr := range []error{store.ErrExists, store.ErrConflict} {
		d = newFakeDocs()
		d.races, d.raceErr = 2, raceErr
		o = &OpenSearch{Docs: d, Prefix: "p"}
		if err := o.Put(ctx, ts); err != nil {
			t.Errorf("after two lost races (%v): %v", raceErr, err)
		}
		if got, _ := o.Get(ctx); len(got) != 1 {
			t.Errorf("saved %+v", got)
		}
		d.races = 3
		if err := o.Put(ctx, ts); !errors.Is(err, raceErr) {
			t.Errorf("after three lost races: %v", err)
		}
	}
}

func TestMemoryCopies(t *testing.T) {
	ctx := context.Background()
	m := &Memory{}
	ts := []Template{{ID: "ot", Name: "OT", Tasks: []string{"a"}}}
	if err := m.Put(ctx, ts); err != nil {
		t.Fatal(err)
	}
	ts[0].Tasks[0] = "changed"
	got, _ := m.Get(ctx)
	if got[0].Tasks[0] != "a" {
		t.Error("Memory keeps the caller's slice")
	}
	got[0].Tasks[0] = "changed"
	if again, _ := m.Get(ctx); again[0].Tasks[0] != "a" {
		t.Error("Memory hands out its own slice")
	}
}

func TestValidateRejects(t *testing.T) {
	many := make([]Template, MaxTemplates+1)
	tooManyTasks := make([]string, cases.MaxTasks+1)
	for i := range tooManyTasks {
		tooManyTasks[i] = "task"
	}
	tests := []struct {
		name string
		ts   []Template
		want string
	}{
		{"too many", many, "at most"},
		{"bad id", []Template{{ID: "Bad ID", Name: "x"}}, "lower-case"},
		{"builtin id", []Template{{ID: "phishing", Name: "x"}}, "already a template"},
		{"no name", []Template{{ID: "x", Name: "  "}}, "needs a name"},
		{"long name", []Template{{ID: "x", Name: strings.Repeat("n", MaxName+1)}}, "needs a name"},
		{"control in name", []Template{{ID: "x", Name: "a\x07b"}}, "needs a name"},
		{"long description", []Template{{ID: "x", Name: "x", Description: strings.Repeat("d", MaxDescription+1)}}, "description"},
		{"bad severity", []Template{{ID: "x", Name: "x", Severity: "urgent"}}, "severity"},
		{"too many tasks", []Template{{ID: "x", Name: "x", Tasks: tooManyTasks}}, "tasks"},
		{"empty task", []Template{{ID: "x", Name: "x", Tasks: []string{"  "}}}, `template "x"`},
	}
	for _, tc := range tests {
		if _, err := Validate(tc.ts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	for _, sev := range cases.Severities {
		if _, err := Validate([]Template{{ID: "x", Name: "x", Severity: sev}}); err != nil {
			t.Errorf("severity %s: %v", sev, err)
		}
	}
	if _, ok := Find(nil, "missing"); ok {
		t.Error("Find found a template that is not there")
	}
}
