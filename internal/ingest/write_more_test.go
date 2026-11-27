// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// scriptedBulk answers each Bulk call with the next of its answers.
type scriptedBulk struct {
	calls   int
	answers []func(docs []store.IndexedDoc) ([]store.BulkItemError, error)
}

func (s *scriptedBulk) Bulk(_ context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	i := s.calls
	s.calls++
	if i >= len(s.answers) {
		return nil, nil
	}
	return s.answers[i](docs)
}

// An event retried with only its known fields counts as refused for now
// when the retry itself fails.
func TestRetryThatFails(t *testing.T) {
	b := &scriptedBulk{answers: []func([]store.IndexedDoc) ([]store.BulkItemError, error){
		func(docs []store.IndexedDoc) ([]store.BulkItemError, error) {
			return []store.BulkItemError{{Index: docs[1].Index, Pos: 1, Type: "mapper_parsing_exception", Reason: "x"}}, nil
		},
		func([]store.IndexedDoc) ([]store.BulkItemError, error) { return nil, errors.New("connection reset") },
	}}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
	res, err := p.IngestEvents(context.Background(), []Event{
		{Time: now, Model: "Network", Fields: map[string]any{"src_ip": "10.0.0.1"}},
		{Time: now, Model: "Network", Fields: map[string]any{"src_ip": "10.0.0.2", "a_field_nobody_knows": "v"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.calls != 2 || res.Indexed != 1 || res.Rejected != 1 || res.FieldsDropped < 1 {
		t.Errorf("calls %d, result %+v", b.calls, res)
	}
	if res.Temporary != 1 || len(res.TemporaryAt) != 1 || res.TemporaryAt[0] != 1 {
		t.Errorf("refused for now = %d at %v (errors %+v)", res.Temporary, res.TemporaryAt, res.Errors)
	}
}

// A write that fails as a whole fails IngestEvents; an event without a
// model or fields goes to Other.
func TestIngestEventsWriteFails(t *testing.T) {
	b := &scriptedBulk{answers: []func([]store.IndexedDoc) ([]store.BulkItemError, error){
		func([]store.IndexedDoc) ([]store.BulkItemError, error) {
			return nil, &store.Error{Status: http.StatusServiceUnavailable, Body: "busy"}
		},
	}}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
	if _, err := p.IngestEvents(context.Background(), []Event{{Time: now}}); err == nil {
		t.Error("no error from a failed write")
	}
	if s := p.Stats(); s.Failed != 1 {
		t.Errorf("stats = %+v", s)
	}
	fb := &fakeBulk{}
	p = &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	if res, err := p.IngestEvents(context.Background(), []Event{{Time: now}}); err != nil || res.Indexed != 1 {
		t.Fatalf("IngestEvents = %+v %v", res, err)
	}
	if fb.docs[0].Index != "sig-other-"+dayOf(now) {
		t.Errorf("index = %q", fb.docs[0].Index)
	}
}

func TestSetMaxEventAge(t *testing.T) {
	p := &Pipeline{}
	if p.maxAge() != DefaultMaxEventAge {
		t.Errorf("default = %v", p.maxAge())
	}
	p.MaxEventAge = time.Hour
	if p.maxAge() != time.Hour {
		t.Errorf("configured = %v", p.maxAge())
	}
	p.SetMaxEventAge(0)
	if p.maxAge() != time.Hour {
		t.Errorf("zero changed it: %v", p.maxAge())
	}
	p.SetMaxEventAge(48 * time.Hour)
	if p.maxAge() != 48*time.Hour {
		t.Errorf("live = %v", p.maxAge())
	}
	recv := time.Now()
	if !TimeUsable(recv.Add(-6*24*time.Hour), recv, 0) || TimeUsable(recv.Add(-8*24*time.Hour), recv, 0) {
		t.Error("TimeUsable with the default age")
	}
}

// A batch that fails to write in the middle of a body stops the body
// there; the events not written count as failed.
func TestIngestBodyBatchFails(t *testing.T) {
	b := &scriptedBulk{answers: []func([]store.IndexedDoc) ([]store.BulkItemError, error){
		func([]store.IndexedDoc) ([]store.BulkItemError, error) { return nil, errors.New("connection reset") },
	}}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
	n := batchEvents + 5
	body := "[" + strings.TrimSuffix(strings.Repeat(`{"log":"hello"},`, n), ",") + "]"
	if _, err := p.IngestBody(context.Background(), "app", []byte(body)); err == nil {
		t.Fatal("no error from a failed batch")
	}
	if b.calls != 1 {
		t.Errorf("%d writes after a failed one", b.calls-1)
	}
	if s := p.Stats(); int(s.Received) != n || int(s.Failed) != n {
		t.Errorf("stats = %+v", s)
	}
}
