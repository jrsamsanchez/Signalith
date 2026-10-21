// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// refusingBulk refuses the documents at the positions given, with the
// status and type given.
type refusingBulk struct {
	at     []int
	status int
	typ    string
}

func (b *refusingBulk) Bulk(_ context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	var errs []store.BulkItemError
	for _, p := range b.at {
		if p < len(docs) {
			errs = append(errs, store.BulkItemError{Index: docs[p].Index, Pos: p, Status: b.status, Type: b.typ, Reason: b.typ})
		}
	}
	return errs, nil
}

func TestTemporaryAtListsEveryEventRefusedForNow(t *testing.T) {
	at := make([]int, 0, 30)
	for i := range 30 {
		at = append(at, 2*i)
	}
	p := &Pipeline{Store: &refusingBulk{at: at, status: http.StatusTooManyRequests, typ: "es_rejected_execution_exception"}, Prefix: "sig"}
	events := make([]Event, 70)
	for i := range events {
		events[i] = Event{Time: time.Now().Add(-time.Hour), Model: "Other", Fields: map[string]any{"message": fmt.Sprint(i)}}
	}
	res, err := p.IngestEvents(context.Background(), events)
	if err != nil {
		t.Fatal(err)
	}
	if res.Temporary != 30 || !slices.Equal(res.TemporaryAt, at) || len(res.Errors) >= 30 {
		t.Errorf("temporary %d at %v, %d errors listed", res.Temporary, res.TemporaryAt, len(res.Errors))
	}

	p.Store = &refusingBulk{at: []int{1}, status: http.StatusBadRequest, typ: "mapper_parsing_exception"}
	res, err = p.IngestEvents(context.Background(), events[:3])
	if err != nil {
		t.Fatal(err)
	}
	if res.Rejected != 1 || res.Temporary != 0 || len(res.TemporaryAt) != 0 {
		t.Errorf("a refusal for good: %+v", res)
	}
}

func TestTemporaryError(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("dial tcp 127.0.0.1:9200: connection refused"), true},
		{context.DeadlineExceeded, true},
		{&store.Error{Status: http.StatusTooManyRequests}, true},
		{&store.Error{Status: http.StatusServiceUnavailable}, true},
		{&store.Error{Status: http.StatusForbidden, Body: `{"error":{"type":"cluster_block_exception","reason":"blocked"}}`}, true},
		{fmt.Errorf("bulk: %w", &store.Error{Status: http.StatusBadGateway}), true},
		{&store.Error{Status: http.StatusBadRequest, Body: "bad request"}, false},
		{&store.Error{Status: http.StatusUnauthorized}, false},
	} {
		if got := TemporaryError(c.err); got != c.want {
			t.Errorf("TemporaryError(%v) = %v", c.err, got)
		}
	}
}
