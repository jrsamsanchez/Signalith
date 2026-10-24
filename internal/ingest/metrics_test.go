// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

func eventsOf(s MetricsSnapshot, intake string) IntakeCount {
	for _, e := range s.Events {
		if e.Intake == intake {
			return e
		}
	}
	return IntakeCount{}
}

// The metrics count events by intake and outcome, and why OpenSearch
// turned each away, with labels from fixed lists only.
func TestMetricsCountWrites(t *testing.T) {
	b := &countingBulk{}
	b.reject = func(d store.IndexedDoc) *store.BulkItemError {
		switch d.Doc["user"] {
		case "busy":
			return &store.BulkItemError{Index: d.Index, Type: "es_rejected_execution_exception", Status: http.StatusTooManyRequests, Reason: "queue full"}
		case "blocked":
			return &store.BulkItemError{Index: d.Index, Type: "cluster_block_exception", Status: http.StatusTooManyRequests, Reason: "index [x] blocked by: [TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark, index has read-only-allow-delete block]"}
		case "shards":
			return &store.BulkItemError{Index: d.Index, Type: "validation_exception", Status: 400,
				Reason: "Validation Failed: 1: this action would add [1] total shards, but this cluster currently has [1000]/[1000] maximum normal shards open;"}
		}
		return nil
	}
	before := Metrics()
	p := &Pipeline{Store: b, Prefix: "sig"}
	ctx := WithOrigin(context.Background(), Origin{Intake: IntakeHEC, TokenName: "a token name"})
	if _, err := p.Ingest(ctx, "app", []map[string]any{{"user": "ok"}, {"user": "busy"}, {"user": "blocked"}, {"user": "shards"}, {"user": "ok2"}}); err != nil {
		t.Fatal(err)
	}
	after := Metrics()
	got, was := eventsOf(after, IntakeHEC), eventsOf(before, IntakeHEC)
	if got.Indexed-was.Indexed != 2 || got.Rejected-was.Rejected != 3 || got.Failed != was.Failed {
		t.Errorf("hec events: before %+v, after %+v", was, got)
	}
	for reason, want := range map[string]int64{RejectTooMany: 1, RejectReadOnly: 1, RejectShards: 1, RejectMapping: 0} {
		if d := after.Rejections[reason] - before.Rejections[reason]; d != want {
			t.Errorf("%s: %d, want %d", reason, d, want)
		}
	}
	if after.BulkSeconds.Count <= before.BulkSeconds.Count {
		t.Error("the write was not timed")
	}
	// A write that fails as a whole counts every event as failed, with
	// why.
	failing := &Pipeline{Store: failBulk{}, Prefix: "sig"}
	ctx = WithOrigin(context.Background(), Origin{Intake: "made-up"})
	if _, err := failing.Ingest(ctx, "app", []map[string]any{{"user": "x"}, {"user": "y"}}); err == nil {
		t.Fatal("no error")
	}
	last := Metrics()
	if d := eventsOf(last, "other").Failed - eventsOf(after, "other").Failed; d != 2 {
		t.Errorf("failed: %d", d)
	}
	if d := last.WriteFailures["unreachable"] - after.WriteFailures["unreachable"]; d != 1 {
		t.Errorf("unreachable: %d", d)
	}
	for _, e := range last.Events {
		if indexOf(MetricIntakes, e.Intake) == len(MetricIntakes)-1 && e.Intake != "other" {
			t.Errorf("intake label %q is not in the fixed list", e.Intake)
		}
	}
}

type failBulk struct{}

func (failBulk) Bulk(context.Context, []store.IndexedDoc) ([]store.BulkItemError, error) {
	return nil, errors.New("dial tcp: connection refused")
}

func TestMetricsSlotWait(t *testing.T) {
	p := &Pipeline{MaxConcurrent: 1}
	before := Metrics()
	release, err := p.Admit(context.Background(), time.Second, "a")
	if err != nil {
		t.Fatal(err)
	}
	if c, held, waiting := p.SlotUse(); c != 1 || held != 1 || waiting != 0 {
		t.Errorf("slots %d %d %d", c, held, waiting)
	}
	if _, err := p.Admit(context.Background(), 10*time.Millisecond, "b"); !errors.Is(err, ErrBusy) {
		t.Errorf("second: %v", err)
	}
	release()
	after := Metrics()
	if after.SlotTimeouts-before.SlotTimeouts != 1 || after.SlotWait.Count-before.SlotWait.Count != 1 {
		t.Errorf("timeouts %d, waits %d", after.SlotTimeouts-before.SlotTimeouts, after.SlotWait.Count-before.SlotWait.Count)
	}
}
