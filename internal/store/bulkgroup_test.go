// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeBulk records each request's documents (by their "n" field) and
// refuses those whose n is in refuse, after waiting for gate.
type fakeBulk struct {
	mu       sync.Mutex
	requests [][]int
	refuse   map[int]bool
	gate     chan struct{}
	err      error
}

func (f *fakeBulk) send(ctx context.Context, body []byte) ([]BulkItemError, error) {
	if f.gate != nil {
		<-f.gate
	}
	var ns []int
	var errs []BulkItemError
	dec := json.NewDecoder(bytes.NewReader(body))
	for i := 0; ; i++ {
		var meta, doc map[string]any
		if dec.Decode(&meta) != nil || dec.Decode(&doc) != nil {
			break
		}
		n := int(doc["n"].(float64))
		ns = append(ns, n)
		if f.refuse[n] {
			errs = append(errs, BulkItemError{Index: "i", Reason: "refused", Pos: i, Status: 400})
		}
	}
	f.mu.Lock()
	f.requests = append(f.requests, ns)
	f.mu.Unlock()
	return errs, f.err
}

func docsFrom(first, n int) []IndexedDoc {
	docs := make([]IndexedDoc, n)
	for i := range docs {
		docs[i] = IndexedDoc{Index: "i", Doc: map[string]any{"n": first + i}}
	}
	return docs
}

func TestBulkGroupSendsAloneWhenQuiet(t *testing.T) {
	f := &fakeBulk{refuse: map[int]bool{2: true}}
	g := newBulkGroup(f.send, 2, 1<<20)
	errs, err := g.Bulk(context.Background(), docsFrom(0, 3))
	if err != nil || len(errs) != 1 || errs[0].Pos != 2 {
		t.Fatalf("errs %+v, err %v", errs, err)
	}
	if len(f.requests) != 1 || len(f.requests[0]) != 3 {
		t.Fatalf("requests %v", f.requests)
	}
}

// Callers arriving while the only slot is busy go together in the next
// request, and each gets its own errors counted in its own documents.
func TestBulkGroupJoinsWaitingCallers(t *testing.T) {
	f := &fakeBulk{refuse: map[int]bool{11: true, 21: true}, gate: make(chan struct{})}
	g := newBulkGroup(f.send, 1, 1<<20)
	first := make(chan error, 1)
	go func() {
		_, err := g.Bulk(context.Background(), docsFrom(0, 2))
		first <- err
	}()
	// Wait until the first request holds the slot.
	for len(g.slots) == 0 {
		time.Sleep(time.Millisecond)
	}
	type result struct {
		errs []BulkItemError
		err  error
	}
	results := make([]chan result, 3)
	for k := range results {
		results[k] = make(chan result, 1)
		go func() {
			errs, err := g.Bulk(context.Background(), docsFrom(10*(k+1), 3))
			results[k] <- result{errs, err}
		}()
	}
	for {
		g.mu.Lock()
		n := len(g.queue)
		g.mu.Unlock()
		if n == 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(f.gate)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	for k, ch := range results {
		r := <-ch
		if r.err != nil {
			t.Fatal(r.err)
		}
		want := 0
		if k < 2 {
			want = 1
		}
		if len(r.errs) != want || (want == 1 && r.errs[0].Pos != 1) {
			t.Errorf("caller %d: errs %+v", k, r.errs)
		}
	}
	if len(f.requests) != 2 || len(f.requests[1]) != 9 {
		t.Fatalf("want the 3 waiting callers in one request, got %v", f.requests)
	}
}

func TestBulkGroupKeepsRequestsUnderMaxBytes(t *testing.T) {
	f := &fakeBulk{gate: make(chan struct{})}
	one, _ := encodeBulk(docsFrom(0, 1))
	g := newBulkGroup(f.send, 1, 2*len(one))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); g.Bulk(context.Background(), docsFrom(0, 1)) }()
	for len(g.slots) == 0 {
		time.Sleep(time.Millisecond)
	}
	for k := 1; k <= 4; k++ {
		wg.Add(1)
		go func() { defer wg.Done(); g.Bulk(context.Background(), docsFrom(k, 1)) }()
	}
	for {
		g.mu.Lock()
		n := len(g.queue)
		g.mu.Unlock()
		if n == 4 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(f.gate)
	wg.Wait()
	total := 0
	for _, r := range f.requests {
		if len(r) > 2 {
			t.Errorf("request of %d documents over the size limit: %v", len(r), f.requests)
		}
		total += len(r)
	}
	if total != 5 || len(f.requests) != 3 {
		t.Fatalf("requests %v", f.requests)
	}
}

func TestBulkGroupFailsEveryCallerOnARequestError(t *testing.T) {
	f := &fakeBulk{err: errors.New("429")}
	g := newBulkGroup(f.send, 1, 1<<20)
	if _, err := g.Bulk(context.Background(), docsFrom(0, 1)); err == nil || err.Error() != "429" {
		t.Fatalf("err %v", err)
	}
}

// A caller whose context ends while it waits is not sent.
func TestBulkGroupDropsCancelledWaiters(t *testing.T) {
	f := &fakeBulk{gate: make(chan struct{})}
	g := newBulkGroup(f.send, 1, 1<<20)
	done := make(chan struct{})
	go func() { g.Bulk(context.Background(), docsFrom(0, 1)); close(done) }()
	for len(g.slots) == 0 {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan error, 1)
	go func() { _, err := g.Bulk(ctx, docsFrom(5, 1)); got <- err }()
	for {
		g.mu.Lock()
		n := len(g.queue)
		g.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-got; !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	close(f.gate)
	<-done
	if fmt.Sprint(f.requests) != "[[0]]" {
		t.Fatalf("requests %v", f.requests)
	}
}

func TestBulkGroupManyCallers(t *testing.T) {
	f := &fakeBulk{refuse: map[int]bool{}}
	for n := 0; n < 2000; n += 7 {
		f.refuse[n] = true
	}
	g := newBulkGroup(f.send, 3, 1<<20)
	var wg sync.WaitGroup
	for k := range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			docs := docsFrom(10*k, 10)
			errs, err := g.Bulk(context.Background(), docs)
			if err != nil {
				t.Error(err)
				return
			}
			want := 0
			for _, d := range docs {
				if f.refuse[d.Doc["n"].(int)] {
					want++
				}
			}
			if len(errs) != want {
				t.Errorf("caller %d: %d errors, want %d", k, len(errs), want)
			}
			for _, e := range errs {
				if !f.refuse[docs[e.Pos].Doc["n"].(int)] {
					t.Errorf("caller %d: error on document %d, which was not refused", k, e.Pos)
				}
			}
		}()
	}
	wg.Wait()
	total := 0
	for _, r := range f.requests {
		total += len(r)
	}
	if total != 2000 {
		t.Fatalf("%d documents sent, want 2000", total)
	}
}
