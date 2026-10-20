// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeIngest answers POST /api/ingest: the first answer to each distinct
// body is 503, so every batch is sent twice, and it keeps the sequence
// numbers it stored.
type fakeIngest struct {
	mu     sync.Mutex
	seen   map[string]int
	stored map[int]map[int64]int
	resent int
	// refuse answers every batch 401.
	refuse bool
}

func (f *fakeIngest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/ingest" || r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("X-Signalith-Agent") == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse {
		http.Error(w, `{"error":"no"}`, http.StatusUnauthorized)
		return
	}
	f.seen[string(body)]++
	if f.seen[string(body)] == 1 {
		w.Header().Set("Retry-After", "1")
		http.Error(w, `{"error":"busy"}`, http.StatusServiceUnavailable)
		return
	}
	f.resent++
	var events []struct {
		Agent int    `json:"loadgen_agent"`
		Seq   int64  `json:"loadgen_seq"`
		Run   string `json:"loadgen_run"`
	}
	if err := json.Unmarshal(body, &events); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, e := range events {
		if f.stored[e.Agent] == nil {
			f.stored[e.Agent] = map[int64]int{}
		}
		f.stored[e.Agent][e.Seq]++
	}
	_ = json.NewEncoder(w).Encode(map[string]int{"received": len(events), "indexed": len(events)})
}

func TestFleetRetriesKeepSequenceNumbers(t *testing.T) {
	fake := &fakeIngest{seen: map[string]int{}, stored: map[int]map[int64]int{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	m := newMetrics()
	m.SetPhase("load")
	f := newFleet("run1", "tok", []string{srv.URL}, srv.Client(), m)
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	f.Run(ctx, AgentLoad{N: 3, Rate: 300, Batch: 10, EventBytes: 300})
	done := make(chan struct{})
	go func() { f.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("agents did not finish their retries")
	}
	sent, stored := f.sent.Load(), f.stored.Load()
	if sent == 0 || sent != stored || f.undelivered.Load() != 0 {
		t.Fatalf("sent %d stored %d undelivered %d", sent, stored, f.undelivered.Load())
	}
	// Every batch was answered 503 once and then stored when sent again
	// byte for byte, so the stored numbers are exactly the acknowledged
	// ones, each once.
	v := compare(f.Acked(), fake.stored)
	if v.Acked != sent || v.Lost != 0 || v.Duplicated != 0 || v.Unacked != 0 {
		t.Errorf("verdict %+v, sent %d", v, sent)
	}
	if int64(fake.resent)*10 != sent {
		t.Errorf("%d resends for %d events", fake.resent, sent)
	}
	if m.Count("", "ingest_status_503") == 0 || m.Hist("", "ingest").Count() != m.Count("", "ingest_requests") {
		t.Errorf("metrics: 503s %d, timings %d, requests %d", m.Count("", "ingest_status_503"),
			m.Hist("", "ingest").Count(), m.Count("", "ingest_requests"))
	}
	for a, seqs := range fake.stored {
		for seq := int64(1); seq <= int64(len(seqs)); seq++ {
			if seqs[seq] != 1 {
				t.Fatalf("agent %d: sequence numbers not 1..%d: missing %d", a, len(seqs), seq)
			}
		}
	}
}

func TestFleetRefusedBatchesAreNotRetried(t *testing.T) {
	fake := &fakeIngest{seen: map[string]int{}, stored: map[int]map[int64]int{}, refuse: true}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	m := newMetrics()
	f := newFleet("run1", "tok", []string{srv.URL}, srv.Client(), m)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	f.Run(ctx, AgentLoad{N: 2, Rate: 100, Batch: 5})
	f.Close()
	if f.refused.Load() == 0 || f.refused.Load() != f.sent.Load() || len(f.Acked()) != 0 {
		t.Errorf("refused %d of %d, acked %v", f.refused.Load(), f.sent.Load(), f.Acked())
	}
}

func TestFleetGivesUpWhenTheDrainEnds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	f := newFleet("run1", "tok", []string{srv.URL}, srv.Client(), newMetrics())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	f.Run(ctx, AgentLoad{N: 1, Rate: 100, Batch: 5})
	time.AfterFunc(300*time.Millisecond, f.StopRetrying)
	f.Close()
	if f.undelivered.Load() == 0 || f.undelivered.Load() != f.sent.Load() {
		t.Errorf("undelivered %d of %d", f.undelivered.Load(), f.sent.Load())
	}
}

func TestFleetCapsBufferedBatches(t *testing.T) {
	// A server that never answers: every batch stays buffered.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	f := newFleet("run1", "tok", []string{srv.URL}, srv.Client(), newMetrics())
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	// Batches of about 100 KB against a 1 MB cap.
	f.Run(ctx, AgentLoad{N: 4, Rate: 10000, Batch: 100, EventBytes: 1000, BufferMB: 1})
	if got := f.buffered.Load(); got > 1<<20+200<<10 {
		t.Errorf("buffered %d bytes past a 1 MB cap", got)
	}
	if f.dropped.Load() == 0 {
		t.Error("nothing dropped once the buffer was full")
	}
	f.StopRetrying()
	close(block)
	f.Close()
	if got := f.buffered.Load(); got != 0 {
		t.Errorf("%d bytes still counted after Close", got)
	}
}

func TestBatchBody(t *testing.T) {
	f := newFleet("abc", "tok", []string{"http://x"}, nil, newMetrics())
	a := &simAgent{id: 42, host: "agent-0042", next: 7}
	b := f.build(a, 2, 200)
	var events []map[string]any
	if err := json.Unmarshal(b.body, &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || b.first != 7 || b.last != 8 || a.next != 9 {
		t.Fatalf("batch %d..%d of %d, next %d", b.first, b.last, len(events), a.next)
	}
	e := events[1]
	if e["loadgen_run"] != "abc" || e["loadgen_agent"] != 42.0 || e["loadgen_seq"] != 8.0 || e["host"] != "agent-0042" {
		t.Errorf("event %v", e)
	}
	if n := len(bytes.TrimSpace([]byte(e["message"].(string)))); n < 100 {
		t.Errorf("message not padded: %d bytes", n)
	}
}

func TestPaceIsOpenLoop(t *testing.T) {
	m := newMetrics()
	var n int
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	pace(ctx, 200, m, func(int64) {
		n++
		if n == 10 {
			// A slow call does not lower the rate: the schedule catches up.
			time.Sleep(100 * time.Millisecond)
		}
	})
	want := int(time.Since(start).Seconds() * 200)
	if n < want*8/10 || n > want+5 {
		t.Errorf("%d calls, want about %d", n, want)
	}
	if m.Hist("", "generator_lag").Max() < 50*time.Millisecond {
		t.Error("the stall was not recorded as generator lag")
	}
}

func TestFleetAgentGoesBackToItsTarget(t *testing.T) {
	old := homeAfter
	homeAfter = 1500 * time.Millisecond
	defer func() { homeAfter = old }()
	var mu sync.Mutex
	refusals, home, other := 0, 0, 0
	answer := func(w http.ResponseWriter, n *int, ok bool) {
		mu.Lock()
		defer mu.Unlock()
		if !ok {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		*n++
		_ = json.NewEncoder(w).Encode(map[string]int{"indexed": 1})
	}
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		ok := refusals > 0
		refusals++
		mu.Unlock()
		answer(w, &home, ok)
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		answer(w, &other, true)
	}))
	defer b.Close()
	f := newFleet("run1", "tok", []string{a.URL, b.URL}, a.Client(), newMetrics())
	// One agent, whose own target is a, which refuses its first batch:
	// the agent switches to b, and returns to a once homeAfter is over.
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()
	f.Run(ctx, AgentLoad{N: 1, Rate: 20, Batch: 1, SwitchOnError: true})
	f.Close()
	mu.Lock()
	defer mu.Unlock()
	if other == 0 || home == 0 {
		t.Errorf("batches stored by its own target %d, by the other %d", home, other)
	}
}
