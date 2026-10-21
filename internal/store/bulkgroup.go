// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"sync"
)

// DefaultBulkInFlight is how many bulk requests a BulkGroup sends at once
// when NewBulkGroup is given 0. Few, so that batches waiting meanwhile make
// large requests: OpenSearch writes one request's shards in parallel, and
// on network volumes the per-request disk syncs, not the CPU, set the rate
// (on the cloud lab, 8 at once from each of 3 servers stored about 1,800
// real Windows events a second, with the volumes doing ~450 syncs a second).
const DefaultBulkInFlight = 2

// DefaultBulkGroupBytes is the most a BulkGroup puts in one request when
// it joins callers' documents. A caller's own documents are never split,
// so one request can be larger when a caller's alone is.
const DefaultBulkGroupBytes = 16 << 20

// BulkGroup writes documents in bulk as Client.Bulk does, joining the
// documents of callers that write at the same time into one request.
// Many agents each sending a small batch every second would otherwise make
// many small requests, each spread over every index its events belong to,
// and OpenSearch syncs each shard's translog to disk once per request: the
// syncs, not the bytes, then limit how many events a second are stored. At
// most inFlight requests are out at once; callers that arrive while they
// are wait and go together in the next one, so a quiet server sends each
// batch at once and a busy one sends fewer, larger requests. Each caller
// gets only its own documents' errors, with Pos counted in its own docs,
// and an error that fails the whole request fails every caller in it.
type BulkGroup struct {
	send     func(context.Context, []byte) ([]BulkItemError, error)
	maxBytes int
	slots    chan struct{}

	mu    sync.Mutex
	queue []*bulkCall
}

type bulkCall struct {
	body []byte
	n    int
	done chan struct{}
	errs []BulkItemError
	err  error
}

// NewBulkGroup returns a BulkGroup that writes through c, with at most
// inFlight requests out at once (0 means DefaultBulkInFlight).
func NewBulkGroup(c *Client, inFlight int) *BulkGroup {
	return newBulkGroup(c.sendBulk, inFlight, DefaultBulkGroupBytes)
}

func newBulkGroup(send func(context.Context, []byte) ([]BulkItemError, error), inFlight, maxBytes int) *BulkGroup {
	if inFlight <= 0 {
		inFlight = DefaultBulkInFlight
	}
	return &BulkGroup{send: send, maxBytes: maxBytes, slots: make(chan struct{}, inFlight)}
}

// Bulk writes docs, possibly in one request with other callers' documents.
// When ctx ends before the documents are sent, they are not sent; once
// sent, the request finishes even if ctx ends, and Bulk returns ctx's
// error without waiting for it.
func (g *BulkGroup) Bulk(ctx context.Context, docs []IndexedDoc) ([]BulkItemError, error) {
	if len(docs) == 0 {
		return nil, nil
	}
	body, err := encodeBulk(docs)
	if err != nil {
		return nil, err
	}
	call := &bulkCall{body: body, n: len(docs), done: make(chan struct{})}
	g.mu.Lock()
	g.queue = append(g.queue, call)
	g.mu.Unlock()
	for {
		select {
		case <-call.done:
			return call.errs, call.err
		case <-ctx.Done():
			// Not sent if still waiting; if already in a request that
			// is out, its result is not waited for.
			g.withdraw(call)
			return nil, ctx.Err()
		case g.slots <- struct{}{}:
			g.sendNext(ctx)
			<-g.slots
		}
	}
}

// withdraw takes call out of the queue if it has not been sent.
func (g *BulkGroup) withdraw(call *bulkCall) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, c := range g.queue {
		if c == call {
			g.queue = append(g.queue[:i], g.queue[i+1:]...)
			return
		}
	}
}

// sendNext sends the waiting calls at the head of the queue, up to
// maxBytes (always at least one), in one request.
func (g *BulkGroup) sendNext(ctx context.Context) {
	g.mu.Lock()
	n, size := 0, 0
	for n < len(g.queue) && (n == 0 || size+len(g.queue[n].body) <= g.maxBytes) {
		size += len(g.queue[n].body)
		n++
	}
	batch := append([]*bulkCall(nil), g.queue[:n]...)
	g.queue = append(g.queue[:0], g.queue[n:]...)
	g.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	body := batch[0].body
	if len(batch) > 1 {
		body = make([]byte, 0, size)
		for _, c := range batch {
			body = append(body, c.body...)
		}
	}
	// The request carries other callers' documents, so the caller that
	// happens to send it must not cancel it.
	errs, err := g.send(context.WithoutCancel(ctx), body)
	start := 0
	for _, c := range batch {
		c.err = err
		for _, e := range errs {
			if e.Pos >= start && e.Pos < start+c.n {
				e.Pos -= start
				c.errs = append(c.errs, e)
			}
		}
		start += c.n
		close(c.done)
	}
}
