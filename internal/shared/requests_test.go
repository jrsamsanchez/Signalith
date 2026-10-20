// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lease is a fake job lease.
type lease struct {
	mu      sync.Mutex
	epoch   int64
	holding bool
}

func (l *lease) get() (int64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.epoch, l.holding
}

func (l *lease) set(epoch int64, holding bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.epoch, l.holding = epoch, holding
}

// U16: two runners claim one request and exactly one runs it; a lost
// lease puts it back in the queue, marked interrupted, and the next
// leader finishes it.
func TestRequestsRunOnceAndResume(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ra, rb := NewRequests(a, "n_a"), NewRequests(b, "n_b")
	req, err := rb.Submit(ctx, "feed_refresh", TargetLeader, map[string]any{"feed": "otx"}, "sam")
	if err != nil {
		t.Fatal(err)
	}
	if req.State != RequestQueued || req.RequestedOn != "siem-b" || e.os.Source(testIndex, "watch:requests") == nil {
		t.Fatalf("submitted %+v", req)
	}

	// Both think they lead (a lease handover in progress): only one runs.
	var runs atomic.Int32
	handler := func(ctx context.Context, r *Request) error {
		var args struct{ Feed string }
		if err := json.Unmarshal(r.Args, &args); err != nil || args.Feed != "otx" {
			t.Errorf("args %s", r.Args)
		}
		runs.Add(1)
		time.Sleep(10 * time.Millisecond)
		return nil
	}
	la, lb := &lease{epoch: 3, holding: true}, &lease{epoch: 3, holding: true}
	runners := []*Runner{
		{Requests: ra, Handlers: map[string]Handler{"feed_refresh": handler}, Lease: la.get},
		{Requests: rb, Handlers: map[string]Handler{"feed_refresh": handler}, Lease: lb.get},
	}
	var wg sync.WaitGroup
	for _, rn := range runners {
		wg.Go(func() {
			if _, err := rn.RunOnce(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if runs.Load() != 1 {
		t.Errorf("ran %d times", runs.Load())
	}
	got, found, err := ra.Get(ctx, req.ID)
	if err != nil || !found || got.State != RequestDone || got.Finished == nil || got.Epoch != 3 || got.ClaimedBy == "" {
		t.Errorf("after the run: %+v %v %v", got, found, err)
	}

	// A run interrupted by a lost lease goes back to the queue.
	req2, err := rb.Submit(ctx, "retention_run", TargetLeader, nil, "sam")
	if err != nil {
		t.Fatal(err)
	}
	la.set(4, true)
	lb.set(0, false)
	runA := &Runner{Requests: ra, Lease: la.get, Handlers: map[string]Handler{"retention_run": func(ctx context.Context, r *Request) error {
		la.set(4, false)
		return errors.New("the lease was lost")
	}}}
	if n, err := runA.RunOnce(ctx); n != 1 || err != nil {
		t.Fatalf("run a: %d %v", n, err)
	}
	got, _, _ = ra.Get(ctx, req2.ID)
	if got.State != RequestQueued || !got.Interrupted || got.ClaimedBy != "" || got.Error != "" {
		t.Errorf("interrupted: %+v", got)
	}

	// The next leader finishes it.
	lb.set(5, true)
	runB := &Runner{Requests: rb, Lease: lb.get, Handlers: map[string]Handler{"retention_run": func(ctx context.Context, r *Request) error {
		return r.SetResult(map[string]int{"deleted": 2})
	}}}
	if n, err := runB.RunOnce(ctx); n != 1 || err != nil {
		t.Fatalf("run b: %d %v", n, err)
	}
	got, _, _ = rb.Get(ctx, req2.ID)
	if got.State != RequestDone || got.Epoch != 5 || got.ClaimedBy != "n_b" || string(got.Result) != `{"deleted":2}` {
		t.Errorf("resumed: %+v %s", got, got.Result)
	}
}

func TestRequestsLeftRunningByAStoppedLeader(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	r := NewRequests(a, "n_a")
	req, err := r.Submit(ctx, "feed_refresh", TargetLeader, nil, "sam")
	if err != nil {
		t.Fatal(err)
	}
	// A leader at epoch 2 claimed it and died.
	req, _, _ = r.Get(ctx, req.ID)
	req.State, req.ClaimedBy, req.Epoch = RequestRunning, "n_dead", 2
	if err := r.put(ctx, req); err != nil {
		t.Fatal(err)
	}
	ran := 0
	l := &lease{epoch: 2, holding: true}
	rn := &Runner{Requests: r, Lease: l.get, Handlers: map[string]Handler{"feed_refresh": func(context.Context, *Request) error { ran++; return nil }}}
	if n, _ := rn.RunOnce(ctx); n != 0 {
		t.Errorf("ran under the same epoch: %d", n)
	}
	l.set(3, true)
	if n, _ := rn.RunOnce(ctx); n != 1 || ran != 1 {
		t.Errorf("ran %d %d", n, ran)
	}
	// Failures are recorded; unknown types are left alone.
	failing, _ := r.Submit(ctx, "feed_refresh", TargetLeader, nil, "sam")
	unknown, _ := r.Submit(ctx, "from_the_future", TargetLeader, nil, "sam")
	rn.Handlers["feed_refresh"] = func(context.Context, *Request) error { return errors.New("the feed answered 500") }
	rn.RunOnce(ctx)
	if got, _, _ := r.Get(ctx, failing.ID); got.State != RequestFailed || got.Error != "the feed answered 500" {
		t.Errorf("failed: %+v", got)
	}
	if got, _, _ := r.Get(ctx, unknown.ID); got.State != RequestQueued {
		t.Errorf("unknown: %+v", got)
	}

	// Housekeeping removes finished requests after 7 days.
	if n, err := r.Housekeep(ctx, e.clock.Now()); n != 0 || err != nil {
		t.Errorf("early housekeeping: %d %v", n, err)
	}
	if n, err := r.Housekeep(ctx, e.clock.Now().Add(FinishedRequestAge+time.Hour)); n != 2 || err != nil {
		t.Errorf("housekeeping: %d %v", n, err)
	}
	if _, found, _ := r.Get(ctx, unknown.ID); !found {
		t.Error("a queued request was removed")
	}
}

func TestRequestsForOneServer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	ra, rb := NewRequests(a, "n_a"), NewRequests(a, "n_b")
	req, err := ra.Submit(ctx, "restart", "n_b", nil, "sam")
	if err != nil {
		t.Fatal(err)
	}
	notLeader := func() (int64, bool) { return 0, false }
	ranOn := ""
	h := map[string]Handler{"restart": func(ctx context.Context, r *Request) error { ranOn = r.ClaimedBy; return nil }}
	(&Runner{Requests: ra, Lease: notLeader, Handlers: h}).RunOnce(ctx)
	(&Runner{Requests: rb, Lease: notLeader, Handlers: h}).RunOnce(ctx)
	if got, _, _ := ra.Get(ctx, req.ID); got.State != RequestDone || ranOn != "n_b" {
		t.Errorf("%+v ran on %q", got, ranOn)
	}
}

// A request for several servers in sequence: each acts once the one
// before it is over, or has been offline long enough; a failure stops
// the servers after it.
func TestRequestsInSequence(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	runners := map[string]*Runner{}
	var order []string
	offline := map[string]bool{}
	fail := map[string]bool{}
	notLeader := func() (int64, bool) { return 0, false }
	for _, id := range []string{"n_a", "n_b", "n_c"} {
		runners[id] = &Runner{Requests: NewRequests(a, id), Lease: notLeader,
			Offline: func(n string) bool { return offline[n] },
			Handlers: map[string]Handler{"restart": func(ctx context.Context, r *Request) error {
				order = append(order, id)
				if fail[id] {
					return errors.New("did not come back")
				}
				return nil
			}}}
	}
	ra := runners["n_a"].Requests
	runAll := func(ids ...string) {
		for _, id := range ids {
			if _, err := runners[id].RunOnce(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}

	req, err := ra.SubmitTo(ctx, "restart", []string{"n_a", "n_b", "n_c"}, true, nil, "sam")
	if err != nil {
		t.Fatal(err)
	}
	// n_c and n_b wait for the ones before them.
	runAll("n_c", "n_b")
	if len(order) != 0 {
		t.Fatalf("ran early: %v", order)
	}
	runAll("n_a", "n_c", "n_b", "n_c")
	got, _, _ := ra.Get(ctx, req.ID)
	if !slices.Equal(order, []string{"n_a", "n_b", "n_c"}) || got.State != RequestDone || got.Finished == nil {
		t.Errorf("order %v, %+v", order, got)
	}
	for _, id := range got.Targets {
		if got.Status[id] != RequestDone {
			t.Errorf("status %v", got.Status)
		}
	}

	// n_a is offline: n_b goes on without it.
	order = nil
	offline["n_a"] = true
	req, _ = ra.SubmitTo(ctx, "restart", []string{"n_a", "n_b"}, true, nil, "sam")
	runAll("n_b")
	got, _, _ = ra.Get(ctx, req.ID)
	if !slices.Equal(order, []string{"n_b"}) || got.Status["n_a"] != RequestSkipped || got.State != RequestDone {
		t.Errorf("order %v, %+v", order, got)
	}

	// A failure stops the sequence.
	order, offline = nil, map[string]bool{}
	fail["n_a"] = true
	req, _ = ra.SubmitTo(ctx, "restart", []string{"n_a", "n_b"}, true, nil, "sam")
	runAll("n_a", "n_b")
	got, _, _ = ra.Get(ctx, req.ID)
	if !slices.Equal(order, []string{"n_a"}) || got.State != RequestFailed || got.Status["n_a"] != RequestFailed ||
		!strings.Contains(got.Error, "n_a: did not come back") {
		t.Errorf("order %v, %+v", order, got)
	}

	// Not in sequence: each runs its part when it can.
	order = nil
	req, _ = ra.SubmitTo(ctx, "restart", []string{"n_b", "n_c"}, false, nil, "sam")
	runAll("n_c")
	if got, _, _ = ra.Get(ctx, req.ID); got.State != RequestQueued || got.Status["n_c"] != RequestDone {
		t.Errorf("%+v", got)
	}
	runAll("n_b", "n_b")
	if got, _, _ = ra.Get(ctx, req.ID); got.State != RequestDone || !slices.Equal(order, []string{"n_c", "n_b"}) {
		t.Errorf("order %v, %+v", order, got)
	}
}

// A request someone wrote to OpenSearch without the cluster key, or one
// whose signed fields were changed, is refused and logged, not run; one
// signed with another key the server still accepts runs.
func TestRequestsRefuseForged(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, logs := e.hub("siem-a")
	r := NewRequests(a, "n_a")
	ran := 0
	l := &lease{epoch: 1, holding: true}
	rn := &Runner{Requests: r, Lease: l.get, Handlers: map[string]Handler{"rotate_key": func(context.Context, *Request) error { ran++; return nil }}}

	// Written straight to the runtime index, without a MAC.
	forged := &Request{Kind: "request", ID: "rq_forged", Type: "rotate_key", Target: TargetLeader, State: RequestQueued,
		RequestedBy: "admin", RequestedOn: "siem-a", Created: e.clock.Now().UTC()}
	if _, err := e.c.Create(ctx, r.index(), requestDocID(forged.ID), forged, true); err != nil {
		t.Fatal(err)
	}
	// Signed, then its arguments changed.
	changed, err := r.Submit(ctx, "rotate_key", TargetLeader, map[string]any{"reason": "routine"}, "sam")
	if err != nil {
		t.Fatal(err)
	}
	changed, _, _ = r.Get(ctx, changed.ID)
	changed.Args, changed.RequestedBy = json.RawMessage(`{"reason":"evil"}`), "admin"
	if err := r.put(ctx, changed); err != nil {
		t.Fatal(err)
	}
	if n, err := rn.RunOnce(ctx); n != 0 || err != nil || ran != 0 {
		t.Fatalf("ran %d %d %v", n, ran, err)
	}
	for _, id := range []string{forged.ID, changed.ID} {
		got, _, _ := r.Get(ctx, id)
		if got.State != RequestFailed || !strings.HasPrefix(got.Error, "refused: ") {
			t.Errorf("%s: %+v", id, got)
		}
	}
	if !strings.Contains(logs.String(), "refused to run a request") || !strings.Contains(logs.String(), `"audit":true`) {
		t.Errorf("not logged: %s", logs)
	}

	// Signed with the old key during a rotation: still accepted.
	other, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	old, _ := e.hub("siem-b")
	old.SetKeys(NewKeySet(other))
	// Its arguments come back from OpenSearch with their keys in another
	// order.
	args := struct {
		Removed []string `json:"removed"`
		Reason  string   `json:"reason"`
	}{[]string{"n_c"}, "removed siem-c"}
	req, err := NewRequests(old, "n_b").Submit(ctx, "rotate_key", TargetLeader, args, "sam")
	if err != nil {
		t.Fatal(err)
	}
	a.SetKeys(NewKeySet(e.key, other))
	if n, _ := rn.RunOnce(ctx); n != 1 || ran != 1 {
		t.Fatalf("ran %d %d", n, ran)
	}
	if got, _, _ := r.Get(ctx, req.ID); got.State != RequestDone {
		t.Errorf("old key: %+v", got)
	}
	// Once the old key is no longer accepted, a request it signed is not run.
	req, _ = NewRequests(old, "n_b").Submit(ctx, "rotate_key", TargetLeader, nil, "sam")
	a.SetKeys(NewKeySet(e.key))
	if n, _ := rn.RunOnce(ctx); n != 0 || ran != 1 {
		t.Fatalf("ran %d %d", n, ran)
	}
	if got, _, _ := r.Get(ctx, req.ID); got.State != RequestFailed {
		t.Errorf("dropped key: %+v", got)
	}
}

// A request that ran, put back in the queue as it was, does not run
// again: not on the server that ran it, nor on another once it is older
// than RequestMaxAge.
func TestRequestsRefuseReplayed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	ra, rb := NewRequests(a, "n_a"), NewRequests(a, "n_b")
	ran := 0
	h := map[string]Handler{"archive_restore": func(context.Context, *Request) error { ran++; return nil }}
	la, lb := &lease{epoch: 1, holding: true}, &lease{}
	runA := &Runner{Requests: ra, Lease: la.get, Handlers: h}
	runB := &Runner{Requests: rb, Lease: lb.get, Handlers: h}
	req, err := ra.Submit(ctx, "archive_restore", TargetLeader, map[string]any{"confirm": true}, "sam")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := runA.RunOnce(ctx); n != 1 || ran != 1 {
		t.Fatalf("ran %d %d", n, ran)
	}
	requeue := func() {
		t.Helper()
		got, _, _ := ra.Get(ctx, req.ID)
		got.State, got.ClaimedBy, got.Started, got.Finished, got.Error = RequestQueued, "", nil, nil, ""
		if err := ra.put(ctx, got); err != nil {
			t.Fatal(err)
		}
	}
	requeue()
	runA.RunOnce(ctx)
	if got, _, _ := ra.Get(ctx, req.ID); ran != 1 || got.State != RequestFailed {
		t.Fatalf("replayed on the same server: ran %d, %+v", ran, got)
	}

	// Another server, after the lease moved, an hour later.
	requeue()
	la.set(1, false)
	lb.set(2, true)
	e.clock.SetWall(e.clock.Now().Add(RequestMaxAge + time.Minute))
	runB.RunOnce(ctx)
	if got, _, _ := ra.Get(ctx, req.ID); ran != 1 || got.State != RequestFailed {
		t.Fatalf("replayed on another server: ran %d, %+v", ran, got)
	}
}
