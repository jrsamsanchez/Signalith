package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

func TestDetPoolBudget(t *testing.T) {
	ctx := context.Background()
	dp := newDetPool(slog.New(slog.DiscardHandler))
	calls := 0
	threads := func(context.Context) (int, error) { calls++; return 26, nil }
	if got := dp.budget(ctx, 7, threads); got != 7 || calls != 0 {
		t.Fatalf("set budget: %d (%d reads)", got, calls)
	}
	if got := dp.budget(ctx, 0, threads); got != 13 {
		t.Fatalf("automatic budget %d, want half of 26", got)
	}
	dp.budget(ctx, 0, threads)
	if calls != 1 {
		t.Errorf("OpenSearch read %d times, want once while the budget is fresh", calls)
	}
	dp = newDetPool(slog.New(slog.DiscardHandler))
	if got := dp.budget(ctx, 0, func(context.Context) (int, error) { return 0, errors.New("forbidden") }); got != 0 {
		t.Errorf("budget %d when OpenSearch cannot say", got)
	}
}

func TestDetPoolResize(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dp := newDetPool(slog.New(slog.DiscardHandler))
	rs := detect.NewMemoryRunStore()
	a := &detect.Assignment{Kind: "detassign", Tenant: "acme", LeaseEpoch: 1, Owners: make([]detect.BucketOwner, detect.Buckets), SearchBudget: 12}
	for b := range a.Owners {
		node := "a"
		if b%4 != 0 {
			node = "b"
		}
		a.Owners[b] = detect.BucketOwner{Node: node, DetEpoch: int64(b + 1), State: detect.BucketRun}
	}
	if _, err := rs.Create(ctx, "rt", detect.AssignmentID("acme"), a, true); err != nil {
		t.Fatal(err)
	}
	f := &detect.Follower{Tenant: "acme", Self: "a", Runtime: rs, RuntimeIndex: "rt"}
	if err := f.Read(ctx); err != nil {
		t.Fatal(err)
	}
	var jobs sync.WaitGroup
	dp.add(ctx, &jobs, f)
	dp.resize()
	if s := dp.pool.Stats(); s.Size != 3 {
		t.Errorf("pool of %d for 16 of 64 buckets of a budget of 12, want 3", s.Size)
	}
	cancel()
	jobs.Wait()
	if s := dp.pool.Stats(); s.Size != detect.DefaultPoolSize {
		t.Errorf("pool of %d after the tenant stopped", s.Size)
	}
}
