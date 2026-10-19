// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

// detPool is this server's detection workers while detections are spread:
// one pool shared by every tenant's spread scheduler, sized to the
// server's share of the cluster's search budget (see detect.Pool).
type detPool struct {
	pool *detect.Pool
	log  *slog.Logger

	mu        sync.Mutex
	followers map[*detect.Follower]int
	// The automatic budget, read from OpenSearch at most every
	// detBudgetAge.
	autoAt time.Time
	auto   int
}

// detBudgetAge is how long the automatic search budget is kept.
const detBudgetAge = 5 * time.Minute

func newDetPool(log *slog.Logger) *detPool {
	p := detect.NewPool(detect.DefaultPoolSize)
	p.Log = log
	return &detPool{pool: p, log: log, followers: map[*detect.Follower]int{}}
}

// add counts f's share in the pool's size until ctx ends.
func (dp *detPool) add(ctx context.Context, jobs *sync.WaitGroup, f *detect.Follower) {
	dp.mu.Lock()
	dp.followers[f]++
	dp.mu.Unlock()
	jobs.Go(func() {
		defer func() {
			dp.mu.Lock()
			if dp.followers[f]--; dp.followers[f] <= 0 {
				delete(dp.followers, f)
			}
			dp.mu.Unlock()
			dp.resize()
		}()
		for {
			dp.resize()
			select {
			case <-ctx.Done():
				return
			case <-time.After(followTick):
			}
		}
	})
}

// resize sets the pool's size from the shares of every tenant followed.
func (dp *detPool) resize() {
	dp.mu.Lock()
	var shares []detect.SpreadShare
	for f := range dp.followers {
		if s, ok := f.Share(); ok {
			shares = append(shares, s)
		}
	}
	dp.mu.Unlock()
	dp.pool.SetSize(detect.PoolSize(shares))
}

// budget is the cluster's detection search budget: setting
// (detections.search_budget) when set, else half the searches OpenSearch's
// data nodes run at once, as threads reads them; 0 when they cannot be
// read, which leaves each server its default pool.
func (dp *detPool) budget(ctx context.Context, setting int, threads func(context.Context) (int, error)) int {
	if setting > 0 {
		return setting
	}
	dp.mu.Lock()
	if !dp.autoAt.IsZero() && time.Since(dp.autoAt) < detBudgetAge {
		n := dp.auto
		dp.mu.Unlock()
		return n
	}
	dp.mu.Unlock()
	n := 0
	if threads != nil {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		t, err := threads(rctx)
		cancel()
		if err != nil {
			dp.log.Warn("could not read how many searches OpenSearch runs at once; each server runs its default number of detections at once", "err", err)
		} else if t > 0 {
			n = max(t/2, 1)
		}
	}
	dp.mu.Lock()
	dp.auto, dp.autoAt = n, time.Now()
	dp.mu.Unlock()
	return n
}
