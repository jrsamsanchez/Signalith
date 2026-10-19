// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"context"
	"time"
)

// Time limits. A whole run is capped at RunLimit; a check whose facts
// did not arrive by then is "can't tell".
const (
	RunLimit          = 15 * time.Second
	OpenSearchTimeout = 5 * time.Second
	DialTimeout       = 1 * time.Second
	// OSTimeout bounds reading files and asking the OS, which can hang
	// on a stuck network share.
	OSTimeout = 5 * time.Second
)

// Collector gathers some facts. Run returns a function that applies
// what it found to Facts; it runs after every collector is done or out
// of time, one at a time, so collectors never touch Facts at once. A
// collector that runs out of time makes the checks it feeds "can't
// tell".
type Collector struct {
	Name string
	// Checks are the checks that need these facts.
	Checks  []string
	Timeout time.Duration
	Run     func(ctx context.Context) func(*Facts)
}

// Gather runs the collectors at once, each within its own time limit
// and all within limit, then applies what they found to f in order.
// Work an OS call cannot stop goes on in the background after its time
// is up, and what it finds is dropped.
func Gather(ctx context.Context, f *Facts, limit time.Duration, cs []Collector) {
	if limit <= 0 {
		limit = RunLimit
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	type result struct {
		i     int
		apply func(*Facts)
	}
	results := make(chan result, len(cs))
	for i, c := range cs {
		go func() {
			cctx := ctx
			if c.Timeout > 0 {
				var cancel context.CancelFunc
				cctx, cancel = context.WithTimeout(ctx, c.Timeout)
				defer cancel()
			}
			done := make(chan func(*Facts), 1)
			go func() {
				defer func() {
					if recover() != nil {
						done <- nil
					}
				}()
				done <- c.Run(cctx)
			}()
			select {
			case apply := <-done:
				results <- result{i, apply}
			case <-cctx.Done():
				results <- result{i, nil}
			}
		}()
	}
	applies := make([]func(*Facts), len(cs))
	got := make([]bool, len(cs))
	for range cs {
		r := <-results
		applies[r.i], got[r.i] = r.apply, r.apply != nil
	}
	for i, c := range cs {
		if got[i] {
			applies[i](f)
			continue
		}
		if f.TimedOut == nil {
			f.TimedOut = map[string]bool{}
		}
		for _, id := range c.Checks {
			f.TimedOut[id] = true
		}
	}
}

// Run gathers facts with cs and evaluates them.
func Run(ctx context.Context, f *Facts, cs []Collector) *Report {
	Gather(ctx, f, RunLimit, cs)
	return Evaluate(f)
}
