// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

// detViewsFresh is how long detViews.all answers from its last read. The
// Servers page and load balancers' tools ask GET /api/cluster every
// second or so, and each read costs OpenSearch a get and a search per
// tenant; the assignment itself is only read every few seconds
// (followTick).
const detViewsFresh = 5 * time.Second

// detViews keeps, per tenant this server follows, how to read how its
// detections are spread, for the Servers page (GET /api/cluster).
type detViews struct {
	mu      sync.Mutex
	tenants map[string]*detView
	// last is what all read at lastAt, while the tenants were those of
	// generation gen.
	gen, lastGen uint64
	last         []detect.SpreadView
	lastAt       time.Time
	// now is time.Now, or a test's clock.
	now func() time.Time
}

type detView struct {
	read func(ctx context.Context) (detect.SpreadView, error)
}

func newDetViews() *detViews { return &detViews{tenants: map[string]*detView{}} }

// add registers tenant's view while ctx lasts.
func (v *detViews) add(ctx context.Context, jobs *sync.WaitGroup, tenant string, read func(context.Context) (detect.SpreadView, error)) {
	e := &detView{read: read}
	v.mu.Lock()
	v.tenants[tenant] = e
	v.gen++
	v.mu.Unlock()
	jobs.Go(func() {
		<-ctx.Done()
		v.mu.Lock()
		if v.tenants[tenant] == e {
			delete(v.tenants, tenant)
			v.gen++
		}
		v.mu.Unlock()
	})
}

// all reads every tenant's view, leaving out those with nothing to show
// (not spread and no detection run lately) or that cannot be read, in
// tenant order. A read less than detViewsFresh old is answered again.
func (v *detViews) all(ctx context.Context) []detect.SpreadView {
	now := time.Now
	if v.now != nil {
		now = v.now
	}
	v.mu.Lock()
	if v.lastGen == v.gen && !v.lastAt.IsZero() && now().Sub(v.lastAt) < detViewsFresh {
		out := slices.Clone(v.last)
		v.mu.Unlock()
		return out
	}
	gen := v.gen
	reads := make(map[string]*detView, len(v.tenants))
	for id, e := range v.tenants {
		reads[id] = e
	}
	v.mu.Unlock()
	var out []detect.SpreadView
	for _, e := range reads {
		if sv, err := e.read(ctx); err == nil && (len(sv.Servers) > 0 || len(sv.Health) > 0) {
			out = append(out, sv)
		}
	}
	slices.SortFunc(out, func(a, b detect.SpreadView) int { return strings.Compare(a.Tenant, b.Tenant) })
	v.mu.Lock()
	if v.gen == gen {
		v.last, v.lastAt, v.lastGen = slices.Clone(out), now(), gen
	}
	v.mu.Unlock()
	return out
}
