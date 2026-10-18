package main

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

// detViews keeps, per tenant this server follows, how to read how its
// detections are spread, for the Servers page (GET /api/cluster).
type detViews struct {
	mu      sync.Mutex
	tenants map[string]*detView
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
	v.mu.Unlock()
	jobs.Go(func() {
		<-ctx.Done()
		v.mu.Lock()
		if v.tenants[tenant] == e {
			delete(v.tenants, tenant)
		}
		v.mu.Unlock()
	})
}

// all reads every tenant's view, leaving out those with nothing to show
// (not spread and no detection run lately) or that cannot be read, in
// tenant order.
func (v *detViews) all(ctx context.Context) []detect.SpreadView {
	v.mu.Lock()
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
	return out
}
