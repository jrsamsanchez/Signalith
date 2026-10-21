// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/exceptionreqs"
)

// Proposed exceptions keep in the runtime index, and two admins deciding
// one request at once cannot both win.
func TestExceptionRequestsInOpenSearch(t *testing.T) {
	cl, _, prefix := setup(t)
	ctx := context.Background()
	o := &exceptionreqs.OpenSearch{Docs: cl, Prefix: prefix}
	r := exceptionreqs.Request{ID: exceptionreqs.NewID(), DetectionID: "d", Match: map[string]string{"host": "web-01"}, By: "ana", Created: time.Now().UTC(), Status: exceptionreqs.Pending}
	if err := o.Modify(ctx, func(rs []exceptionreqs.Request) ([]exceptionreqs.Request, error) { return exceptionreqs.Add(rs, r) }); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Go(func() {
			errs[i] = o.Modify(ctx, func(rs []exceptionreqs.Request) ([]exceptionreqs.Request, error) {
				out, _, err := exceptionreqs.Decide(rs, r.ID, exceptionreqs.Approved, "root", "", "ex", time.Now())
				return out, err
			})
		})
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, exceptionreqs.ErrDecided):
			t.Errorf("decide: %v", err)
		}
	}
	if won != 1 {
		t.Errorf("%d decisions won, want 1", won)
	}
	rs, err := o.List(ctx)
	if err != nil || len(rs) != 1 || rs[0].Status != exceptionreqs.Approved || rs[0].Match["host"] != "web-01" {
		t.Errorf("list %+v %v", rs, err)
	}
}
