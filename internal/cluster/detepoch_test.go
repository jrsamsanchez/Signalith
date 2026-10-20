// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

type emptyRunner struct{}

func (emptyRunner) Execute(context.Context, *query.Query) (*search.Result, error) {
	return &search.Result{Kind: "table"}, nil
}

// TestLeaseEpochIgnoresDetectionEpochs: the detection epochs the
// scheduler writes from cluster level 11 (lease<<20 and up) are not taken
// for lease epochs, so a lease made again after they were written gets
// the next lease epoch, not one about a million times bigger.
func TestLeaseEpochIgnoresDetectionEpochs(t *testing.T) {
	srv := ostest.New(t)
	cl := store.New(store.Config{URL: srv.URL})
	ctx := context.Background()
	lib, problems, err := detect.NewLibrary(t.TempDir())
	if err != nil || len(problems) > 0 {
		t.Fatal(err, problems)
	}
	if err := lib.Put(&detect.Detection{ID: "lease-rule", Title: "L", Query: "user=l", Enabled: true, Schedule: "5m", Lookback: "5m", Severity: "low"}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	sched := (&detect.Scheduler{Library: lib, Engine: emptyRunner{}, Findings: findings.NewMemory(),
		Now: func() time.Time { return now }, ClusterNow: func() time.Time { return now },
		Log: slog.New(slog.DiscardHandler), Runtime: cl, RuntimeIndex: testIndex,
		Epoch: func() int64 { return 5 }, Counter: func() bool { return true }, NodeID: "n1"})
	sched.RunDue(ctx)
	now = now.Add(5 * time.Minute)
	sched.RunDue(ctx)
	if srv.Source(testIndex, "detstate:lease-rule")["det_epoch"] == nil {
		t.Fatal("no detection epoch was written")
	}
	top, err := maxEpoch(ctx, cl, testIndex)
	if err != nil {
		t.Fatal(err)
	}
	if top != 5 {
		t.Errorf("highest lease epoch %d after detection epochs were written, want 5 (the lease made again takes %d)", top, top+1)
	}
}
