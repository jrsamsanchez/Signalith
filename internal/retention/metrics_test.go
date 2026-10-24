// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"context"
	"testing"
)

func TestMetricsView(t *testing.T) {
	f := newFixture(t, Config{Days: 90})
	ctx := context.Background()
	v := f.m.Metrics(ctx)
	if !v.LastRun.IsZero() || v.Running || v.GuardState != GuardOK || v.DiskPercent < 0 || v.GuardLimit == 0 {
		t.Errorf("before a run: %+v", v)
	}
	if _, err := f.m.Run(ctx, TriggerManual, "ann"); err != nil {
		t.Fatal(err)
	}
	v = f.m.Metrics(ctx)
	if !v.LastRun.Equal(testNow) || v.LastRunErrors != 0 {
		t.Errorf("after a run: %+v", v)
	}
	// Another server start reads the last run from the history.
	again := newFixture(t, Config{Days: 90})
	again.m.HistoryFile = f.m.HistoryFile
	if v := again.m.Metrics(ctx); !v.LastRun.Equal(testNow) {
		t.Errorf("from the history: %+v", v)
	}
}
