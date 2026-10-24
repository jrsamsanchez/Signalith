// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/compliance"
	"github.com/jrsamsanchez/signalith/internal/compliancehist"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Compliance history records round-trip through OpenSearch as stored,
// newest first, one per ID.
func TestComplianceHistoryInOpenSearch(t *testing.T) {
	cl, _, prefix := setup(t)
	ctx := context.Background()
	st := compliancehist.NewOpenSearch(cl, prefix)
	if list, err := st.List(ctx); err != nil || len(list) != 0 {
		t.Fatalf("before any record: %v %v", list, err)
	}
	if due, err := compliancehist.Due(ctx, st, time.Now()); err != nil || !due {
		t.Fatalf("due with no index: %v %v", due, err)
	}
	month := time.Date(2026, 9, 1, 0, 5, 0, 0, time.UTC)
	later := month.Add(40 * 24 * time.Hour)
	for _, r := range []*compliancehist.Record{
		compliancehist.FromReport(&compliance.Report{Generated: month}, compliancehist.MonthID(month), compliancehist.Monthly, "", "s", "v", prefix),
		compliancehist.FromReport(&compliance.Report{Generated: later}, compliancehist.ManualID(later), compliancehist.Manual, "ana", "s", "v", prefix),
	} {
		s, _ := compliancehist.Sign(r, nil)
		if err := st.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		if err := st.Create(ctx, s); !errors.Is(err, store.ErrExists) {
			t.Errorf("again: %v", err)
		}
	}
	list, err := st.List(ctx)
	if err != nil || len(list) != 2 || list[0].ID != compliancehist.ManualID(later) || list[1].ID != compliancehist.MonthID(month) {
		t.Fatalf("list: %+v %v", list, err)
	}
	got, err := st.Get(ctx, compliancehist.MonthID(month))
	if err != nil {
		t.Fatal(err)
	}
	if c := compliancehist.Check(got, nil); c.Check != compliancehist.Unsigned || c.Record != nil || got.Taken.IsZero() {
		t.Errorf("check: %+v", c)
	}
	// A copy of one month's record stored as another's is read under the
	// ID it is stored at, so it no longer matches its data (SEC-527-4).
	if err := cl.Do(ctx, "PUT", "/"+st.Index+"/_create/2026-11?refresh=true", got, nil); err != nil {
		t.Fatal(err)
	}
	if back, err := st.Get(ctx, "2026-11"); err != nil || back.ID != "2026-11" {
		t.Errorf("copy: %+v %v", back, err)
	}
	if due, _ := compliancehist.Due(ctx, st, month); due {
		t.Error("due after the month's record")
	}
	if _, err := st.Get(ctx, "2001-01"); !errors.Is(err, compliancehist.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
}
