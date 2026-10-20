// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"testing"
	"time"
)

// @w, bin span=1w and timechart span=1w all start weeks on Sunday
// (SL-05).
func TestWeeksStartOnSunday(t *testing.T) {
	wed := time.Date(2026, 10, 14, 13, 0, 0, 0, time.UTC)
	if got, _ := relativeTime(wed, "@w"); got.Weekday() != time.Sunday {
		t.Errorf("relative_time @w = %v", got)
	}
	// bin's week buckets start weekStart seconds after Unix time 0.
	if d := time.Unix(weekStart, 0).UTC().Weekday(); d != time.Sunday {
		t.Errorf("bin weeks start on %v", d)
	}
	iv, err := spanInterval("2w")
	if err != nil || iv["fixed_interval"] != "14d" || iv["offset"] != "+3d" {
		t.Errorf("timechart span=2w = %v %v", iv, err)
	}
	// Unix time 0 plus the offset is a Sunday.
	if d := time.Unix(0, 0).UTC().AddDate(0, 0, 3).Weekday(); d != time.Sunday {
		t.Errorf("timechart weeks start on %v", d)
	}
	if iv, err := spanInterval("1q"); err != nil || iv["calendar_interval"] != "quarter" {
		t.Errorf("span=1q = %v %v", iv, err)
	}
}
