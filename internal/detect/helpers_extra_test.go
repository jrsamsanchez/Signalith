// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/search"
)

func TestAnyTechnique(t *testing.T) {
	if tq, ok := AnyTechnique("T1059"); !ok || tq == nil {
		t.Error("an Enterprise technique was not found")
	}
	if tq, ok := AnyTechnique("t0800"); !ok || tq == nil {
		t.Error("an ICS technique was not found")
	}
	if _, ok := AnyTechnique("T9999"); ok {
		t.Error("an unknown technique was found")
	}
}

func TestRowTimeAndFormatStep(t *testing.T) {
	fallback := time.Now().UTC().Truncate(time.Second)
	at := fallback.Add(-time.Hour)
	tests := []struct {
		row  search.Row
		want time.Time
	}{
		{search.Row{"_time": at}, at},
		{search.Row{"_time": at.Format(time.RFC3339Nano)}, at},
		{search.Row{"_time": "yesterday"}, fallback},
		{search.Row{"_time": 12}, fallback},
		{search.Row{}, fallback},
	}
	for _, tc := range tests {
		if got := rowTime(tc.row, fallback); !got.Equal(tc.want) {
			t.Errorf("rowTime(%v) = %v, want %v", tc.row, got, tc.want)
		}
	}
	for d, want := range map[time.Duration]string{48 * time.Hour: "2d", 3 * time.Hour: "3h", 15 * time.Minute: "15m", 90 * time.Second: "1m30s"} {
		if got := formatStep(d); got != want {
			t.Errorf("formatStep(%v) = %s, want %s", d, got, want)
		}
	}
}

func TestToWeight(t *testing.T) {
	tests := []struct {
		v    any
		want float64
		ok   bool
	}{
		{5.5, 5.5, true},
		{int64(3), 3, true},
		{7, 7, true},
		{" 2.5 ", 2.5, true},
		{"ten", 0, false},
		{0.0, 0, false},
		{11, 0, false},
		{-1, 0, false},
		{true, 0, false},
		{nil, 0, false},
	}
	for _, tc := range tests {
		got, ok := toWeight(tc.v)
		if ok != tc.ok || got != tc.want {
			t.Errorf("toWeight(%v) = %v, %v", tc.v, got, ok)
		}
	}
}

func TestSlotsBetween(t *testing.T) {
	now := time.Now().UTC()
	s := 5 * time.Minute
	if n := slotsBetween("r", s, now, now); n != 0 {
		t.Errorf("no time: %d slots", n)
	}
	if n := slotsBetween("r", s, now, now.Add(-time.Hour)); n != 0 {
		t.Errorf("backwards: %d slots", n)
	}
	start := SlotAt("r", s, now)
	if n := slotsBetween("r", s, start, start.Add(time.Hour)); n != 12 {
		t.Errorf("an hour of 5m slots: %d", n)
	}
}
