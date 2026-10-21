// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package findings

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

// TestOrdersPageThroughEveryFinding: each order pages through every
// finding once, two at a time, in the order a single search returns.
func TestOrdersPageThroughEveryFinding(t *testing.T) {
	m := NewMemory()
	now := time.Now().UTC().Truncate(time.Millisecond)
	urg := []string{"low", "critical", "high", "low", "medium", "critical", ""}
	for i, u := range urg {
		f := &Finding{ID: fmt.Sprintf("f%d", i), Title: "x", Severity: "high", Urgency: u, Status: StatusNew,
			Created: now.Add(-time.Duration(i%4) * time.Minute)}
		if i == 2 {
			f.Owner = "alice"
		}
		if err := m.Create(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(l []*Finding) []string {
		var out []string
		for _, f := range l {
			out = append(out, f.ID)
		}
		return out
	}
	for _, o := range append(Orders, "") {
		all, total, _ := m.Search(context.Background(), Filter{Order: o})
		if total != len(urg) || len(all) != len(urg) {
			t.Fatalf("%q: %d of %d", o, len(all), total)
		}
		var paged []*Finding
		var after *Cursor
		for range len(urg) {
			page, total, _ := m.Search(context.Background(), Filter{Order: o, Limit: 2, After: after})
			if total != len(urg) {
				t.Fatalf("%q: total %d on a later page", o, total)
			}
			if len(page) == 0 {
				break
			}
			paged = append(paged, page...)
			c, err := DecodeCursor(CursorOf(page[len(page)-1]).Encode())
			if err != nil {
				t.Fatal(err)
			}
			after = c
		}
		if !slices.Equal(ids(paged), ids(all)) {
			t.Errorf("%q: paged %v, whole %v", o, ids(paged), ids(all))
		}
	}
	top, _, _ := m.Search(context.Background(), Filter{Order: OrderUrgency})
	if r := UrgencyRank(top[0].EffectiveUrgency()); r != 4 || UrgencyRank(top[len(top)-1].EffectiveUrgency()) != 1 {
		t.Errorf("by urgency %v", ids(top))
	}
	if l, _, _ := m.Search(context.Background(), Filter{Unowned: true}); len(l) != len(urg)-1 || slices.Contains(ids(l), "f2") {
		t.Errorf("unowned %v", ids(l))
	}
}

func TestDecodeCursorRefusesWhatEncodeDidNotWrite(t *testing.T) {
	for _, s := range []string{"", "!!", "e30", "eyJjIjoxLCJpIjoiYSBiIn0", "eyJyIjo5LCJjIjoxLCJpIjoiYSJ9"} {
		if _, err := DecodeCursor(s); err == nil {
			t.Errorf("%q was read", s)
		}
	}
	c := Cursor{Rank: 3, Created: 1, ID: "20261020-a"}
	if got, err := DecodeCursor(c.Encode()); err != nil || *got != c {
		t.Errorf("%v %v", got, err)
	}
}
