// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"errors"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

// eventMonth is the monthly index of an event category for month m of 2026.
func eventMonth(cat string, m time.Month, bytes int64) IndexInfo {
	name := datamodel.MonthIndexName("signalith", cat, datamodel.MonthOf(time.Date(2026, m, 1, 0, 0, 0, 0, time.UTC)))
	return IndexInfo{Name: name, Bytes: bytes, Docs: 10, Segments: 4, Copies: 1, UUID: "u-" + name}
}

func TestParseEventMonth(t *testing.T) {
	cat, day, ok := ParseIndex("signalith", "signalith-network_traffic-2026.07")
	if !ok || cat != "network_traffic" || !day.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("ParseIndex = %q %v %v", cat, day, ok)
	}
	if !EventMonth("signalith", "signalith-network_traffic-2026.07") {
		t.Error("EventMonth: a month of events not seen")
	}
	for _, name := range []string{
		"signalith-network_traffic-2026.07.01", // a day
		"signalith-network_traffic-2026.13",
		"signalith-network_traffic-2026.7",
		"signalith-network_traffic-2026.07-2", // months have no parts
		"signalith-nope-2026.07",
		"signalith_audit-2026.07", // records, not events
		"other-network_traffic-2026.07",
	} {
		if EventMonth("signalith", name) {
			t.Errorf("EventMonth(%s) = true", name)
		}
	}
	for _, name := range []string{"signalith-nope-2026.07", "signalith-network_traffic-2026.13", "signalith-network_traffic-2026.07-2"} {
		if _, _, ok := ParseIndex("signalith", name); ok {
			t.Errorf("ParseIndex(%s) accepted it", name)
		}
	}
	// A cold snapshot of a month, and a day's own name, which is no
	// snapshot's.
	if ix, ok := coldIndex("signalith", "signalith-authentication-2026.07.abc123"); !ok || ix != "signalith-authentication-2026.07" {
		t.Errorf("coldIndex of a month = %q %v", ix, ok)
	}
	if ix, ok := coldIndex("signalith", "signalith-authentication-2026.07.02"); ok {
		t.Errorf("coldIndex of a day's name = %q", ix)
	}
}

// A month of events counts from its last day: this month is kept, a month
// whose last day is within keep_days is kept, one past it is deleted
// (archived first when the policy archives). Ended months can be
// compacted and are deleted by the size cap and the disk guard like days.
func TestPlanEventMonths(t *testing.T) {
	// testNow is 2026-10-12: with keep_days 90, June (ends 06-30, 104
	// days ago) goes, July (ends 07-31, 73 days ago) stays.
	snap := snapOf(eventMonth("authentication", 6, 100), eventMonth("authentication", 7, 100), eventMonth("authentication", 10, 100), ix("authentication", 1, 10))
	s := noGuard(withPolicy(Effective(Config{Days: 90}, Saved{}), "authentication", Policy{KeepDays: 90, CompactAfterDays: 7}))
	got := byIndex(PlanIndices(snap, s))
	if d := got["signalith-authentication-2026.06"]; d.Action != ActionDelete || d.Rule != RuleKeepDays || d.Category != "authentication" || d.Day != "2026-06-01" {
		t.Errorf("June: %+v", d)
	}
	if d := got["signalith-authentication-2026.07"]; d.Action != ActionCompact {
		t.Errorf("July: %+v, want compacted", d)
	}
	if d := got["signalith-authentication-2026.10"]; d.Action != ActionKeep || d.Reason != "This month's events" {
		t.Errorf("October: %+v", d)
	}

	s = withPolicy(s, "authentication", Policy{KeepDays: 90, Archive: true})
	if d := byIndex(PlanIndices(snap, s))["signalith-authentication-2026.06"]; d.Action != ActionArchive {
		t.Errorf("June with archive: %+v", d)
	}

	// The disk guard deletes ended months, oldest first, never this one.
	s = Effective(Config{Days: 0}, Saved{})
	full := snapOf(eventMonth("authentication", 7, 300), eventMonth("authentication", 8, 300), eventMonth("authentication", 10, 300))
	full.Disk = &Disk{Node: "n", Total: 1000, Available: 100}
	got = byIndex(PlanIndices(full, s))
	if got["signalith-authentication-2026.07"].Rule != RuleGuard || got["signalith-authentication-2026.10"].Action != ActionKeep {
		t.Errorf("guard: July %+v, October %+v", got["signalith-authentication-2026.07"], got["signalith-authentication-2026.10"])
	}
}

// Retention never deletes, compacts or moves a month of events before
// its last day has passed.
func TestApplyRefusesTheCurrentEventMonth(t *testing.T) {
	f := newFixture(t, Config{})
	now := f.m.now()
	first := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	name := datamodel.MonthIndexName("signalith", "authentication", datamodel.MonthOf(now))
	for _, a := range []string{ActionDelete, ActionCompact, ActionCold} {
		d := Decision{Index: name, Category: "authentication", Day: first.Format(time.DateOnly), Action: a, Snapshot: "s"}
		if act := f.m.apply(t.Context(), d, startOfDay(now)); act.Error == "" {
			t.Errorf("%s the current month: %+v", a, act)
		}
	}
}

func TestPolicyByMonth(t *testing.T) {
	for _, c := range []struct {
		p    Policy
		want bool
	}{
		{Policy{KeepDays: 90}, true},
		{Policy{}, true}, // forever
		{Policy{KeepDays: 30}, false},
		{Policy{KeepDays: 31, CompactAfterDays: 2, Archive: true}, true},
		{Policy{KeepDays: 90, MaxSizeGB: 10}, false},
		{Policy{KeepDays: 90, ColdAfterDays: 14}, false},
		{Policy{KeepDays: 90, ColdAfterDays: 45}, true},
	} {
		if got := c.p.ByMonth(); got != c.want {
			t.Errorf("%+v: ByMonth %v, want %v", c.p, got, c.want)
		}
	}
}

// ByMonthFunc follows each category's policy, stores models without an
// event category and every model before settings could be read by day,
// and reads the settings at most every ByMonthCheck.
func TestByMonthFunc(t *testing.T) {
	reads := 0
	var err error = errors.New("settings file has errors")
	s := withPolicy(Effective(Config{Days: 90}, Saved{}), "web", Policy{KeepDays: 14})
	f := ByMonthFunc(func() (Settings, error) { reads++; return s, err })
	if f("Authentication") {
		t.Error("stored by month before settings were read")
	}
	f = ByMonthFunc(func() (Settings, error) { reads++; return s, nil })
	reads = 0
	if !f("Authentication") || f("Web") || f("Nope") || f("Audit") {
		t.Errorf("Authentication %v, Web %v, Nope %v, Audit %v", f("Authentication"), f("Web"), f("Nope"), f("Audit"))
	}
	if reads != 1 {
		t.Errorf("settings read %d times", reads)
	}
}

// A run archives and deletes a month of events past keep_days and keeps
// this one; the overview counts each day a month holds, up to today.
func TestRunArchivesOldEventMonths(t *testing.T) {
	f := newFixture(t, Config{})
	old := datamodel.MonthIndexName("signalith", "authentication", "2026.06")
	cur := datamodel.MonthIndexName("signalith", "authentication", datamodel.MonthOf(testNow))
	f.mem.AddIndex(old, 100, testDocs(3)...)
	f.mem.AddIndex(cur, 100, testDocs(3)...)
	if err := f.m.SetPolicy("authentication", &Policy{KeepDays: 90, Archive: true}); err != nil {
		t.Fatal(err)
	}
	run, err := f.m.Run(t.Context(), TriggerManual, "")
	if err != nil {
		t.Fatal(err)
	}
	if run.Archived != 1 || f.exists(old) || !f.exists(cur) {
		t.Fatalf("run = %+v, old there %v, current there %v", run, f.exists(old), f.exists(cur))
	}
	for _, c := range f.m.Overview(t.Context()).Categories {
		// testNow is 2026-10-12: twelve days of October.
		if c.ID == "authentication" && (c.Days != 12 || c.OldestDay != "2026-10-01" || c.NewestDay != "2026-10-12") {
			t.Errorf("authentication row = %+v", c)
		}
	}
}
