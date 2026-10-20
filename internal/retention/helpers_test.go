// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package retention

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// apply re-checks every decision itself, so a planner bug cannot delete
// what retention must never touch.
func TestApplyRefusesWhatMustNeverChange(t *testing.T) {
	f := newFixture(t, Config{Days: 30})
	today := startOfDay(testNow)
	day := func(ago int) string { return IndexName("signalith", "endpoint", dayAgo(ago)) }
	month := MonthlyIndexName("signalith", Audit, testNow)
	for _, c := range []struct {
		name string
		d    Decision
		want string
	}{
		{"another prefix", Decision{Index: "other-endpoint-2026.01.01", Category: "endpoint", Action: ActionDelete}, "not a Signalith daily or monthly index"},
		{"wrong category", Decision{Index: day(40), Category: "authentication", Action: ActionDelete}, "not a Signalith daily or monthly index"},
		{"today", Decision{Index: day(0), Category: "endpoint", Action: ActionDelete}, "today's and future days are never deleted"},
		{"this month", Decision{Index: month, Category: Audit, Action: ActionArchive}, "the current month is never deleted"},
		{"compact yesterday", Decision{Index: day(1), Category: "endpoint", Action: ActionCompact}, "today and yesterday are never compacted"},
		{"cold yesterday", Decision{Index: day(1), Category: "endpoint", Action: ActionCold}, "never move to cold storage"},
		{"mount without snapshot", Decision{Index: day(40), Category: "endpoint", Action: ActionMount}, "no cold storage snapshot named"},
	} {
		act := f.m.apply(context.Background(), c.d, today)
		if !strings.Contains(act.Error, c.want) {
			t.Errorf("%s: %q, want %q", c.name, act.Error, c.want)
		}
	}
	if len(f.mem.Calls) != 0 {
		t.Errorf("calls = %v", f.mem.Calls)
	}
}

func TestReadHistoryFile(t *testing.T) {
	dir := t.TempDir()
	if run, acts, err := ReadHistoryFile(filepath.Join(dir, "none.json")); run != nil || acts != nil || err != nil {
		t.Errorf("missing file: %v %v %v", run, acts, err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadHistoryFile(bad); err == nil || !strings.Contains(err.Error(), "is not a retention history") {
		t.Errorf("bad file: %v", err)
	}
	if _, _, err := ReadHistoryFile(dir); err == nil {
		t.Error("a folder read as a history")
	}

	// A run's history reads back.
	f := newFixture(t, Config{Days: 30})
	f.add("endpoint", 40, GB, 1)
	if _, err := f.m.Run(context.Background(), TriggerManual, "admin"); err != nil {
		t.Fatal(err)
	}
	run, acts, err := ReadHistoryFile(f.m.HistoryFile)
	if err != nil || run == nil || run.Deleted != 1 || len(acts) != 1 || acts[0].Action != ActionDelete || acts[0].By != "admin" {
		t.Errorf("history = %+v %+v %v", run, acts, err)
	}
}

func TestDecisionAndPolicyHelpers(t *testing.T) {
	for a, want := range map[string]bool{ActionCompact: true, ActionArchive: true, ActionDelete: true, ActionCold: true, ActionMount: true, "keep": false, "": false} {
		if got := (Decision{Action: a}).Changes(); got != want {
			t.Errorf("Changes(%q) = %v", a, got)
		}
	}
	for _, c := range []struct {
		p    Policy
		want bool
	}{{Policy{}, false}, {Policy{KeepDays: 1}, true}, {Policy{MaxSizeGB: 1}, true}, {Policy{CompactAfterDays: 3}, false}} {
		if got := c.p.Deletes(); got != c.want {
			t.Errorf("%+v.Deletes() = %v", c.p, got)
		}
	}
	if (&ConfirmError{Check: &RestoreCheck{Message: "confirm"}}).Error() != "confirm" {
		t.Error("ConfirmError")
	}
	if got := (&ReadOnlyError{}).Error(); !strings.Contains(got, "no server runs the background jobs") {
		t.Errorf("ReadOnlyError = %q", got)
	}
	if got := (&ReadOnlyError{Holder: "node-b"}).Error(); !strings.Contains(got, "node-b runs it") {
		t.Errorf("ReadOnlyError = %q", got)
	}

	// Defaults of a manager without a clock or interval.
	var m Manager
	if time.Since(m.now()) > time.Minute || m.interval() != DefaultInterval {
		t.Errorf("defaults: %v %v", m.now(), m.interval())
	}
	m.Interval = time.Hour
	if m.interval() != time.Hour {
		t.Errorf("interval = %v", m.interval())
	}
}
