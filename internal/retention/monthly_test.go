package retention

import (
	"testing"
	"time"
)

func monthIx(month time.Time, bytes int64) IndexInfo {
	return IndexInfo{Name: MonthlyIndexName("signalith", Audit, month), Bytes: bytes, Docs: 10, Segments: 4, Copies: 1, UUID: "u-" + month.Format("200601")}
}

func TestParseMonthlyIndex(t *testing.T) {
	cat, day, ok := ParseIndex("signalith", "signalith_audit-2026.07")
	if !ok || cat != Audit || !day.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("ParseIndex(signalith_audit-2026.07) = %q %v %v", cat, day, ok)
	}
	if got := MonthlyIndexName("signalith", Audit, time.Date(2026, 7, 31, 23, 0, 0, 0, time.UTC)); got != "signalith_audit-2026.07" {
		t.Errorf("MonthlyIndexName = %s", got)
	}
	for _, name := range []string{
		"signalith_audit-2026.13",
		"signalith_audit-2026.7",
		"signalith_audit-2026.07.01", // not monthly
		"signalith_audit",
		"signalith_findings",
		"signalith_runtime",
		"signalith_authentication-2026.07", // events are daily
		"signalith-audit-2026.07",
		"signalith_lab_audit-2026.07",
	} {
		if cat, _, ok := ParseIndex("signalith", name); ok {
			t.Errorf("ParseIndex(%s) accepted it as %s", name, cat)
		}
	}
}

func TestPlanMonthly(t *testing.T) {
	// testNow is 2026-10-12; with keep_days 100 a month goes once its last
	// day is more than 100 days old: June (ends 06-30, 104 days) goes,
	// July (ends 07-31, 73 days) stays.
	month := func(m time.Month) time.Time { return time.Date(2026, m, 1, 0, 0, 0, 0, time.UTC) }
	snap := snapOf(monthIx(month(6), 100), monthIx(month(7), 100), monthIx(month(10), 100), ix("authentication", 1, 10))
	s := noGuard(withPolicy(Effective(Config{Days: 90}, Saved{}), Audit, Policy{KeepDays: 100}))
	got := byIndex(PlanIndices(snap, s))
	if d := got["signalith_audit-2026.06"]; d.Action != ActionDelete || d.Rule != RuleKeepDays || d.Category != Audit || d.Day != "2026-06-01" {
		t.Errorf("June: %+v", d)
	}
	if d := got["signalith_audit-2026.07"]; d.Action != ActionKeep {
		t.Errorf("July: %+v", d)
	}
	if d := got["signalith_audit-2026.10"]; d.Action != ActionKeep || d.Reason != "This month's records" {
		t.Errorf("October: %+v", d)
	}

	// Archived first when the policy archives.
	s = withPolicy(s, Audit, Policy{KeepDays: 100, Archive: true})
	if d := byIndex(PlanIndices(snap, s))["signalith_audit-2026.06"]; d.Action != ActionArchive {
		t.Errorf("June with archive: %+v", d)
	}

	// The default keeps 400 days; neither the guard nor compaction touches
	// a month.
	s = Effective(Config{Days: 90, Default: &Policy{KeepDays: 90, CompactAfterDays: 2}}, Saved{})
	full := snap
	full.Disk = &Disk{Node: "n", Total: 1000, Available: 10}
	for name, d := range byIndex(PlanIndices(full, s)) {
		if d.Category == Audit && d.Action != ActionKeep {
			t.Errorf("%s: %+v", name, d)
		}
	}
	if p, src := s.For(Audit); p.KeepDays != DefaultAuditKeepDays || src != SourceDefault {
		t.Errorf("default audit policy = %+v %s", p, src)
	}
}

func TestMonthlyPolicyProblems(t *testing.T) {
	if p := (Policy{KeepDays: 30, Archive: true}).Problems(KindMonthly); len(p) != 0 {
		t.Errorf("keep_days and archive: %v", p)
	}
	if p := (Policy{KeepDays: 30, MaxSizeGB: 1, CompactAfterDays: 2}).Problems(KindMonthly); len(p) != 2 {
		t.Errorf("size cap and compaction: %v", p)
	}
}

func TestApplyRefusesTheCurrentMonth(t *testing.T) {
	f := newFixture(t, Config{})
	d := Decision{Index: MonthlyIndexName("signalith", Audit, f.m.now()), Category: Audit,
		Day: time.Date(f.m.now().Year(), f.m.now().Month(), 1, 0, 0, 0, 0, time.UTC).Format(time.DateOnly), Action: ActionDelete}
	if act := f.m.apply(t.Context(), d, startOfDay(f.m.now())); act.Error == "" {
		t.Errorf("deleted the current month: %+v", act)
	}
}

func TestRunArchivesOldMonths(t *testing.T) {
	f := newFixture(t, Config{})
	old := MonthlyIndexName("signalith", Audit, time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC))
	cur := MonthlyIndexName("signalith", Audit, testNow)
	f.mem.AddIndex(old, 100, testDocs(3)...)
	f.mem.AddIndex(cur, 100, testDocs(3)...)
	if err := f.m.SetPolicy(Audit, &Policy{KeepDays: DefaultAuditKeepDays, Archive: true}); err != nil {
		t.Fatal(err)
	}
	run, err := f.m.Run(t.Context(), TriggerManual, "")
	if err != nil {
		t.Fatal(err)
	}
	if run.Archived != 1 || f.exists(old) || !f.exists(cur) {
		t.Fatalf("run = %+v, old there %v, current there %v", run, f.exists(old), f.exists(cur))
	}
	list, _, err := f.m.Archive.List()
	if err != nil || len(list) != 1 || list[0].Index != old || list[0].Category != Audit || list[0].Day != "2025-06-01" {
		t.Fatalf("archives = %+v, %v", list, err)
	}
}
