package retention

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

var testNow = time.Date(2026, 10, 12, 15, 0, 0, 0, time.UTC)

func dayAgo(n int) time.Time { return testNow.AddDate(0, 0, -n) }

func ix(cat string, ago int, bytes int64) IndexInfo {
	return IndexInfo{Name: IndexName("signalith", cat, dayAgo(ago)), Bytes: bytes, Docs: 10, Segments: 4, Copies: 1}
}

func snapOf(ixs ...IndexInfo) Snapshot {
	return Snapshot{Now: testNow, Prefix: "signalith", Indices: ixs}
}

func byIndex(p *Plan) map[string]Decision {
	out := map[string]Decision{}
	for _, d := range p.Decisions {
		out[d.Index] = d
	}
	return out
}

func withPolicy(s Settings, id string, p Policy) Settings {
	s = s.clone()
	s.Policies[id], s.Sources[id] = p, SourceUI
	return s
}

func noGuard(s Settings) Settings {
	off := false
	s.Guard.Enabled = &off
	return s
}

func TestParseIndex(t *testing.T) {
	day := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	for _, m := range datamodel.Models {
		name := datamodel.IndexName("signalith", m.Name, "2026.07.12")
		if got := IndexName("signalith", strings.ToLower(m.Name), day); got != name {
			t.Errorf("IndexName(%s) = %s, ingest writes %s", m.Name, got, name)
		}
		cat, d, ok := ParseIndex("signalith", name)
		if !ok || cat != strings.ToLower(m.Name) || !d.Equal(day) {
			t.Errorf("ParseIndex(%s) = %q %v %v", name, cat, d, ok)
		}
	}
	for _, name := range []string{
		"signalith_findings",
		"signalith_cases",
		"signalith-lab-authentication-2026.07.12", // another install's prefix
		"signalith-syslog-2026.07.12",             // unknown category
		"signalith-authentication-2026.13.01",     // not a date
		"signalith-authentication-2026.7.12",
		"signalith-authentication-2026.07.12-old",
		"signalith-authentication",
		"other-authentication-2026.07.12",
		"signalithx-authentication-2026.07.12",
		"signalith-findings-2026.07.12", // findings are not daily
	} {
		if cat, _, ok := ParseIndex("signalith", name); ok {
			t.Errorf("ParseIndex(%s) accepted it as %s", name, cat)
		}
	}
	if _, _, ok := ParseIndex("sig", "signalith-authentication-2026.07.12"); ok {
		t.Error("prefix sig must not match signalith- indices")
	}
}

// expiredBefore is the retention rule before policies existed: delete
// indices whose date is before today minus days.
func expiredBefore(indices []string, days int, now time.Time) []string {
	if days <= 0 {
		return nil
	}
	cutoff := now.UTC().AddDate(0, 0, -days).Truncate(24 * time.Hour)
	re := regexp.MustCompile(`-(\d{4}\.\d{2}\.\d{2})$`)
	var out []string
	for _, name := range indices {
		m := re.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		day, err := time.Parse("2006.01.02", m[1])
		if err == nil && day.Before(cutoff) {
			out = append(out, name)
		}
	}
	return out
}

func TestKeepDaysMatchesRetentionDays(t *testing.T) {
	var ixs []IndexInfo
	var names []string
	for _, cat := range []string{"authentication", "endpoint", "network_traffic", "change", "malware", "risk", "other"} {
		for ago := -2; ago < 200; ago += 3 {
			i := ix(cat, ago, 100)
			ixs = append(ixs, i)
			names = append(names, i.Name)
		}
	}
	for _, days := range []int{0, 1, 7, 30, 90, 365} {
		plan := PlanIndices(snapOf(ixs...), noGuard(Effective(Config{Days: days}, Saved{})))
		var got []string
		for _, d := range plan.Decisions {
			if d.Removes() {
				got = append(got, d.Index)
				if d.Action != ActionDelete || d.Rule != RuleKeepDays || d.Source != SourceDefault {
					t.Errorf("days=%d %s: %+v", days, d.Index, d)
				}
			}
		}
		want := expiredBefore(names, days, testNow)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("days=%d: deleted %d indices, the old rule deletes %d\ngot  %v\nwant %v", days, len(got), len(want), got, want)
		}
	}
	// 90 days keeps today and the 90 days before it.
	plan := PlanIndices(snapOf(ix("endpoint", 90, 1), ix("endpoint", 91, 1)), noGuard(Effective(Config{Days: 90}, Saved{})))
	d := byIndex(plan)
	if d[ix("endpoint", 90, 1).Name].Action != ActionKeep || d[ix("endpoint", 91, 1).Name].Action != ActionDelete {
		t.Errorf("decisions = %+v", plan.Decisions)
	}
	if got := d[ix("endpoint", 91, 1).Name].Reason; got != "Older than 90 days" {
		t.Errorf("reason = %q", got)
	}
}

func TestTodayAndFutureAreNeverDeleted(t *testing.T) {
	s := withPolicy(Effective(Config{Days: 1}, Saved{}), "endpoint", Policy{KeepDays: 1, MaxSizeGB: 0.000001, CompactAfterDays: 1})
	snap := snapOf(ix("endpoint", 0, 5*GB), ix("endpoint", -1, 5*GB), ix("endpoint", -400, 5*GB), ix("authentication", 0, 5*GB))
	// The disk is full too.
	snap.Disk = &Disk{Total: 21 * GB, Available: 0}
	plan := PlanIndices(snap, s)
	for _, d := range plan.Decisions {
		if d.Action != ActionKeep {
			t.Errorf("%s: %s (%s)", d.Index, d.Action, d.Reason)
		}
	}
	if plan.Guard.State != GuardShort {
		t.Errorf("guard = %+v", plan.Guard)
	}
	if len(plan.Notes) != 2 {
		t.Errorf("notes = %q", plan.Notes)
	}
}

func TestUnknownIndicesAreSkipped(t *testing.T) {
	names := []string{"signalith-lab-authentication-2020.01.01", "signalith-syslog-2020.01.01", "signalith-authentication-2020.13.01"}
	var ixs []IndexInfo
	for _, n := range names {
		ixs = append(ixs, IndexInfo{Name: n, Bytes: 100 * GB, Docs: 1})
	}
	snap := snapOf(ixs...)
	snap.Disk = &Disk{Total: 100 * GB, Available: 0}
	plan := PlanIndices(snap, Effective(Config{Days: 1}, Saved{}))
	for _, d := range plan.Decisions {
		if d.Action != ActionSkip || d.Category != "" {
			t.Errorf("%s: %+v", d.Index, d)
		}
	}
	if len(plan.Steps()) != 0 {
		t.Errorf("steps = %+v", plan.Steps())
	}
}

func TestSizeCapDeletesOldestDaysFirst(t *testing.T) {
	var ixs []IndexInfo
	for ago := 0; ago < 10; ago++ {
		ixs = append(ixs, ix("endpoint", ago, GB), ix("authentication", ago, GB))
	}
	s := noGuard(withPolicy(Effective(Config{Days: 0}, Saved{}), "endpoint", Policy{MaxSizeGB: 4.5}))
	plan := PlanIndices(snapOf(ixs...), s)
	var deleted []int
	for _, d := range plan.Decisions {
		if d.Removes() {
			if d.Category != "endpoint" || d.Rule != RuleSizeCap || d.Reason != "Endpoint is over its 4.5 GB size cap" {
				t.Errorf("%+v", d)
			}
			deleted = append(deleted, int(startOfDay(testNow).Sub(mustDay(t, d.Day)).Hours()/24))
		}
	}
	// 10 GB down to at most 4.5 GB: the six oldest days go, oldest first.
	if !slices.Equal(deleted, []int{9, 8, 7, 6, 5, 4}) {
		t.Errorf("deleted ages %v", deleted)
	}
	steps := plan.Steps()
	if len(steps) != 6 || steps[0].Index != ix("endpoint", 9, 0).Name {
		t.Errorf("steps = %+v", steps)
	}
	// keep_days deletions count toward the cap.
	s = noGuard(withPolicy(s, "endpoint", Policy{KeepDays: 7, MaxSizeGB: 6}))
	plan = PlanIndices(snapOf(ixs...), s)
	var rules []string
	for _, d := range plan.Steps() {
		rules = append(rules, d.Rule)
	}
	if !slices.Equal(rules, []string{RuleKeepDays, RuleKeepDays, RuleSizeCap, RuleSizeCap}) {
		t.Errorf("rules = %v", rules)
	}
}

func mustDay(t *testing.T, s string) time.Time {
	t.Helper()
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestGuardDeletesOldestDaysAcrossCategories(t *testing.T) {
	ixs := []IndexInfo{
		ix("endpoint", 30, 2*GB), ix("authentication", 30, 3*GB), // same day: the bigger goes first
		ix("change", 29, 1*GB),
		ix("endpoint", 8, 4*GB),
		ix("endpoint", 7, 50*GB), // protected by min_days
		ix("endpoint", 0, 50*GB),
	}
	restored := ix("risk", 100, 10*GB)
	restored.RestoredUntil = "2026-10-20"
	ixs = append(ixs, restored)
	snap := snapOf(ixs...)
	// 100 GB disk, 90% used: 5 GB must go to get under 85%.
	snap.Disk = &Disk{Total: 100 * GB, Available: 10 * GB}
	s := Effective(Config{Days: 0}, Saved{})
	plan := PlanIndices(snap, s)
	var got []string
	for _, d := range plan.Steps() {
		got = append(got, d.Index)
		if d.Rule != RuleGuard || d.Source != SourceBuiltin || !strings.Contains(d.Reason, "above the 85% disk guard") {
			t.Errorf("%+v", d)
		}
	}
	want := []string{ix("authentication", 30, 0).Name, ix("endpoint", 30, 0).Name}
	if !slices.Equal(got, want) {
		t.Errorf("guard deleted %v, want %v", got, want)
	}
	if g := plan.Guard; g.State != GuardOver || g.NeedBytes != 5*GB || g.PlannedBytes != 5*GB || g.PlannedDays != 2 || g.Percent != 90 {
		t.Errorf("guard = %+v", g)
	}

	// When the days it may delete cannot get the disk under the limit, the
	// guard only deletes to stay below OpenSearch's flood stage: 100% used,
	// 15 GB needed, 10 GB deletable; 6 GB gets it to 94%.
	snap.Disk = &Disk{Total: 100 * GB, Available: 0}
	plan = PlanIndices(snap, s)
	if len(plan.Steps()) != 3 || plan.Guard.State != GuardShort || plan.Guard.CanFreeBytes != 10*GB || plan.Guard.PlannedBytes != 6*GB ||
		!strings.Contains(plan.Guard.Message, "deletes only the oldest 3 days, enough to keep the disk below 95%") {
		t.Errorf("steps = %d, guard = %+v", len(plan.Steps()), plan.Guard)
	}
	for _, d := range plan.Steps() {
		if d.Index == ix("endpoint", 7, 0).Name || d.Index == restored.Name {
			t.Errorf("guard deleted a protected day: %s", d.Index)
		}
	}

	// A smaller min_days lets the guard go further.
	s.Guard.MinDays = 3
	plan = PlanIndices(snap, s)
	if len(plan.Steps()) != 5 {
		t.Errorf("min_days 3: steps = %+v", plan.Steps())
	}

	// Policy deletions count first.
	snap.Disk = &Disk{Total: 100 * GB, Available: 10 * GB}
	s = Effective(Config{Days: 20}, Saved{})
	plan = PlanIndices(snap, s)
	for _, d := range plan.Steps() {
		if d.Rule != RuleKeepDays {
			t.Errorf("%+v", d)
		}
	}
	if plan.Guard.State != GuardOver || plan.Guard.PlannedDays != 0 || !strings.Contains(plan.Guard.Message, "policies' own deletions") {
		t.Errorf("guard = %+v", plan.Guard)
	}
}

func TestGuardStates(t *testing.T) {
	s := Effective(Config{Days: 0}, Saved{})
	snap := snapOf(ix("endpoint", 30, GB))
	if g := PlanIndices(snap, s).Guard; g.State != GuardUnknown {
		t.Errorf("no disk: %+v", g)
	}
	snap.Disk = &Disk{Total: 100 * GB, Available: 50 * GB}
	if g := PlanIndices(snap, s).Guard; g.State != GuardOK || g.Percent != 50 || g.Threshold != 85 || g.MinDays != 7 {
		t.Errorf("half full: %+v", g)
	}
	snap.Disk = &Disk{Total: 100 * GB, Available: 0}
	p := PlanIndices(snap, noGuard(s))
	if p.Guard.State != GuardOff || len(p.Steps()) != 0 {
		t.Errorf("off: %+v %v", p.Guard, p.Steps())
	}
}

func TestCompaction(t *testing.T) {
	done := ix("endpoint", 20, GB)
	done.WriteBlocked, done.Segments = true, 1
	blockedNotMerged := ix("endpoint", 21, GB)
	blockedNotMerged.WriteBlocked = true
	restored := ix("endpoint", 22, GB)
	restored.RestoredUntil = "2026-10-12"
	snap := snapOf(ix("endpoint", 0, GB), ix("endpoint", 1, GB), ix("endpoint", 2, GB), ix("endpoint", 8, GB), done, blockedNotMerged, restored,
		ix("endpoint", 40, GB), ix("authentication", 20, GB))
	s := noGuard(withPolicy(Effective(Config{Days: 0}, Saved{}), "endpoint", Policy{KeepDays: 30, CompactAfterDays: 7}))
	plan := PlanIndices(snap, s)
	d := byIndex(plan)
	want := map[string]string{
		ix("endpoint", 0, 0).Name: ActionKeep, ix("endpoint", 1, 0).Name: ActionKeep, ix("endpoint", 2, 0).Name: ActionKeep,
		ix("endpoint", 8, 0).Name: ActionCompact, done.Name: ActionKeep, blockedNotMerged.Name: ActionCompact,
		restored.Name: ActionKeep, ix("endpoint", 40, 0).Name: ActionDelete, ix("authentication", 20, 0).Name: ActionKeep,
	}
	for name, act := range want {
		if d[name].Action != act {
			t.Errorf("%s: %s (%s), want %s", name, d[name].Action, d[name].Reason, act)
		}
	}
	if r := d[ix("endpoint", 8, 0).Name]; r.Rule != RuleCompact || r.Reason != "Older than 7 days" {
		t.Errorf("compact decision = %+v", r)
	}
	// Deletions come before compactions.
	steps := plan.Steps()
	if len(steps) != 3 || steps[0].Action != ActionDelete {
		t.Errorf("steps = %+v", steps)
	}
	// compact_after_days 1 never touches today or yesterday.
	s = noGuard(withPolicy(s, "endpoint", Policy{CompactAfterDays: 1}))
	d = byIndex(PlanIndices(snapOf(ix("endpoint", 0, GB), ix("endpoint", 1, GB), ix("endpoint", 2, GB)), s))
	if d[ix("endpoint", 0, 0).Name].Action != ActionKeep || d[ix("endpoint", 1, 0).Name].Action != ActionKeep ||
		d[ix("endpoint", 2, 0).Name].Action != ActionCompact {
		t.Errorf("decisions = %+v", d)
	}
}

func TestRestoredIndicesAreKeptUntilTheirDay(t *testing.T) {
	keep := ix("endpoint", 300, GB)
	keep.RestoredUntil = "2026-10-12" // today: still kept
	gone := ix("endpoint", 301, GB)
	gone.RestoredUntil = "2026-10-11"
	plan := PlanIndices(snapOf(keep, gone), Effective(Config{Days: 90}, Saved{}))
	d := byIndex(plan)
	if d[keep.Name].Action != ActionKeep || d[keep.Name].Reason != "Restored from the archive; kept until 2026-10-12" {
		t.Errorf("restored: %+v", d[keep.Name])
	}
	if d[gone.Name].Action != ActionDelete {
		t.Errorf("expired restore: %+v", d[gone.Name])
	}
}

func TestArchiveBeforeDeleting(t *testing.T) {
	a, b, empty := ix("endpoint", 100, GB), ix("endpoint", 101, GB), ix("endpoint", 102, GB)
	b.UUID = "uuid-b"
	empty.Docs = 0
	snap := snapOf(a, b, empty)
	snap.Archives = map[string][]Manifest{b.Name: {{ID: b.Name, Index: b.Name, IndexUUID: "uuid-b", Docs: 10}}}
	s := noGuard(withPolicy(Effective(Config{Days: 90}, Saved{}), "endpoint", Policy{KeepDays: 90, Archive: true}))
	d := byIndex(PlanIndices(snap, s))
	if d[a.Name].Action != ActionArchive || d[a.Name].Source != SourceUI {
		t.Errorf("not archived yet: %+v", d[a.Name])
	}
	if d[b.Name].Action != ActionDelete || !strings.HasSuffix(d[b.Name].Reason, "(already archived)") {
		t.Errorf("already archived: %+v", d[b.Name])
	}
	if d[empty.Name].Action != ActionDelete {
		t.Errorf("empty: %+v", d[empty.Name])
	}
	sum := Summarize(PlanIndices(snap, s).Steps(), nil)
	if sum.DeleteDays != 3 || sum.ArchiveDays != 1 || sum.DeleteBytes != 3*GB || !slices.Equal(sum.Categories, []string{"endpoint"}) {
		t.Errorf("summary = %+v", sum)
	}
}

func TestSettingsPrecedence(t *testing.T) {
	cfg := Config{Days: 90, Policies: map[string]Policy{"endpoint": {KeepDays: 30}}}
	saved := Saved{
		Default:  &Policy{KeepDays: 60, CompactAfterDays: 7},
		Policies: map[string]Policy{"endpoint": {KeepDays: 5}, "change": {KeepDays: 400, Archive: true}, Findings: {KeepDays: 365}},
	}
	s := Effective(cfg, saved)
	check := func(id string, keep int, src string) {
		t.Helper()
		p, got := s.For(id)
		if p.KeepDays != keep || got != src {
			t.Errorf("%s: keep %d from %s, want %d from %s", id, p.KeepDays, got, keep, src)
		}
	}
	check("endpoint", 30, SourceConfig)
	check("change", 400, SourceUI)
	check("authentication", 60, SourceDefault)
	check(Findings, 365, SourceUI)
	check(Cases, 0, SourceDefault)
	check(Intel, 0, SourceFeeds)
	if s.DefaultSource != SourceUI || s.GuardSource != SourceBuiltin || !s.Guard.IsEnabled() || s.Guard.MaxDiskPercent != 85 {
		t.Errorf("settings = %+v", s)
	}
	// retention.days is the default until one is saved; a configured
	// default wins over both.
	if s := Effective(Config{Days: 90}, Saved{}); s.Default.KeepDays != 90 || s.DefaultSource != SourceDays {
		t.Errorf("days: %+v", s)
	}
	off := false
	s = Effective(Config{Days: 90, Default: &Policy{KeepDays: 10}, Guard: &Guard{Enabled: &off}, Policies: cfg.Policies}, saved)
	if s.Default.KeepDays != 10 || s.DefaultSource != SourceConfig || s.Guard.IsEnabled() || s.GuardSource != SourceConfig {
		t.Errorf("config default: %+v", s)
	}

	// Changes check where a setting comes from.
	if _, err := s.apply(Change{Category: "endpoint", Policy: &Policy{KeepDays: 1}}); err != ErrFromConfig {
		t.Errorf("config category: %v", err)
	}
	if _, err := s.apply(Change{Default: &Policy{KeepDays: 1}}); err != ErrFromConfig {
		t.Errorf("config default: %v", err)
	}
	if _, err := s.apply(Change{Category: Intel, Policy: &Policy{}}); err != ErrManaged {
		t.Errorf("intel: %v", err)
	}
	if _, err := s.apply(Change{Category: "nope", Policy: &Policy{}}); err != ErrUnknownCategory {
		t.Errorf("unknown: %v", err)
	}
	if _, err := s.apply(Change{}); err == nil {
		t.Error("empty change accepted")
	}
	next, err := s.apply(Change{Category: "change"})
	if err != nil {
		t.Fatal(err)
	}
	if p, src := next.For("change"); p.KeepDays != 10 || src != SourceDefault {
		t.Errorf("reset: %+v %s", p, src)
	}
	if p, _ := s.For("change"); p.KeepDays != 400 {
		t.Error("apply changed the original settings")
	}
}

func TestPolicyProblems(t *testing.T) {
	for _, tc := range []struct {
		p    Policy
		kind string
		want string
	}{
		{Policy{KeepDays: 90, MaxSizeGB: 50, CompactAfterDays: 7, Archive: true}, KindEvents, ""},
		{Policy{}, KindEvents, ""},
		{Policy{CompactAfterDays: 30}, KindEvents, ""}, // kept forever, compacted after 30 days
		{Policy{KeepDays: -1}, KindEvents, "keep_days cannot be negative"},
		{Policy{KeepDays: MaxKeepDays + 1}, KindEvents, "keep_days must be at most"},
		{Policy{MaxSizeGB: -1}, KindEvents, "max_size_gb cannot be negative"},
		{Policy{KeepDays: 7, CompactAfterDays: 7}, KindEvents, "compact_after_days must be less than keep_days"},
		{Policy{CompactAfterDays: -2}, KindEvents, "compact_after_days cannot be negative"},
		{Policy{KeepDays: 365}, KindRecords, ""},
		{Policy{KeepDays: 365, Archive: true}, KindRecords, "only use keep_days"},
		{Policy{}, KindManaged, "max_age"},
	} {
		got := strings.Join(tc.p.Problems(tc.kind), "; ")
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%+v %s: %q, want %q", tc.p, tc.kind, got, tc.want)
		}
	}
	for _, tc := range []struct {
		g    Guard
		want string
	}{
		{Guard{}, ""},
		{Guard{MaxDiskPercent: 80, MinDays: 3}, ""},
		{Guard{MaxDiskPercent: 95}, "max_disk_percent must be between 50 and 94"},
		{Guard{MaxDiskPercent: 20}, "max_disk_percent"},
		{Guard{MinDays: -1}, "min_days"},
	} {
		got := strings.Join(tc.g.Problems(), "; ")
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%+v: %q, want %q", tc.g, got, tc.want)
		}
	}
	cfg := Config{Policies: map[string]Policy{"nope": {}, Intel: {}, "endpoint": {KeepDays: -1}}, Default: &Policy{MaxSizeGB: -1}, Guard: &Guard{MaxDiskPercent: 99}}
	got := strings.Join(cfg.Problems(), "\n")
	for _, want := range []string{"retention.policies.nope: unknown category", "retention.policies.intel:", "retention.policies.endpoint.keep_days",
		"retention.default.max_size_gb", "retention.guard.max_disk_percent"} {
		if !strings.Contains(got, want) {
			t.Errorf("config problems miss %q:\n%s", want, got)
		}
	}
}

func TestCategories(t *testing.T) {
	var ids, names []string
	for _, c := range Categories() {
		ids = append(ids, c.ID)
		names = append(names, c.Name)
	}
	if !slices.Equal(ids, []string{"authentication", "endpoint", "network_traffic", "change", "malware", "filesystem", "registry", "network_resolution", "image_load", "script", "inventory", "configuration_check", "alerts", "other", "risk", Findings, Cases, Intel}) {
		t.Errorf("ids = %v", ids)
	}
	if n := len(names); names[2] != "Network traffic" || names[4] != "Malware" || names[n-5] != "Other events" || names[n-4] != "Risk events" || names[n-2] != "Investigations" {
		t.Errorf("names = %v", names)
	}
}
