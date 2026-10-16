package detect

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// windowRunner returns the events whose time falls in each search's window.
type windowRunner struct {
	events  []search.Row
	queries []*query.Query
	fail    error
}

func (w *windowRunner) Execute(ctx context.Context, q *query.Query) (*search.Result, error) {
	if w.fail != nil && len(w.queries) > 0 {
		return nil, w.fail
	}
	w.queries = append(w.queries, q)
	from, _ := time.Parse(time.RFC3339, q.Earliest)
	to, _ := time.Parse(time.RFC3339, q.Latest)
	res := &search.Result{Kind: "events"}
	for _, e := range w.events {
		t, _ := time.Parse(time.RFC3339, e["_time"].(string))
		if !t.Before(from) && t.Before(to) {
			res.Rows = append(res.Rows, e)
		}
	}
	res.Matched = int64(len(res.Rows))
	return res, nil
}

func TestBacktestStep(t *testing.T) {
	d := &Detection{Lookback: "15m"}
	for _, tc := range []struct {
		window time.Duration
		want   time.Duration
	}{
		{time.Hour, 15 * time.Minute},
		{24 * time.Hour, 24 * time.Minute},
		{30 * 24 * time.Hour, 12 * time.Hour},
		{90 * 24 * time.Hour, 36 * time.Hour},
		{10 * time.Minute, 10 * time.Minute},
	} {
		got, err := BacktestStep(d, tc.window)
		if err != nil || got != tc.want {
			t.Errorf("window %s: step %s, %v; want %s", tc.window, got, err, tc.want)
		}
		if n := (tc.window + got - 1) / got; n > MaxBacktestRuns {
			t.Errorf("window %s: %d runs", tc.window, n)
		}
	}
	if _, err := BacktestStep(d, 91*24*time.Hour); err == nil {
		t.Error("a 91-day window was accepted")
	}
	if _, err := BacktestStep(d, 0); err == nil {
		t.Error("an empty window was accepted")
	}
}

func TestBacktestCountsWhatRunsWouldRaise(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	at := func(ago time.Duration) string { return now.Add(-ago).Format(time.RFC3339) }
	run := &windowRunner{events: []search.Row{
		{"_time": at(1 * time.Hour), "dest": "web1", "user": "alice"},
		{"_time": at(70 * time.Minute), "dest": "web1", "user": "alice"}, // throttled: same key within 1h
		{"_time": at(5 * time.Hour), "dest": "web1", "user": "alice"},    // raised: over an hour before
		{"_time": at(2 * time.Hour), "dest": "db1", "user": "bob"},
		{"_time": at(3 * time.Hour), "dest": "lab1", "user": "carol"},  // excepted
		{"_time": at(48 * time.Hour), "dest": "web1", "user": "alice"}, // outside the window
	}}
	s := &Scheduler{Engine: run, Findings: findings.NewMemory(), Now: func() time.Time { return now }}
	d := &Detection{
		ID: "bt", Title: "Thing on $dest$", Query: "datamodel=Endpoint process_name=x.exe", Schedule: "5m", Lookback: "10m",
		Severity: "high", Throttle: Throttle{Fields: []string{"dest", "user"}, Window: "1h"},
		Exceptions: []Exception{{ID: "x1", Match: map[string]string{"dest": "lab*"}}},
	}
	d.Defaults()
	bt, err := s.Backtest(context.Background(), d, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if bt.Results != 5 || bt.Findings != 3 || bt.Throttled != 1 || bt.Suppressed != 1 {
		t.Fatalf("results %d findings %d throttled %d suppressed %d; want 5, 3, 1, 1", bt.Results, bt.Findings, bt.Throttled, bt.Suppressed)
	}
	if bt.Approximate {
		t.Error("an event search is exact at any step")
	}
	if len(run.queries) != bt.Searches || bt.Searches > MaxBacktestRuns || len(bt.Buckets) != bt.Searches {
		t.Errorf("%d searches, %d buckets, %d queries", bt.Searches, len(bt.Buckets), len(run.queries))
	}
	// The windows tile the 24 hours exactly.
	if !bt.Buckets[0].Start.Equal(now.Add(-24*time.Hour)) || !bt.Buckets[len(bt.Buckets)-1].End.Equal(now) {
		t.Errorf("buckets run %s to %s", bt.Buckets[0].Start, bt.Buckets[len(bt.Buckets)-1].End)
	}
	for i := 1; i < len(bt.Buckets); i++ {
		if !bt.Buckets[i].Start.Equal(bt.Buckets[i-1].End) {
			t.Fatalf("gap or overlap at bucket %d", i)
		}
	}
	for _, q := range run.queries {
		if q.Earliest == "" || q.Latest == "" {
			t.Fatal("a backtest search was not bounded in time")
		}
	}
	if len(bt.Samples) != 3 || bt.Samples[0].Title != "Thing on web1" || !bt.Samples[0].Time.After(bt.Samples[1].Time) {
		t.Errorf("samples: %+v", bt.Samples)
	}
	if top := bt.Top["dest"]; len(top) == 0 || top[0].Value != "web1" || top[0].Count != 2 {
		t.Errorf("top dest: %+v", bt.Top["dest"])
	}
	// Nothing was written.
	if _, n, _ := s.Findings.Search(context.Background(), findings.Filter{}); n != 0 {
		t.Errorf("a backtest raised %d findings", n)
	}
}

func TestBacktestSummaryOverLongerStepIsApproximate(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	s := &Scheduler{Engine: &windowRunner{}, Findings: findings.NewMemory(), Now: func() time.Time { return now }}
	d := &Detection{ID: "bt", Title: "x", Query: "datamodel=Authentication action=failure | stats count by src | where count>10", Schedule: "5m", Lookback: "15m", Severity: "low"}
	d.Defaults()
	bt, err := s.Backtest(context.Background(), d, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !bt.Approximate || bt.Step != "12h" || bt.Searches != 60 {
		t.Errorf("approximate %v step %s searches %d", bt.Approximate, bt.Step, bt.Searches)
	}
	bt, err = s.Backtest(context.Background(), d, 6*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if bt.Approximate || bt.Step != "15m" || bt.Searches != 24 {
		t.Errorf("at the lookback: approximate %v step %s searches %d", bt.Approximate, bt.Step, bt.Searches)
	}
}

func TestBacktestStopsCleanlyWhenTimeRunsOut(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	run := &windowRunner{fail: context.DeadlineExceeded}
	s := &Scheduler{Engine: run, Findings: findings.NewMemory(), Now: func() time.Time { return now }}
	d := &Detection{ID: "bt", Title: "x", Query: "datamodel=Endpoint", Schedule: "5m", Lookback: "1h", Severity: "low"}
	d.Defaults()
	bt, err := s.Backtest(context.Background(), d, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !bt.Partial || bt.Searches != 1 || bt.PartialAt == nil || !bt.PartialAt.Equal(now.Add(-23*time.Hour)) {
		t.Errorf("partial %v searches %d at %v", bt.Partial, bt.Searches, bt.PartialAt)
	}
	// A failure on the very first search is an error, not an empty result.
	run.queries = nil
	run.fail = nil
	bad := &Detection{ID: "bt", Title: "x", Query: "datamodel=Endpoint", Schedule: "5m", Lookback: "1h", Severity: "low"}
	if _, err := s.Backtest(context.Background(), bad, 0); err == nil {
		t.Error("no error for an empty window")
	}
}

func TestBacktestTrimsLongSampleValues(t *testing.T) {
	wide := search.Row{"_raw": strings.Repeat("é", 3000), "n": 5, "zz_key": "k"}
	for i := 0; i < 500; i++ {
		wide["f"+strconv.Itoa(i)] = i
	}
	r := trimRow(wide, []string{"zz_key"})
	if len(r) != maxSampleFields || r["zz_key"] != "k" || r["_raw"] == nil {
		t.Errorf("kept %d fields, zz_key %v", len(r), r["zz_key"])
	}
	if s := r["_raw"].(string); len(s) > maxSampleValue+len("…") || !strings.HasSuffix(s, "…") {
		t.Errorf("_raw kept %d bytes", len(s))
	}
	if r := trimRow(search.Row{"n": 5}, nil); r["n"] != 5 {
		t.Error("a number changed")
	}
}
