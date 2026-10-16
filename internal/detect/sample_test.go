package detect

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// queryRecorder records the searches a scheduler runs.
type queryRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *queryRecorder) Execute(_ context.Context, q *query.Query) (*search.Result, error) {
	r.mu.Lock()
	r.seen = append(r.seen, q.String())
	r.mu.Unlock()
	return &search.Result{Kind: "table"}, nil
}

// TestScopeSample: the live scheduler leaves every sample document out of
// its searches, and the sample backfill reads only its own load's, so live
// runs never raise unmarked findings from sample data and the backfill
// never marks real activity as sample.
func TestScopeSample(t *testing.T) {
	lib, problems, err := NewLibrary(t.TempDir())
	if err != nil || len(problems) > 0 {
		t.Fatal(err, problems)
	}
	dets := []*Detection{
		{ID: "x-filter", Title: "Filtered", Query: "user=bob OR user=eve | stats count by user", Enabled: true, Schedule: "5m", Lookback: "1h"},
		{ID: "x-risk", Title: "Risk", Query: "datamodel=Risk | stats sum(risk_score) as score by risk_object", Enabled: true, Schedule: "5m", Lookback: "24h"},
		{ID: "x-bare", Title: "Everything", Query: "| stats count", Enabled: true, Schedule: "5m", Lookback: "1h"},
	}
	for _, d := range dets {
		if err := lib.Put(d); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ mark, want string }{
		{"", "NOT signalith_sample=*"},
		{"sample-20261013-120000", "signalith_sample=sample-20261013-120000"},
	} {
		rec := &queryRecorder{}
		s := &Scheduler{Library: lib, Engine: rec, Findings: findings.NewMemory(), SampleMark: tc.mark}
		for _, d := range dets {
			if _, err := s.RunAt(context.Background(), d, at); err != nil {
				t.Fatalf("%s: %v", d.ID, err)
			}
		}
		if len(rec.seen) != len(dets) {
			t.Fatalf("ran %d searches, want %d", len(rec.seen), len(dets))
		}
		for i, q := range rec.seen {
			if !strings.Contains(q, tc.want) {
				t.Errorf("mark %q, %s: search %q lacks %q", tc.mark, dets[i].ID, q, tc.want)
			}
			if tc.mark != "" && strings.Contains(q, "NOT signalith_sample") {
				t.Errorf("the backfill's search %q leaves out its own documents", q)
			}
		}
		// The detection's own filter is kept alongside.
		if !strings.Contains(rec.seen[0], "user=bob") {
			t.Errorf("filter lost: %q", rec.seen[0])
		}
	}
}

// rowRunner answers every search with one row for the same user.
type rowRunner struct{}

func (rowRunner) Execute(context.Context, *query.Query) (*search.Result, error) {
	return &search.Result{Kind: "table", Columns: []string{"user", "count"},
		Rows: []search.Row{{"user": "dc-01", "count": 9}}}, nil
}

// TestSampleThrottleIsSeparate: a sample finding about a name a real host
// also has does not hold back the real finding, and the other way round,
// while each still throttles its own kind.
func TestSampleThrottleIsSeparate(t *testing.T) {
	lib, _, err := NewLibrary(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := &Detection{ID: "x-throttled", Title: "Throttled", Query: "user=* | stats count by user", Enabled: true,
		Schedule: "5m", Lookback: "1h", Severity: "high", Throttle: Throttle{Window: "24h", Fields: []string{"user"}}}
	if err := lib.Put(d); err != nil {
		t.Fatal(err)
	}
	fs := findings.NewMemory()
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	backfill := &Scheduler{Library: lib, Engine: rowRunner{}, Findings: fs, SampleMark: "sample-x"}
	live := &Scheduler{Library: lib, Engine: rowRunner{}, Findings: fs}
	for i, step := range []struct {
		s    *Scheduler
		want int
	}{{backfill, 1}, {live, 1}, {live, 0}, {backfill, 0}} {
		res, err := step.s.RunAt(context.Background(), d, at.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != step.want {
			t.Errorf("step %d: %d findings, want %d", i, len(res.Findings), step.want)
		}
	}
}

// The marker filter is for the run only: a finding's drilldown is the
// detection's own search.
func TestSampleScopeNotInDrilldown(t *testing.T) {
	lib, _, err := NewLibrary(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := &Detection{ID: "x-drill", Title: "Drill", Query: "user=* | stats count by user", Enabled: true, Schedule: "5m", Lookback: "1h", Severity: "high"}
	if err := lib.Put(d); err != nil {
		t.Fatal(err)
	}
	for _, mark := range []string{"", "sample-x"} {
		s := &Scheduler{Library: lib, Engine: rowRunner{}, Findings: findings.NewMemory(), SampleMark: mark}
		res, err := s.RunAt(context.Background(), d, time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC))
		if err != nil || len(res.Findings) != 1 {
			t.Fatalf("mark %q: %v, %d findings", mark, err, len(res.Findings))
		}
		if q := res.Findings[0].Query; strings.Contains(q, "signalith_sample") {
			t.Errorf("mark %q: drilldown %q has the marker filter", mark, q)
		}
	}
}

// TestScheduledRunsLeaveSampleOut: the schedule, which runs only on the
// server holding the job lease (Allowed), leaves sample documents out of
// every search it runs, and runs nothing once that server loses the lease.
// The sample backfill is part of an admin's load, not a background job: it
// runs on whichever server the admin used, lease or not, and reads only its
// own load's documents.
func TestScheduledRunsLeaveSampleOut(t *testing.T) {
	lib, _, err := NewLibrary(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := &Detection{ID: "x-sched", Title: "Scheduled", Query: "user=bob | stats count by user", Enabled: true, Schedule: "5m", Lookback: "1h"}
	if err := lib.Put(d); err != nil {
		t.Fatal(err)
	}
	holds := true
	live := &queryRecorder{}
	at := time.Now()
	s := &Scheduler{Library: lib, Engine: live, Findings: findings.NewMemory(), Allowed: func() bool { return holds },
		Now: func() time.Time { return at }}
	s.RunDue(context.Background()) // first sight: the next slot is the first run
	at = at.Add(10 * time.Minute)
	s.RunDue(context.Background())
	if len(live.seen) == 0 {
		t.Fatal("the schedule ran nothing on the server holding the lease")
	}
	for _, q := range live.seen {
		if !strings.Contains(q, "NOT signalith_sample=*") {
			t.Errorf("scheduled search %q does not leave sample data out", q)
		}
	}
	holds = false
	n := len(live.seen)
	at = at.Add(time.Hour) // due again
	s.RunDue(context.Background())
	if len(live.seen) != n {
		t.Errorf("a server without the lease ran %d scheduled searches", len(live.seen)-n)
	}

	fill := &queryRecorder{}
	bf := &Scheduler{Library: lib, Engine: fill, Findings: findings.NewMemory(), SampleMark: "sample-x", Allowed: func() bool { return false }}
	if _, err := bf.RunAt(context.Background(), d, time.Now()); err != nil {
		t.Fatalf("backfill on a server without the lease: %v", err)
	}
	if len(fill.seen) != 1 || !strings.Contains(fill.seen[0], "signalith_sample=sample-x") {
		t.Errorf("backfill searches = %q", fill.seen)
	}
}
