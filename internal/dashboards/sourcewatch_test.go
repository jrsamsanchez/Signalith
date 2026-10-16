package dashboards

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// sourceExec answers SourceWatch's stats queries from event times per
// source, the way OpenSearch would.
type sourceExec struct {
	mu      sync.Mutex
	events  map[sourceKey][]time.Time
	queries []string
}

func (f *sourceExec) Execute(_ context.Context, q *query.Query) (*search.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q.String())
	from, err := time.Parse(time.RFC3339Nano, q.Earliest)
	if err != nil {
		return nil, err
	}
	to := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	if q.Latest != "" {
		if to, err = time.Parse(time.RFC3339Nano, q.Latest); err != nil {
			return nil, err
		}
	}
	last := strings.Contains(q.String(), "max(_time)")
	res := &search.Result{}
	for k, ts := range f.events {
		var n int
		var max time.Time
		for _, t := range ts {
			if !t.Before(from) && !t.After(to) {
				n++
				if t.After(max) {
					max = t
				}
			}
		}
		if n == 0 {
			continue
		}
		r := search.Row{"host": k.host, "sourcetype": k.sourcetype}
		if last {
			r["last_seen"] = float64(max.UnixMilli())
		} else {
			r["count"] = float64(n)
		}
		res.Rows = append(res.Rows, r)
	}
	return res, nil
}

type eventSink struct {
	mu     sync.Mutex
	events []ingest.Event
	ctxs   []ingest.Origin
}

func (s *eventSink) IngestEvents(ctx context.Context, evs []ingest.Event) (*ingest.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evs...)
	s.ctxs = append(s.ctxs, ingest.OriginFrom(ctx))
	return &ingest.Result{}, nil
}

// every returns times from start to end, one each step.
func every(start, end time.Time, step time.Duration) []time.Time {
	var out []time.Time
	for t := start; !t.After(end); t = t.Add(step) {
		out = append(out, t)
	}
	return out
}

func TestSourceWatch(t *testing.T) {
	now := time.Date(2026, 10, 16, 20, 0, 0, 0, time.UTC)
	clock := now
	steady := sourceKey{"dc-02", "WinEventLog:Security"}
	nightly := sourceKey{"laptop-7", "WinEventLog:Security"}
	live := sourceKey{"web-01", "nginx:access"}
	young := sourceKey{"new-01", "linux:auth"}
	exec := &sourceExec{events: map[sourceKey][]time.Time{
		// All day until 3 hours ago.
		steady: every(now.Add(-40*time.Hour), now.Add(-3*time.Hour), 20*time.Minute),
		// Off overnight: nothing in one of the blocks.
		nightly: append(every(now.Add(-40*time.Hour), now.Add(-30*time.Hour), 20*time.Minute),
			every(now.Add(-15*time.Hour), now.Add(-3*time.Hour), 20*time.Minute)...),
		// Still sending.
		live: every(now.Add(-40*time.Hour), now.Add(10*time.Hour), 20*time.Minute),
		// Started this morning, then stopped.
		young: every(now.Add(-12*time.Hour), now.Add(-3*time.Hour), 20*time.Minute),
	}}
	sink := &eventSink{}
	w := &SourceWatch{Engine: exec, Events: sink, Now: func() time.Time { return clock }}

	if err := w.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("events = %d, want 1 (only the steady source): %+v", len(sink.events), sink.events)
	}
	ev := sink.events[0]
	if ev.Fields["host"] != "dc-02" || ev.Fields["stopped_sourcetype"] != "WinEventLog:Security" ||
		ev.Fields["sourcetype"] != SourceHealthSourcetype || ev.Fields["quiet_minutes"] != int64(180) {
		t.Fatalf("event fields = %v", ev.Fields)
	}
	if !strings.Contains(fmt.Sprint(ev.Fields["message"]), "dc-02 stopped sending WinEventLog:Security: nothing for 3 hours") {
		t.Fatalf("message = %v", ev.Fields["message"])
	}
	if sink.ctxs[0].Intake != ingest.IntakeSignalith {
		t.Fatalf("origin = %+v, want Signalith's own", sink.ctxs[0])
	}
	firstID := ev.ID
	for _, q := range exec.queries {
		// Sample data, Signalith's own events and its scans are left out.
		if !strings.Contains(q, "signalith_intake") || !strings.Contains(q, "scanner") || !strings.Contains(q, "signalith_sample") {
			t.Fatalf("query does not leave out its own events: %s", q)
		}
	}

	// The same silence is not written twice.
	clock = now.Add(15 * time.Minute)
	if err := w.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("events after second check = %d, want 1", len(sink.events))
	}
	// Another server taking over writes the same event ID again.
	w2 := &SourceWatch{Engine: exec, Events: sink, Now: func() time.Time { return clock }}
	if err := w2.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 2 || sink.events[1].ID != firstID {
		t.Fatalf("takeover event ID = %v, want %s", sink.events[len(sink.events)-1].ID, firstID)
	}

	// It sends again, then stops again: a new silence, a new event.
	exec.mu.Lock()
	exec.events[steady] = append(exec.events[steady], every(now.Add(time.Hour), now.Add(4*time.Hour), 20*time.Minute)...)
	exec.mu.Unlock()
	clock = now.Add(2 * time.Hour)
	if err := w.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 2 {
		t.Fatalf("events while sending = %d, want 2", len(sink.events))
	}
	clock = now.Add(6*time.Hour + 30*time.Minute)
	if err := w.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 3 || sink.events[2].ID == firstID {
		t.Fatalf("events after second silence = %d, want a new one", len(sink.events))
	}
}

func TestSourceWatchStaleAfterAndLeader(t *testing.T) {
	now := time.Date(2026, 10, 16, 20, 0, 0, 0, time.UTC)
	exec := &sourceExec{events: map[sourceKey][]time.Time{
		{"dc-01", "WinEventLog:Security"}: every(now.Add(-40*time.Hour), now.Add(-90*time.Minute), 10*time.Minute),
	}}
	sink := &eventSink{}
	stale := 2 * time.Hour
	leader := false
	w := &SourceWatch{Engine: exec, Events: sink, Now: func() time.Time { return now },
		StaleAfter: func() time.Duration { return stale }, Leader: func() bool { return leader }}
	if err := w.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(exec.queries) != 0 {
		t.Fatalf("a server that does not run the jobs searched: %v", exec.queries)
	}
	leader = true
	if err := w.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 0 {
		t.Fatalf("quiet for 90 minutes with 2h allowed wrote %d events", len(sink.events))
	}
	// A shorter setting applies on the next check.
	stale = time.Hour
	if err := w.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("events = %d after lowering the setting, want 1", len(sink.events))
	}
}

func TestSourceWatchCap(t *testing.T) {
	now := time.Date(2026, 10, 16, 20, 0, 0, 0, time.UTC)
	exec := &sourceExec{events: map[sourceKey][]time.Time{}}
	for i := range maxSourceEvents + 30 {
		k := sourceKey{fmt.Sprintf("host-%03d", i), "linux:auth"}
		exec.events[k] = every(now.Add(-40*time.Hour), now.Add(-3*time.Hour-time.Duration(i)*time.Minute), 30*time.Minute)
	}
	sink := &eventSink{}
	w := &SourceWatch{Engine: exec, Events: sink, Now: func() time.Time { return now }}
	if err := w.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != maxSourceEvents {
		t.Fatalf("events = %d, want the cap %d", len(sink.events), maxSourceEvents)
	}
	// The rest follow on the next check.
	if err := w.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != maxSourceEvents+30 {
		t.Fatalf("events after second check = %d, want %d", len(sink.events), maxSourceEvents+30)
	}
}

func TestSourceWatchQueriesParse(t *testing.T) {
	for _, src := range []string{"| stats max(_time) as last_seen by host, sourcetype", "| stats count by host, sourcetype"} {
		q, err := query.Parse(qWatched + src)
		if err != nil {
			t.Fatalf("%q: %v", qWatched+src, err)
		}
		if _, err := (&search.Engine{}).Compile(q); err != nil {
			t.Fatalf("%q: compile: %v", src, err)
		}
	}
}
