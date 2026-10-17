package detect

import (
	"fmt"
	"testing"
	"time"
)

// Each rule counts for the server that ran it last: run times and lags
// are summed up per server, and a server falls behind when many of its
// rules ran late in the last hour, or slots were skipped.
func TestHealthByServer(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	states := map[string]RunState{}
	// a: 20 rules, run times 100..2000 ms, lag 1..20 s, 1 late: keeping up.
	for i := 1; i <= 20; i++ {
		rs := RunState{Node: "a", LastRun: now.Add(-time.Minute), LastDuration: int64(i * 100), Lag: int64(i * 1000)}
		if i == 20 {
			rs.LastLate = now.Add(-10 * time.Minute)
		}
		states[fmt.Sprintf("a%d", i)] = rs
	}
	// b: 10 rules, 3 of them late in the last hour, one late yesterday.
	for i := 1; i <= 10; i++ {
		rs := RunState{Node: "b", LastRun: now.Add(-time.Minute), LastDuration: 50, Lag: 500}
		if i <= 3 {
			rs.LastLate = now.Add(-30 * time.Minute)
		} else if i == 4 {
			rs.LastLate = now.Add(-20 * time.Hour)
		}
		states[fmt.Sprintf("b%d", i)] = rs
	}
	// c: one rule with slots skipped just now; another skipped yesterday
	// morning and a timeout.
	states["c1"] = RunState{Node: "c", LastRun: now.Add(-time.Minute), Skipped: &Skipped{Count: 4, At: now.Add(-5 * time.Minute)}}
	states["c2"] = RunState{Node: "c", LastRun: now.Add(-time.Minute), Skipped: &Skipped{Count: 9, At: now.Add(-30 * time.Hour)}, TimedOut: true}
	// Not counted: no server, never run, or last run two days ago.
	states["x1"] = RunState{LastRun: now}
	states["x2"] = RunState{Node: "a"}
	states["x3"] = RunState{Node: "a", LastRun: now.Add(-48 * time.Hour), LastDuration: 999999}

	h := HealthByServer(states, now)
	if len(h) != 3 {
		t.Fatalf("servers: %v", h)
	}
	a := h["a"]
	if a.Rules != 20 || a.DurationP50 != 1000 || a.DurationP95 != 1900 || a.LagP50 != 10000 || a.LagP95 != 19000 || a.LateHour != 1 || a.Behind {
		t.Errorf("a: %+v", a)
	}
	if b := h["b"]; b.Rules != 10 || b.LateHour != 3 || !b.Behind || b.Why == "" {
		t.Errorf("b: %+v", b)
	}
	if c := h["c"]; c.Rules != 2 || c.Skipped != 4 || c.SkippedHour != 4 || c.TimedOut != 1 || !c.Behind {
		t.Errorf("c: %+v", c)
	}
}

func TestPercentile(t *testing.T) {
	if got := percentile(nil, 95); got != 0 {
		t.Errorf("none: %d", got)
	}
	if got := percentile([]int64{7}, 95); got != 7 {
		t.Errorf("one: %d", got)
	}
	if got := percentile([]int64{4, 1, 3, 2}, 50); got != 2 {
		t.Errorf("p50 of 1..4: %d", got)
	}
}
