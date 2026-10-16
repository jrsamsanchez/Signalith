package detect

import (
	"context"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/search"
)

func TestThreatActivityScalesRiskByWeight(t *testing.T) {
	lib, _, _ := NewLibrary("")
	d, err := lib.Get("threat-activity")
	if err != nil || !d.Enabled || d.Risk.WeightField != "threat_weight" {
		t.Fatalf("threat-activity = %+v %v", d, err)
	}
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	row := func(user string) search.Row {
		return search.Row{"_time": "2026-10-11T11:58:00Z", "src": "203.0.113.9", "dest": "web1", "user": user, "threat_match_field": "src",
			"threat_match_value": "203.0.113.9", "threat_indicator": "203.0.113.9", "threat_source": "feodo", "threat_weight": 1.5, "threat_target": "web1"}
	}
	run := &fakeRunner{rows: []search.Row{row("oracle"), row("root")}}
	rs := &memRisk{}
	s := &Scheduler{Library: lib, Engine: run, Findings: findings.NewMemory(), Risk: rs, Now: func() time.Time { return now }}
	res, err := s.RunManual(context.Background(), d, "")
	if err != nil {
		t.Fatal(err)
	}
	// One finding per indicator and target; the second event is throttled.
	if len(res.Findings) != 1 || res.Throttled != 1 {
		t.Fatalf("run = %+v", res)
	}
	f := res.Findings[0]
	if f.Title != "Threat intel match on src 203.0.113.9 (feodo)" {
		t.Errorf("title = %q", f.Title)
	}
	// The drilldown shows the events with the matched value.
	if f.Query != "src=203.0.113.9" {
		t.Errorf("drilldown = %q", f.Query)
	}
	// Score 60 times weight 1.5, to the target system and the user.
	if len(rs.events) != 2 || rs.events[0].Object != "web1" || rs.events[0].Score != 90 || rs.events[1].Object != "oracle" || rs.events[1].Score != 90 {
		t.Errorf("risk = %+v", rs.events)
	}
	if w, ok := toWeight("50"); ok {
		t.Errorf("weight 50 accepted as %v", w)
	}
	if w, ok := toWeight("2"); !ok || w != 2 {
		t.Errorf("weight string = %v %v", w, ok)
	}
}
