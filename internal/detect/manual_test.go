package detect_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/search"
)

func throttledRule() *detect.Detection {
	return &detect.Detection{ID: "rule-m", Title: "M {user}", Query: "user=m", Enabled: true, Schedule: "5m", Lookback: "5m",
		Throttle: detect.Throttle{Window: "1h", Fields: []string{"user"}}}
}

// TestRunNowOnAnotherServer: "Run now" on a server that does not run the
// schedule respects the leader's throttle, records who ran it where, and
// leaves the schedule's run state alone.
func TestRunNowOnAnotherServer(t *testing.T) {
	r := newRig(t, []search.Row{{"user": "bob"}}, throttledRule())
	cl := &clock{t: t0}
	leader := r.scheduler(cl, cl, 5, "siem-a")
	leader.RunDue(context.Background())
	cl.Set(t0.Add(5 * time.Minute))
	leader.RunDue(context.Background())
	if st := r.detstate("rule-m"); st.LastFindings != 1 {
		t.Fatalf("leader's slot %+v", st)
	}
	before := r.srv.Source(runtimeIndex, "detstate:rule-m")

	cl.Set(t0.Add(20 * time.Minute))
	other := r.scheduler(cl, cl, 0, "siem-b")
	other.Allowed = func() bool { return false }
	res, err := other.RunManual(context.Background(), throttledRule(), "sam")
	if err != nil || res.Results != 1 || len(res.Findings) != 0 || res.Throttled != 1 {
		t.Fatalf("run now = %+v, %v", res, err)
	}
	var m struct {
		Kind      string    `json:"kind"`
		At        time.Time `json:"at"`
		By        string    `json:"by"`
		Node      string    `json:"node"`
		Results   int       `json:"results"`
		Throttled int       `json:"throttled"`
	}
	b, _ := json.Marshal(r.srv.Source(runtimeIndex, "detmanual:rule-m"))
	if err := json.Unmarshal(b, &m); err != nil || m.Kind != "detmanual" || m.By != "sam" || m.Node != "siem-b" ||
		m.Results != 1 || m.Throttled != 1 || !m.At.Equal(t0.Add(20*time.Minute)) {
		t.Errorf("detmanual = %s", b)
	}
	if after := r.srv.Source(runtimeIndex, "detstate:rule-m"); !reflect.DeepEqual(before, after) {
		t.Errorf("run now changed the run state:\n%v\n%v", before, after)
	}
	// Every server sees it.
	st, err := leader.StatusCtx(context.Background())
	if err != nil || st["rule-m"].Manual == nil || st["rule-m"].Manual.By != "sam" || st["rule-m"].LastFindings != 1 {
		t.Errorf("status = %+v, %v", st["rule-m"], err)
	}
}

// TestRunNowThrottleHoldsTheSchedule: a finding "Run now" raised holds
// the group back from scheduled slots until its window ends.
func TestRunNowThrottleHoldsTheSchedule(t *testing.T) {
	r := newRig(t, []search.Row{{"user": "bob"}}, throttledRule())
	cl := &clock{t: t0}
	other := r.scheduler(cl, cl, 0, "siem-b")
	res, err := other.RunManual(context.Background(), throttledRule(), "sam")
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("run now = %+v, %v", res, err)
	}
	var manual int
	for _, d := range r.docs(runtimeIndex) {
		var th struct{ Kind, Slot string }
		if json.Unmarshal(d.Source, &th) == nil && th.Kind == "throttle" {
			if th.Slot != "manual" {
				t.Errorf("throttle %s", d.Source)
			}
			manual++
		}
	}
	if manual != 1 {
		t.Fatalf("%d manual throttles", manual)
	}

	leader := r.scheduler(cl, cl, 5, "siem-a")
	leader.RunDue(context.Background())
	cl.Set(t0.Add(10 * time.Minute))
	leader.RunDue(context.Background())
	if st := r.detstate("rule-m"); st.LastFindings != 0 || st.LastThrottled != 1 {
		t.Errorf("scheduled slot within the window %+v", st)
	}
	// The missed slots are made up: the first one after the window ends
	// raises the next finding.
	cl.Set(t0.Add(70 * time.Minute))
	leader.RunDue(context.Background())
	if n := len(r.docs("t_findings")); n != 2 {
		t.Errorf("%d findings after the window, want the Run now one and one scheduled", n)
	}
}
