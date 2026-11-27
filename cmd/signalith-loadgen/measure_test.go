// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestMeasureSkipsAndValues checks each criterion's value, or why it was
// not measured, from a runner's metrics.
func TestMeasureSkipsAndValues(t *testing.T) {
	base := func() *runner {
		return &runner{s: &Scenario{}, m: newMetrics(), report: &Report{}, phaseSecs: map[string]float64{}, opsPerSecond: map[string]float64{}}
	}
	withFleet := func(r *runner) { r.fleet = newFleet("r", "t", nil, http.DefaultClient, r.m) }
	withOS := func(r *runner) { r.os = &osReader{} }
	two, one := 2, 1
	tests := []struct {
		name  string
		setup func(r *runner)
		want  float64
		skip  string
	}{
		{"events_lost", nil, 0, "no agents"},
		{"events_lost", withFleet, 0, "names no OpenSearch"},
		{"events_lost", func(r *runner) { withFleet(r); withOS(r) }, 0, "could not be read"},
		{"events_lost", func(r *runner) { withFleet(r); withOS(r); r.report.Verify = &Verdict{Lost: 3, Duplicated: 2} }, 3, ""},
		{"events_duplicated", func(r *runner) { withFleet(r); withOS(r); r.report.Verify = &Verdict{Lost: 3, Duplicated: 2} }, 2, ""},
		{"events_undelivered", nil, 0, "no agents"},
		{"events_undelivered", func(r *runner) { withFleet(r); r.fleet.undelivered.Store(4) }, 4, ""},
		{"events_dropped", nil, 0, "no agents"},
		{"events_dropped", func(r *runner) { withFleet(r); r.fleet.dropped.Store(5) }, 5, ""},
		{"ingest_error_rate", nil, 0, "no agent requests"},
		{"ingest_error_rate", func(r *runner) { r.m.Add("ingest_requests", 4); r.m.Add("ingest_errors", 1) }, 0.25, ""},
		{"ingest_p99_ms", nil, 0, "nothing measured"},
		{"ingest_p99_ms", func(r *runner) { r.m.Observe("ingest", 0) }, 0, ""},
		{"syslog_send_errors", nil, 0, "no syslog sent"},
		{"syslog_send_errors", func(r *runner) { r.m.Add("syslog_sent", 9); r.m.Add("syslog_send_errors", 1) }, 1, ""},
		{"unexpected_signouts", nil, 0, "no user requests"},
		{"write_conflicts", func(r *runner) { r.m.Add("user_requests", 3); r.m.Add("write_conflicts", 2) }, 2, ""},
		{"takeover_seconds", nil, 0, "not a cluster"},
		{"takeover_seconds", func(r *runner) { r.cluster = true }, 0, "nothing measured"},
		{"takeover_seconds", func(r *runner) { r.cluster = true; r.m.Set("", "takeover_seconds", 7) }, 7, ""},
		{"settings_converge_seconds", nil, 0, "no setting was changed"},
		{"settings_converge_seconds", func(r *runner) { r.m.Add("churn_conflicts", 1) }, math.NaN(), ""},
		{"settings_converge_seconds", func(r *runner) { r.m.Add("churn_saved", 1); r.m.Add("churn_not_converged", 1) }, math.Inf(1), ""},
		{"leaders_at_once", func(r *runner) { r.cluster = true }, 0, "needs each server listed"},
		{"os_ops_per_server_per_second", nil, 0, "names no OpenSearch"},
		{"os_ops_per_server_per_second", withOS, 0, "could not be read"},
		{"os_ops_per_random_cookie", nil, 0, "names no OpenSearch"},
		{"os_ops_per_random_cookie", withOS, 0, "nothing measured"},
		{"os_ops_per_random_cookie", func(r *runner) {
			withOS(r)
			r.opsPerSecond["flood"], r.opsPerSecond["quiet"] = 30, 10
			r.phaseSecs["flood"] = 2
			r.m.SetPhase("flood")
			r.m.Add("cookie_requests", 40)
		}, 1, ""},
		{"brute_lockouts", nil, 0, "no sign-in attempts"},
		{"brute_lockouts", func(r *runner) { r.m.Add("brute_attempts", 5); r.m.Add("brute_lockouts", 2) }, 2, ""},
		{"generator_lag_ms", nil, 0, "nothing measured"},
		{"generator_lag_ms", func(r *runner) { r.m.Observe("generator_lag", 0) }, 0, ""},
		{"ingest_events_per_second", nil, 0, "no agents"},
		{"ingest_events_per_second", func(r *runner) {
			withFleet(r)
			r.report.Phases = []PhaseReport{{Name: "load", Seconds: 2, Counts: map[string]int64{"agent_events_stored": 10}}}
		}, 5, ""},
		{"ingest_scaling", nil, 0, "no agents"},
		{"ingest_scaling", withFleet, 0, "no baseline"},
		{"ingest_scaling", func(r *runner) { withFleet(r); r.opts.Baseline = &Report{} }, 0, "no events stored"},
		{"ingest_scaling", func(r *runner) {
			withFleet(r)
			r.report.Phases = []PhaseReport{{Name: "load", Seconds: 2, Counts: map[string]int64{"agent_events_stored": 10}}}
			r.opts.Baseline = &Report{}
		}, 0, "baseline report has no events"},
		{"ingest_share_min", nil, 0, "no agents"},
		{"ingest_share_min", withFleet, 0, "needs each server listed"},
		{"ingest_share_min", func(r *runner) { withFleet(r); r.s.Targets = []string{"a", "b"} }, 0, "no events stored"},
		{"servers_ready", nil, 0, "needs admin credentials"},
		{"servers_ready", func(r *runner) { r.endReady, r.endWindows = &two, &one }, 2, ""},
		{"windows_servers_ready", func(r *runner) { r.endReady, r.endWindows = &two, &one }, 1, ""},
		{"windows_led_seconds", func(r *runner) { r.cluster = true }, 0, "needs each server listed"},
		{"windows_led_seconds", func(r *runner) { r.cluster = true; r.m.Add("leader_samples", 1); r.m.Add("windows_led_ms", 1500) }, 1.5, ""},
		{"opensearch_red_samples", nil, 0, "names no OpenSearch"},
		{"opensearch_unreachable_samples", withOS, 0, "nothing measured"},
		{"opensearch_unreachable_samples", func(r *runner) {
			withOS(r)
			r.m.Add("opensearch_health_samples", 3)
			r.m.Add("opensearch_unreachable_samples", 1)
		}, 1, ""},
		{"server_cpu_cores", nil, 0, "needs the servers' process IDs"},
		{"server_memory_mb", func(r *runner) { r.opts.PIDs = map[string]int{"a": 1} }, 0, "nothing measured"},
		{"server_memory_mb", func(r *runner) { r.opts.PIDs = map[string]int{"a": 1}; r.m.Set("", "server_memory_mb", 64) }, 64, ""},
		{"servers_not_upgraded", nil, 0, "no upgrade fault"},
		{"servers_not_upgraded", func(r *runner) { r.report.Faults = []FaultResult{{Kind: "upgrade", Skipped: "not safe"}} }, 0, "upgrade skipped: not safe"},
		{"servers_not_upgraded", func(r *runner) {
			r.report.Faults = []FaultResult{{Kind: "cmd"}, {Kind: "upgrade", ToUpgrade: []string{"a", "b", "c"}, Upgrades: []UpgradeStep{{Server: "a"}, {Server: "b", Error: "failed"}}}}
		}, 2, ""},
		{"upgrade_server_seconds", func(r *runner) { r.report.Faults = []FaultResult{{Kind: "upgrade"}} }, 0, "no server was upgraded"},
		{"upgrade_server_seconds", func(r *runner) {
			r.report.Faults = []FaultResult{{Kind: "upgrade"}}
			r.m.Set("", "upgrade_server_seconds", 12)
		}, 12, ""},
		{"jobs_moves", func(r *runner) { r.cluster = true }, 0, "needs each server listed"},
		{"jobs_moves", func(r *runner) { r.cluster = true; r.m.Add("leader_samples", 2); r.m.Add("jobs_moves", 1) }, 1, ""},
		{"page_reloads_per_user", nil, 0, "no user requests"},
		{"page_reloads_per_user", func(r *runner) { r.m.Add("user_requests", 1); r.m.Set("", "page_reloads_per_user", 2) }, 2, ""},
		{"check_failures", nil, 0, "no checks"},
		{"check_failures", func(r *runner) { r.report.Checks = []CheckResult{{Pass: true}, {Pass: false}} }, 1, ""},
		{"no_such_criterion", nil, 0, "not measured by this version"},
	}
	for _, tc := range tests {
		r := base()
		if tc.setup != nil {
			tc.setup(r)
		}
		c := Criterion{Name: tc.name}
		if tc.name == "os_ops_per_random_cookie" {
			c.Phase, c.Baseline = "flood", "quiet"
		}
		got, skip := r.measure(c)
		if tc.skip != "" {
			if !strings.Contains(skip, tc.skip) {
				t.Errorf("%s: skip %q, want %q", tc.name, skip, tc.skip)
			}
			continue
		}
		if skip != "" {
			t.Errorf("%s: skipped: %s", tc.name, skip)
			continue
		}
		if got != tc.want && !(math.IsNaN(got) && math.IsNaN(tc.want)) {
			t.Errorf("%s: measured %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestVerifySettles(t *testing.T) {
	osrv := fakeOpenSearch(t, "green")
	r, err := newOSReader(OpenSearch{URL: osrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	// Agent 0's event 3 never arrives: with no time to settle, verify
	// reports it lost at once.
	acked := map[int][]seqRange{0: {{1, 3}}, 1: {{1, 1}}}
	v, err := verify(context.Background(), r, "run", acked, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.Lost != 1 || v.Duplicated != 1 || v.Acked != 4 || v.Unacked != 1 {
		t.Errorf("verdict %+v", v)
	}
	// All there: done at once.
	v, err = verify(context.Background(), r, "run", map[int][]seqRange{0: {{1, 2}}}, time.Hour)
	if err != nil || v.Lost != 0 {
		t.Errorf("verdict %+v, %v", v, err)
	}
	// Missing events until the context ends.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := verify(ctx, r, "run", acked, time.Hour); err == nil {
		t.Error("verify that cannot settle gives no error when its context ends")
	}
	r.urls = []string{"http://127.0.0.1:1"}
	if _, err := verify(context.Background(), r, "run", acked, 0); err == nil {
		t.Error("unreachable OpenSearch gives no error")
	}
}
