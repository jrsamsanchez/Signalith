package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHistogramQuantiles(t *testing.T) {
	h := newHistogram()
	for i := 1; i <= 1000; i++ {
		h.Observe(time.Duration(i) * time.Millisecond)
	}
	for q, want := range map[float64]time.Duration{0.5: 500 * time.Millisecond, 0.95: 950 * time.Millisecond, 0.99: 990 * time.Millisecond} {
		got := h.Quantile(q)
		if math.Abs(float64(got-want))/float64(want) > 0.011 {
			t.Errorf("q%v = %v, want %v within 1%%", q, got, want)
		}
	}
	if h.Max() != time.Second || h.Quantile(1) != time.Second {
		t.Errorf("max %v, q1 %v", h.Max(), h.Quantile(1))
	}
	o := newHistogram()
	o.Observe(5 * time.Second)
	h.Merge(o)
	if h.Count() != 1001 || h.Max() != 5*time.Second {
		t.Errorf("merged: %d %v", h.Count(), h.Max())
	}
	if newHistogram().Quantile(0.5) != 0 {
		t.Error("empty histogram")
	}
}

func TestMetricsByPhase(t *testing.T) {
	m := newMetrics()
	m.SetPhase("a")
	m.Add("n", 2)
	m.Observe("t", time.Millisecond)
	m.Set("", "g", 3)
	m.SetPhase("b")
	m.Add("n", 5)
	m.Set("", "g", 1)
	m.Set("a", "g", 2) // smaller: kept 3
	if m.Count("a", "n") != 2 || m.Count("", "n") != 7 {
		t.Errorf("counts %d %d", m.Count("a", "n"), m.Count("", "n"))
	}
	if g, _ := m.Gauge("a", "g"); g != 3 {
		t.Errorf("gauge a %v", g)
	}
	if g, _ := m.Gauge("", "g"); g != 3 {
		t.Errorf("gauge %v", g)
	}
	if m.Hist("b", "t").Count() != 0 || m.Hist("", "t").Count() != 1 {
		t.Error("histograms by phase")
	}
}

func TestJudge(t *testing.T) {
	two, five := 2.0, 5.0
	for _, tc := range []struct {
		c     Criterion
		v     float64
		skip  string
		want  string
		limit string
	}{
		{Criterion{Name: "x", Max: &two}, 1, "", statusPass, "<= 2"},
		{Criterion{Name: "x", Max: &two}, 3, "", statusFail, "<= 2"},
		{Criterion{Name: "x", Min: &two, Max: &five}, 1, "", statusFail, ">= 2 and <= 5"},
		{Criterion{Name: "x"}, 9, "", statusRecord, ""},
		{Criterion{Name: "x", Max: &two}, 9, "not a cluster", statusSkip, "<= 2"},
		{Criterion{Name: "x", Max: &two}, math.NaN(), "", statusFail, "<= 2"},
		{Criterion{Name: "x", Max: &two}, math.Inf(1), "", statusFail, "<= 2"},
	} {
		got := judge(tc.c, tc.v, tc.skip)
		if got.Status != tc.want || got.Limit != tc.limit {
			t.Errorf("judge(%+v, %v, %q) = %+v", tc.c, tc.v, tc.skip, got)
		}
	}
}

func TestReport(t *testing.T) {
	one := 1.0
	r := &Report{Run: "r1", Scenario: "s", Targets: []string{"https://a"},
		Phases:   []PhaseReport{{Name: "p", Seconds: 3, Counts: map[string]int64{"ingest_requests": 4}}},
		Criteria: []CriterionResult{judge(Criterion{Name: "ingest_p99_ms", Max: &one}, 2, ""), judge(Criterion{Name: "takeover_seconds", Max: &one}, 0, "not a cluster")}}
	r.finish()
	if r.Pass {
		t.Error("a failed criterion passed the run")
	}
	var b strings.Builder
	r.WriteText(&b)
	for _, want := range []string{"FAIL   ingest_p99_ms", "SKIP   takeover_seconds", "(not a cluster)", "ingest_requests", "RESULT: FAIL"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("text report lacks %q:\n%s", want, b.String())
		}
	}
	path := filepath.Join(t.TempDir(), "r.json")
	if err := r.WriteJSON(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil || back.Run != "r1" || len(back.Criteria) != 2 || back.Criteria[0].Status != statusFail {
		t.Errorf("JSON report: %v %+v", err, back)
	}
}
