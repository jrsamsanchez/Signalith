// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"math"
	"strings"
	"sync"
	"testing"
)

func TestHistogram(t *testing.T) {
	h := NewHistogram(1, 0.1, 10)
	var wg sync.WaitGroup
	for _, v := range []float64{0.05, 0.1, 0.5, 5, 50, math.NaN()} {
		wg.Add(1)
		go func() { defer wg.Done(); h.Observe(v) }()
	}
	wg.Wait()
	s := h.Snapshot()
	if s.Count != 5 || math.Abs(s.Sum-55.65) > 1e-9 {
		t.Errorf("count %d sum %v", s.Count, s.Sum)
	}
	if want := []uint64{2, 3, 4}; len(s.Cumulative) != 3 || s.Cumulative[0] != want[0] || s.Cumulative[1] != want[1] || s.Cumulative[2] != want[2] {
		t.Errorf("buckets %v %v", s.Bounds, s.Cumulative)
	}
}

func TestWriterFormats(t *testing.T) {
	h := NewHistogram(0.5)
	h.Observe(0.25)
	for _, om := range []bool{false, true} {
		w := NewWriter(om)
		w.Info("x_build", "Build.", Label{"version", `1.2 "beta"` + "\n" + `\x`})
		w.Counter("x_events", "Events\nseen.", L(3, "intake", "agent"))
		w.Gauge("x_up", "Up.", L(1))
		w.Gauge("x_none", "No samples: not written.")
		w.Histogram("x_seconds", "Time.", h.Snapshot())
		out := string(w.Bytes())
		for _, want := range []string{
			`x_build_info{version="1.2 \"beta\"\n\\x"} 1`,
			`x_events_total{intake="agent"} 3`,
			"# HELP x_events_total Events\\nseen.\n",
			"x_up 1\n",
			`x_seconds_bucket{le="0.5"} 1`, `x_seconds_bucket{le="+Inf"} 1`, "x_seconds_sum 0.25\n", "x_seconds_count 1\n",
		} {
			if om {
				want = strings.ReplaceAll(want, "# HELP x_events_total", "# HELP x_events")
			}
			if !strings.Contains(out, want) {
				t.Errorf("openmetrics=%v: no %q in\n%s", om, want, out)
			}
		}
		if strings.Contains(out, "x_none") {
			t.Error("a family without samples was written")
		}
		if om != strings.HasSuffix(out, "# EOF\n") {
			t.Errorf("openmetrics=%v: EOF in\n%s", om, out)
		}
		if om && (!strings.Contains(out, "# TYPE x_events counter\n") || !strings.Contains(out, "# TYPE x_build info\n")) {
			t.Errorf("openmetrics families:\n%s", out)
		}
		if !om && (!strings.Contains(out, "# TYPE x_events_total counter\n") || !strings.Contains(out, "# TYPE x_build_info gauge\n")) {
			t.Errorf("text families:\n%s", out)
		}
	}
	if !WantsOpenMetrics("application/openmetrics-text; version=1.0.0") || WantsOpenMetrics("text/plain") {
		t.Error("WantsOpenMetrics")
	}
}
