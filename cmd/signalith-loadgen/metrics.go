package main

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// histGrowth is how much each latency bucket is wider than the one before:
// percentiles are right to within 1%.
const histGrowth = 1.01

// Histogram counts durations in buckets that grow by 1%, like an HDR
// histogram: small and fast whatever the number of samples.
type Histogram struct {
	mu      sync.Mutex
	buckets map[int]int64
	count   int64
	max     time.Duration
}

func newHistogram() *Histogram { return &Histogram{buckets: map[int]int64{}} }

func bucketOf(d time.Duration) int {
	us := float64(d) / float64(time.Microsecond)
	if us < 1 {
		return 0
	}
	return int(math.Log(us)/math.Log(histGrowth)) + 1
}

// bucketValue is the upper edge of bucket b.
func bucketValue(b int) time.Duration {
	if b == 0 {
		return time.Microsecond
	}
	return time.Duration(math.Pow(histGrowth, float64(b)) * float64(time.Microsecond))
}

// Observe adds one sample.
func (h *Histogram) Observe(d time.Duration) {
	if d < 0 {
		d = 0
	}
	b := bucketOf(d)
	h.mu.Lock()
	h.buckets[b]++
	h.count++
	if d > h.max {
		h.max = d
	}
	h.mu.Unlock()
}

// Merge adds o's samples.
func (h *Histogram) Merge(o *Histogram) {
	o.mu.Lock()
	defer o.mu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	for b, n := range o.buckets {
		h.buckets[b] += n
	}
	h.count += o.count
	h.max = max(h.max, o.max)
}

// Count is the number of samples.
func (h *Histogram) Count() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

// Quantile is the q (0-1) quantile, 0 without samples. It never says
// more than the largest sample.
func (h *Histogram) Quantile(q float64) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count == 0 {
		return 0
	}
	keys := make([]int, 0, len(h.buckets))
	for b := range h.buckets {
		keys = append(keys, b)
	}
	sort.Ints(keys)
	want := int64(math.Ceil(q * float64(h.count)))
	want = max(want, 1)
	var seen int64
	for _, b := range keys {
		seen += h.buckets[b]
		if seen >= want {
			return min(bucketValue(b), h.max)
		}
	}
	return h.max
}

// Max is the largest sample.
func (h *Histogram) Max() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.max
}

// LatencySummary is a histogram as the report shows it.
type LatencySummary struct {
	Count int64   `json:"count"`
	P50   float64 `json:"p50_ms"`
	P95   float64 `json:"p95_ms"`
	P99   float64 `json:"p99_ms"`
	Max   float64 `json:"max_ms"`
}

func ms(d time.Duration) float64 { return math.Round(float64(d)/float64(time.Millisecond)*100) / 100 }

func (h *Histogram) Summary() LatencySummary {
	return LatencySummary{Count: h.Count(), P50: ms(h.Quantile(0.5)), P95: ms(h.Quantile(0.95)),
		P99: ms(h.Quantile(0.99)), Max: ms(h.Max())}
}

// Metrics holds the counters and latencies of a run, by phase.
type Metrics struct {
	mu     sync.Mutex
	phase  string
	order  []string
	hists  map[string]map[string]*Histogram
	counts map[string]map[string]*atomic.Int64
	// gauges are values set once, such as a takeover time.
	gauges map[string]map[string]float64
}

func newMetrics() *Metrics {
	return &Metrics{hists: map[string]map[string]*Histogram{}, counts: map[string]map[string]*atomic.Int64{},
		gauges: map[string]map[string]float64{}}
}

// SetPhase makes later samples count for phase.
func (m *Metrics) SetPhase(phase string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.phase = phase
	if _, ok := m.hists[phase]; !ok {
		m.order = append(m.order, phase)
		m.hists[phase] = map[string]*Histogram{}
		m.counts[phase] = map[string]*atomic.Int64{}
		m.gauges[phase] = map[string]float64{}
	}
}

// Phase is the phase samples count for now.
func (m *Metrics) Phase() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.phase
}

func (m *Metrics) ensure(phase string) {
	if _, ok := m.hists[phase]; !ok {
		m.order = append(m.order, phase)
		m.hists[phase] = map[string]*Histogram{}
		m.counts[phase] = map[string]*atomic.Int64{}
		m.gauges[phase] = map[string]float64{}
	}
}

// Observe adds a latency sample to the current phase.
func (m *Metrics) Observe(name string, d time.Duration) {
	m.mu.Lock()
	m.ensure(m.phase)
	h, ok := m.hists[m.phase][name]
	if !ok {
		h = newHistogram()
		m.hists[m.phase][name] = h
	}
	m.mu.Unlock()
	h.Observe(d)
}

// Add adds n to a counter of the current phase.
func (m *Metrics) Add(name string, n int64) {
	m.mu.Lock()
	m.ensure(m.phase)
	c, ok := m.counts[m.phase][name]
	if !ok {
		c = &atomic.Int64{}
		m.counts[m.phase][name] = c
	}
	m.mu.Unlock()
	c.Add(n)
}

// Set records a value for phase ("" for the current one); a later value
// for the same name wins only when larger.
func (m *Metrics) Set(phase, name string, v float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if phase == "" {
		phase = m.phase
	}
	m.ensure(phase)
	if old, ok := m.gauges[phase][name]; !ok || v > old {
		m.gauges[phase][name] = v
	}
}

// Hist is the latencies of name in phase, or in every phase when phase is
// empty.
func (m *Metrics) Hist(phase, name string) *Histogram {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := newHistogram()
	for p, hs := range m.hists {
		if phase != "" && p != phase {
			continue
		}
		if h, ok := hs[name]; ok {
			out.Merge(h)
		}
	}
	return out
}

// Count is the counter name in phase, or in every phase when phase is
// empty.
func (m *Metrics) Count(phase, name string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for p, cs := range m.counts {
		if phase != "" && p != phase {
			continue
		}
		if c, ok := cs[name]; ok {
			n += c.Load()
		}
	}
	return n
}

// Gauge is the largest value set for name in phase (or any phase), and
// whether one was.
func (m *Metrics) Gauge(phase, name string) (float64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best float64
	found := false
	for p, gs := range m.gauges {
		if phase != "" && p != phase {
			continue
		}
		if v, ok := gs[name]; ok && (!found || v > best) {
			best, found = v, true
		}
	}
	return best, found
}

// phaseView is one phase's numbers for the report.
func (m *Metrics) phaseView(phase string) (map[string]int64, map[string]LatencySummary, map[string]float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := map[string]int64{}
	for n, c := range m.counts[phase] {
		counts[n] = c.Load()
	}
	lat := map[string]LatencySummary{}
	for n, h := range m.hists[phase] {
		lat[n] = h.Summary()
	}
	gauges := map[string]float64{}
	for n, v := range m.gauges[phase] {
		gauges[n] = v
	}
	return counts, lat, gauges
}
