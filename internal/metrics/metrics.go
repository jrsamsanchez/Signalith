// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package metrics writes Signalith's metrics in the Prometheus text
// exposition format (0.0.4) or in OpenMetrics 1.0, for GET /metrics, and
// keeps the few counters and histograms the rest of the server records.
// It has no dependency: the formats are small, and every metric is named
// and labelled here or by its caller with a fixed set of values, so no
// sender, user or event can add a series.
package metrics

import (
	"bytes"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// Content types of the two formats.
const (
	ContentTypeText        = "text/plain; version=0.0.4; charset=utf-8"
	ContentTypeOpenMetrics = "application/openmetrics-text; version=1.0.0; charset=utf-8"
)

// WantsOpenMetrics reports whether a scraper's Accept header asks for
// OpenMetrics, as Prometheus does when it can read it.
func WantsOpenMetrics(accept string) bool {
	return strings.Contains(accept, "application/openmetrics-text")
}

// Histogram counts observations in fixed buckets. It is safe for
// concurrent use; Observe takes no lock.
type Histogram struct {
	bounds []float64
	counts []atomic.Uint64
	count  atomic.Uint64
	sum    atomic.Uint64 // math.Float64bits of the sum
}

// NewHistogram returns a histogram with the given upper bounds, which
// must be in increasing order; +Inf is added by itself.
func NewHistogram(bounds ...float64) *Histogram {
	b := append([]float64(nil), bounds...)
	sort.Float64s(b)
	return &Histogram{bounds: b, counts: make([]atomic.Uint64, len(b))}
}

// Observe records one value.
func (h *Histogram) Observe(v float64) {
	if math.IsNaN(v) {
		return
	}
	if i := sort.SearchFloat64s(h.bounds, v); i < len(h.bounds) {
		h.counts[i].Add(1)
	}
	h.count.Add(1)
	for {
		old := h.sum.Load()
		if h.sum.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+v)) {
			return
		}
	}
}

// HistogramSnapshot is a histogram at one moment: Cumulative[i] counts the
// observations at most Bounds[i].
type HistogramSnapshot struct {
	Bounds     []float64
	Cumulative []uint64
	Count      uint64
	Sum        float64
}

// Snapshot reads the histogram.
func (h *Histogram) Snapshot() HistogramSnapshot {
	s := HistogramSnapshot{Bounds: h.bounds, Cumulative: make([]uint64, len(h.bounds))}
	var run uint64
	for i := range h.counts {
		run += h.counts[i].Load()
		s.Cumulative[i] = run
	}
	s.Count = h.count.Load()
	if s.Count < run {
		// An Observe between the reads: keep the buckets consistent.
		s.Count = run
	}
	s.Sum = math.Float64frombits(h.sum.Load())
	return s
}

// Label is one label of a sample.
type Label struct{ Name, Value string }

// Sample is one value of a metric family, with its labels.
type Sample struct {
	Labels []Label
	Value  float64
}

// L is a short way to write one sample with labels in name, value pairs.
func L(v float64, nameValues ...string) Sample {
	s := Sample{Value: v}
	for i := 0; i+1 < len(nameValues); i += 2 {
		s.Labels = append(s.Labels, Label{nameValues[i], nameValues[i+1]})
	}
	return s
}

// Writer writes metric families in one of the two formats.
type Writer struct {
	buf         bytes.Buffer
	openMetrics bool
}

// NewWriter returns a writer of OpenMetrics when openMetrics is true, else
// of the Prometheus text format.
func NewWriter(openMetrics bool) *Writer { return &Writer{openMetrics: openMetrics} }

// ContentType is the Content-Type of what the writer writes.
func (w *Writer) ContentType() string {
	if w.openMetrics {
		return ContentTypeOpenMetrics
	}
	return ContentTypeText
}

// Bytes ends the exposition and returns it.
func (w *Writer) Bytes() []byte {
	if w.openMetrics {
		w.buf.WriteString("# EOF\n")
	}
	return w.buf.Bytes()
}

func (w *Writer) head(name, typ, help string) {
	w.buf.WriteString("# HELP ")
	w.buf.WriteString(name)
	w.buf.WriteByte(' ')
	w.buf.WriteString(escapeHelp(help))
	w.buf.WriteString("\n# TYPE ")
	w.buf.WriteString(name)
	w.buf.WriteByte(' ')
	w.buf.WriteString(typ)
	w.buf.WriteByte('\n')
}

func (w *Writer) sample(name string, labels []Label, v float64) {
	w.buf.WriteString(name)
	if len(labels) > 0 {
		w.buf.WriteByte('{')
		for i, l := range labels {
			if i > 0 {
				w.buf.WriteByte(',')
			}
			w.buf.WriteString(l.Name)
			w.buf.WriteString(`="`)
			w.buf.WriteString(escapeLabel(l.Value))
			w.buf.WriteByte('"')
		}
		w.buf.WriteByte('}')
	}
	w.buf.WriteByte(' ')
	w.buf.WriteString(formatFloat(v))
	w.buf.WriteByte('\n')
}

// Gauge writes a gauge family.
func (w *Writer) Gauge(name, help string, samples ...Sample) {
	if len(samples) == 0 {
		return
	}
	w.head(name, "gauge", help)
	for _, s := range samples {
		w.sample(name, s.Labels, s.Value)
	}
}

// Counter writes a counter family. name is without the _total suffix,
// which every sample gets.
func (w *Writer) Counter(name, help string, samples ...Sample) {
	if len(samples) == 0 {
		return
	}
	family := name
	if !w.openMetrics {
		// The text format names the family as its samples.
		family = name + "_total"
	}
	w.head(family, "counter", help)
	for _, s := range samples {
		w.sample(name+"_total", s.Labels, s.Value)
	}
}

// Info writes an info metric, whose one sample is 1 with labels. name is
// without the _info suffix.
func (w *Writer) Info(name, help string, labels ...Label) {
	if w.openMetrics {
		w.head(name, "info", help)
	} else {
		w.head(name+"_info", "gauge", help)
	}
	w.sample(name+"_info", labels, 1)
}

// Histogram writes a histogram family.
func (w *Writer) Histogram(name, help string, h HistogramSnapshot) {
	w.head(name, "histogram", help)
	for i, b := range h.Bounds {
		w.sample(name+"_bucket", []Label{{"le", formatFloat(b)}}, float64(h.Cumulative[i]))
	}
	w.sample(name+"_bucket", []Label{{"le", "+Inf"}}, float64(h.Count))
	w.sample(name+"_sum", nil, h.Sum)
	w.sample(name+"_count", nil, float64(h.Count))
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)

func escapeLabel(s string) string { return labelEscaper.Replace(s) }
func escapeHelp(s string) string  { return helpEscaper.Replace(s) }
