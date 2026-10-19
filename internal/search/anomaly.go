// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"math"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// anomalyFields are the fields a command reads: the named ones, or every
// column except _raw, _ fields and internal ones.
func anomalyFields(res *Result, named []string) []string {
	if len(named) > 0 {
		return named
	}
	var out []string
	for _, f := range res.Columns {
		if f != RawField && !strings.HasPrefix(f, "_") && !strings.HasPrefix(f, "\x00") {
			out = append(out, f)
		}
	}
	return out
}

// applyAnomalyDetection scores each row by how likely its values are. A
// value's probability is, with the histogram method, the share of rows
// with the same value, and with zscore the two-sided normal probability
// of a number that far from the field's mean. A row whose least likely
// value is below c.PThresh is anomalous.
func applyAnomalyDetection(ctx context.Context, res *Result, c *query.AnomalyDetection) error {
	ev := evaluatorFor(ctx)
	fields := anomalyFields(res, c.Fields)
	n := len(res.Rows)
	counts := make([]map[string]int, len(fields))
	means := make([]float64, len(fields))
	stdevs := make([]float64, len(fields))
	for k, f := range fields {
		if c.Method == "histogram" {
			counts[k] = map[string]int{}
		}
		var sum, sq float64
		nums := 0
		for i, r := range res.Rows {
			if i%checkEvery == 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			if !ev.step() {
				return ev.err
			}
			v := r[f]
			if v == nil {
				continue
			}
			if c.Method == "histogram" {
				var b strings.Builder
				valueKey(&b, v)
				key := b.String()
				// Writing a long value's key costs more than a step.
				if !ev.stepN(len(key) / 16) {
					return ev.err
				}
				if _, seen := counts[k][key]; !seen && !ev.charge(len(key)+fieldOverhead) {
					return ev.err
				}
				counts[k][key]++
			} else if x, ok := outlierNum(v); ok {
				sum += x
				sq += x * x
				nums++
			}
		}
		if nums > 0 {
			means[k] = sum / float64(nums)
			stdevs[k] = math.Sqrt(math.Max(0, sq/float64(nums)-means[k]*means[k]))
		}
	}
	type score struct {
		logp  float64
		cause string
		minp  float64
	}
	var scores []score
	anomalies := 0
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		s := score{minp: 1}
		for k, f := range fields {
			if !ev.step() {
				return ev.err
			}
			v := r[f]
			if v == nil {
				continue
			}
			p := 1.0
			if c.Method == "histogram" {
				var b strings.Builder
				valueKey(&b, v)
				if !ev.stepN(b.Len() / 16) {
					return ev.err
				}
				p = float64(counts[k][b.String()]) / float64(n)
			} else if x, ok := outlierNum(v); ok && stdevs[k] > 0 {
				p = math.Erfc(math.Abs(x-means[k]) / stdevs[k] / math.Sqrt2)
			}
			if p > 0 {
				s.logp += math.Log(p)
			}
			if p < s.minp {
				s.minp, s.cause = p, f
			}
		}
		if s.minp < c.PThresh {
			anomalies++
		}
		scores = append(scores, s)
	}
	if c.Action == "summary" {
		row := Row{"num_events": int64(n), "num_anomalies": int64(anomalies), "method": c.Method, "pthresh": c.PThresh}
		if !ev.charge(4 * (fieldOverhead + 16)) {
			return ev.err
		}
		res.Rows, res.Columns, res.Kind = []Row{row}, []string{"num_anomalies", "num_events", "method", "pthresh"}, "table"
		return nil
	}
	var rows []Row
	for i, r := range res.Rows {
		s := scores[i]
		anomalous := s.minp < c.PThresh
		if c.Action == "filter" && !anomalous {
			continue
		}
		for _, f := range []string{"log_event_prob", "probable_cause", "probable_cause_freq", "isOutlier"} {
			if !ev.newField(r, f) {
				return ev.err
			}
		}
		if !ev.charge(len(s.cause) + 24) {
			return ev.err
		}
		r["log_event_prob"] = numOut(s.logp)
		if s.cause != "" {
			r["probable_cause"] = s.cause
			r["probable_cause_freq"] = numOut(s.minp)
		}
		r["isOutlier"] = int64(0)
		if anomalous {
			r["isOutlier"] = int64(1)
		}
		rows = append(rows, r)
	}
	res.Rows = rows
	for _, f := range []string{"log_event_prob", "probable_cause", "probable_cause_freq", "isOutlier"} {
		addColumn(res, f)
	}
	return nil
}

// applyCorrelate replaces the rows with one per field: RowField names it,
// and each field's column is the share of rows that have both.
func applyCorrelate(ctx context.Context, res *Result, c *query.Correlate) error {
	ev := evaluatorFor(ctx)
	fields := anomalyFields(res, c.Fields)
	if len(fields) > query.MaxCorrelateFields {
		fields, res.Truncated = fields[:query.MaxCorrelateFields], true
	}
	idx := map[string]int{}
	for i, f := range fields {
		idx[f] = i
	}
	both := make([][]int, len(fields))
	for i := range both {
		both[i] = make([]int, len(fields))
	}
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		var have []int
		for _, f := range fields {
			if r[f] != nil {
				have = append(have, idx[f])
			}
		}
		if !ev.stepN(len(fields) + len(have)*len(have)) {
			return ev.err
		}
		for _, a := range have {
			for _, b := range have {
				both[a][b]++
			}
		}
	}
	n := float64(len(res.Rows))
	var rows []Row
	for a, f := range fields {
		row := Row{query.CorrelateRowField: f}
		for b, g := range fields {
			if n > 0 {
				row[g] = numOut(float64(both[a][b]) / n)
			}
		}
		if !ev.charge(len(f) + len(fields)*(fieldOverhead+8)) {
			return ev.err
		}
		rows = append(rows, row)
	}
	res.Rows, res.Columns, res.Kind = rows, append([]string{query.CorrelateRowField}, fields...), "table"
	return nil
}
