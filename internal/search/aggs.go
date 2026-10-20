// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// maxAggValues caps the values list() returns per group, and values()
// when stats runs in OpenSearch; a result that reaches the cap is marked
// truncated.
const maxAggValues = 100

// maxValues caps the values values() returns per group when stats runs in
// Signalith, as Splunk's default limit does.
const maxValues = 10000

// metricAgg returns the OpenSearch aggregation for one stats function, or
// nil when the bucket's doc_count already answers it (a bare count).
func metricAgg(a query.Agg) (map[string]any, error) {
	field := a.Field
	if field == "_time" {
		field = TimeField
	}
	if field == IndexField {
		// _index is not in an event's _source and holds no numbers.
		switch a.Func {
		case "count", "dc", "values", "mode":
			field = indexMeta
		default:
			return nil, fmt.Errorf("%s(index) is not supported; index works with count, dc, values and mode", a.Func)
		}
	}
	byTime := func(order string, size int) map[string]any {
		return map[string]any{
			"filter": map[string]any{"exists": map[string]any{"field": field}},
			"aggs": map[string]any{"h": map[string]any{"top_hits": map[string]any{
				"size":    size,
				"_source": map[string]any{"includes": []any{field}},
				"sort":    []any{map[string]any{TimeField: map[string]any{"order": order, "unmapped_type": "date"}}},
			}}},
		}
	}
	if n := query.Percentile(a.Func); n > 0 {
		return map[string]any{"percentiles": map[string]any{"field": field, "percents": []any{n}, "keyed": false}}, nil
	}
	switch a.Func {
	case "count":
		if field == "" {
			return nil, nil // doc_count
		}
		return map[string]any{"value_count": map[string]any{"field": field}}, nil
	case "dc":
		return map[string]any{"cardinality": map[string]any{"field": field}}, nil
	case "sum", "avg", "min", "max":
		return map[string]any{a.Func: map[string]any{"field": field}}, nil
	case "median":
		return map[string]any{"percentiles": map[string]any{"field": field, "percents": []any{50}, "keyed": false}}, nil
	case "stdev", "var", "stdevp", "varp", "sumsq":
		return map[string]any{"extended_stats": map[string]any{"field": field}}, nil
	case "range":
		return map[string]any{"stats": map[string]any{"field": field}}, nil
	case "values":
		return map[string]any{"terms": map[string]any{"field": field, "size": maxAggValues, "order": map[string]any{"_key": "asc"}}}, nil
	case "mode":
		return map[string]any{"terms": map[string]any{"field": field, "size": 1}}, nil
	case "list":
		return byTime("desc", maxAggValues), nil
	case "first", "latest":
		return byTime("desc", 1), nil
	case "last", "earliest":
		return byTime("asc", 1), nil
	}
	return nil, fmt.Errorf("unsupported function %q", a.Func)
}

// aggClipped reports whether values() or list(), run in OpenSearch, left
// values out of the aggregation named name inside container.
func aggClipped(a query.Agg, container map[string]any, name string) bool {
	m, _ := container[name].(map[string]any)
	switch a.Func {
	case "values":
		n, _ := asFloat(toNumber(m["sum_other_doc_count"]))
		return n > 0
	case "list":
		n, _ := asFloat(toNumber(m["doc_count"]))
		return n > maxAggValues
	}
	return false
}

// aggValue reads one stats function's result from the aggregation named
// name inside container (the response's aggregations or a bucket).
func aggValue(a query.Agg, container map[string]any, name string) any {
	v := rawAggValue(a, container, name)
	if a.Field == "_time" {
		return timeSeconds(a, v)
	}
	return v
}

// timeSeconds converts a number OpenSearch computed over event times,
// in milliseconds since 1970, to seconds, as Splunk gives _time: min,
// max, avg and the rest are epoch seconds, var is in seconds squared.
// Other values (values(), first() and so on) pass through.
func timeSeconds(a query.Agg, v any) any {
	f, ok := asFloat(v)
	if !ok {
		return v
	}
	switch {
	case a.Func == "var", a.Func == "varp", a.Func == "sumsq":
		return numOut(f / 1e6)
	case a.Func == "min", a.Func == "max", a.Func == "avg", a.Func == "sum", a.Func == "range",
		a.Func == "median", a.Func == "stdev", a.Func == "stdevp", query.Percentile(a.Func) > 0:
		return numOut(f / 1e3)
	}
	return v
}

func rawAggValue(a query.Agg, container map[string]any, name string) any {
	m, _ := container[name].(map[string]any)
	if m == nil {
		return nil
	}
	field := a.Field
	if field == "_time" {
		field = TimeField
	}
	num := func(v any) (float64, bool) {
		f, ok := asFloat(toNumber(v))
		return f, ok
	}
	switch {
	case query.Percentile(a.Func) > 0 || a.Func == "median":
		vals, _ := m["values"].([]any)
		if len(vals) == 0 {
			return nil
		}
		v, _ := vals[0].(map[string]any)
		return toNumber(v["value"])
	}
	switch a.Func {
	case "stdev", "var":
		n, ok1 := num(m["count"])
		v, ok2 := num(m["variance"])
		if !ok1 || !ok2 || n < 1 {
			return nil
		}
		if n == 1 {
			// One value varies by nothing; Splunk gives 0.
			return int64(0)
		}
		sample := v * n / (n - 1) // OpenSearch reports the population variance
		if a.Func == "stdev" {
			return numOut(math.Sqrt(sample))
		}
		return numOut(sample)
	case "stdevp", "varp":
		n, ok1 := num(m["count"])
		v, ok2 := num(m["variance"])
		if !ok1 || !ok2 || n < 1 {
			return nil
		}
		if a.Func == "stdevp" {
			return numOut(math.Sqrt(math.Max(v, 0)))
		}
		return numOut(math.Max(v, 0))
	case "sumsq":
		n, ok1 := num(m["count"])
		v, ok2 := num(m["sum_of_squares"])
		if !ok1 || !ok2 || n < 1 {
			return nil
		}
		return numOut(v)
	case "range":
		lo, ok1 := num(m["min"])
		hi, ok2 := num(m["max"])
		if !ok1 || !ok2 {
			return nil
		}
		return numOut(hi - lo)
	case "values", "mode":
		bs, _ := m["buckets"].([]any)
		var out []any
		for _, b := range bs {
			bm, _ := b.(map[string]any)
			k := bm["key_as_string"]
			if k == nil {
				k = bm["key"]
			}
			out = append(out, normalize(k))
		}
		return mvOut(out)
	case "list", "first", "last", "earliest", "latest":
		h, _ := m["h"].(map[string]any)
		hits, _ := h["hits"].(map[string]any)
		hs, _ := hits["hits"].([]any)
		var out []any
		for _, x := range hs {
			hm, _ := x.(map[string]any)
			src, _ := hm["_source"].(map[string]any)
			row := Row{}
			flatten("", src, row)
			if v, ok := row[field]; ok && v != nil {
				out = append(out, v)
			}
		}
		return mvOut(out)
	}
	return toNumber(m["value"])
}

// aggState collects one stats function's values for one group, for
// stats that run in the server.
type aggState struct {
	count    int64
	sum      float64
	numeric  int64
	min, max float64
	distinct map[string]any // each value's text, and the first value with it
	clipped  bool           // values() or list() left values out
	sumsq    float64
	nums     []float64 // for median, percentiles, stdev and var
	vals     []any     // values in row order, for list, first, last and mode
	times    []time.Time
}

func newAggState() *aggState {
	return &aggState{min: math.Inf(1), max: math.Inf(-1), distinct: map[string]any{}}
}

func (s *aggState) add(a query.Agg, v any, r Row) {
	s.count++
	if a.Func == "dc" || a.Func == "values" {
		for _, x := range asList(v) {
			k, _ := evStr(x)
			if _, seen := s.distinct[k]; seen {
				continue
			}
			if a.Func == "values" && len(s.distinct) >= maxValues {
				s.clipped = true
				break
			}
			s.distinct[k] = x
		}
	}
	f, ok := asFloat(v)
	if !ok && a.Field == "_time" {
		// Events carry _time as text; its number is epoch seconds.
		if t, isTime := toTime(v); isTime {
			f, ok = float64(t.Unix())+float64(t.Nanosecond())/1e9, true
		}
	}
	if ok {
		s.numeric++
		s.sum += f
		s.sumsq += f * f
		s.min = math.Min(s.min, f)
		s.max = math.Max(s.max, f)
		switch a.Func {
		case "median", "stdev", "var", "stdevp", "varp":
			s.nums = append(s.nums, f)
		default:
			if query.Percentile(a.Func) > 0 {
				s.nums = append(s.nums, f)
			}
		}
	}
	switch a.Func {
	case "list", "first", "last", "mode", "earliest", "latest":
		s.vals = append(s.vals, v)
		if a.Func == "earliest" || a.Func == "latest" {
			t, _ := toTime(r["_time"])
			s.times = append(s.times, t)
		}
	}
}

func (s *aggState) result(a query.Agg) any {
	if n := query.Percentile(a.Func); n > 0 {
		return percentile(s.nums, float64(n))
	}
	switch a.Func {
	case "count":
		return s.count
	case "dc":
		return int64(len(s.distinct))
	case "sum":
		// No numbers to add up gives nothing, as in Splunk, not 0.
		if s.numeric > 0 {
			return toNumber(s.sum)
		}
	case "avg":
		if s.numeric > 0 {
			return s.sum / float64(s.numeric)
		}
	case "min":
		if s.numeric > 0 {
			return toNumber(s.min)
		}
	case "max":
		if s.numeric > 0 {
			return toNumber(s.max)
		}
	case "range":
		if s.numeric > 0 {
			return toNumber(s.max - s.min)
		}
	case "median":
		return percentile(s.nums, 50)
	case "sumsq":
		if s.numeric > 0 {
			return toNumber(s.sumsq)
		}
	case "stdev", "var", "stdevp", "varp":
		n := float64(len(s.nums))
		if n < 1 {
			return nil
		}
		population := a.Func == "stdevp" || a.Func == "varp"
		if n == 1 && !population {
			// One value varies by nothing; Splunk gives 0.
			return int64(0)
		}
		mean := 0.0
		for _, f := range s.nums {
			mean += f
		}
		mean /= n
		ss := 0.0
		for _, f := range s.nums {
			ss += (f - mean) * (f - mean)
		}
		v := ss / (n - 1)
		if population {
			v = ss / n
		}
		if a.Func == "stdev" || a.Func == "stdevp" {
			return numOut(math.Sqrt(v))
		}
		return numOut(v)
	case "values":
		// Sorted as text, as Splunk does, each keeping its type.
		var keys []string
		for k := range s.distinct {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []any
		for _, k := range keys {
			out = append(out, s.distinct[k])
		}
		return mvOut(out)
	case "list":
		var out []any
		for _, v := range s.vals {
			out = append(out, asList(v)...)
			if len(out) >= maxAggValues {
				s.clipped = s.clipped || len(out) > maxAggValues
				out = out[:maxAggValues]
				break
			}
		}
		return mvOut(out)
	case "first":
		if len(s.vals) > 0 {
			return s.vals[0]
		}
	case "last":
		if len(s.vals) > 0 {
			return s.vals[len(s.vals)-1]
		}
	case "earliest", "latest":
		best := -1
		for i, t := range s.times {
			if best < 0 || a.Func == "earliest" && t.Before(s.times[best]) || a.Func == "latest" && t.After(s.times[best]) {
				best = i
			}
		}
		if best >= 0 {
			return s.vals[best]
		}
	case "mode":
		counts := map[string]int{}
		var best any
		bestN := 0
		for _, v := range s.vals {
			k, _ := evStr(v)
			counts[k]++
			if counts[k] > bestN {
				best, bestN = v, counts[k]
			}
		}
		return best
	}
	return nil
}

// percentile interpolates between the closest ranks, as most tools do.
func percentile(nums []float64, p float64) any {
	if len(nums) == 0 {
		return nil
	}
	s := append([]float64(nil), nums...)
	sort.Float64s(s)
	rank := p / 100 * float64(len(s)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	f := s[lo] + (s[hi]-s[lo])*(rank-float64(lo))
	return numOut(f)
}
