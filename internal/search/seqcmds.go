package search

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// applyAccum sets each row's running total of c.Field; rows without a
// number keep no total.
func applyAccum(ctx context.Context, res *Result, c *query.Accum) error {
	name := c.AccumName()
	sum, any_ := 0.0, false
	ev := evaluatorFor(ctx)
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		n, ok := evNum(r[c.Field])
		if !ok {
			continue
		}
		if !ev.newField(r, name) {
			return ev.err
		}
		sum += n
		r[name] = numOut(sum)
		any_ = true
	}
	if any_ {
		addColumn(res, name)
	}
	return nil
}

// applyDelta sets each row with a number in c.Field to that number minus
// the one c.P rows-with-a-number earlier.
func applyDelta(ctx context.Context, res *Result, c *query.Delta) error {
	name := c.DeltaName()
	ev := evaluatorFor(ctx)
	var ring []float64
	next, added := 0, false
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		n, ok := evNum(r[c.Field])
		if !ok {
			continue
		}
		if len(ring) < c.P {
			ring = append(ring, n)
			continue
		}
		if !ev.newField(r, name) {
			return ev.err
		}
		r[name] = numOut(n - ring[next])
		added = true
		ring[next] = n
		next = (next + 1) % c.P
	}
	if added {
		addColumn(res, name)
	}
	return nil
}

// applyAutoRegress copies c.Field from the rows c.PFrom to c.PTo before
// each row; a row too near the start gets no copy from before it.
func applyAutoRegress(ctx context.Context, res *Result, c *query.AutoRegress) error {
	names := c.Names()
	ev := evaluatorFor(ctx)
	added := make([]bool, len(names))
	// Each row's value is read before the row gets its copies, so a
	// field copied onto itself (AS Field) still copies the old value.
	var prev []any
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		prev = append(prev, r[c.Field])
		for j := range names {
			back := c.PFrom + j
			if back > i {
				break
			}
			v := prev[i-back]
			if v == nil {
				continue
			}
			if !ev.newField(r, names[j]) || !ev.charge(valueSize(v)) {
				return ev.err
			}
			r[names[j]] = v
			added[j] = true
		}
	}
	for j, name := range names {
		if added[j] {
			addColumn(res, name)
		}
	}
	return nil
}

const (
	// maxSummaryFields caps the fields fieldsummary describes.
	maxSummaryFields = 1000
	// maxSummaryDistinct caps the distinct values counted per field;
	// past it, distinct_count is a lower bound and is_exact is 0.
	maxSummaryDistinct = 10000
)

type fieldStats struct {
	count, numeric int64
	min, max       float64
	sum, sumSq     float64
	values         map[string]int64
	exact          bool
}

// applyFieldSummary replaces the rows with one per field, as Splunk's
// fieldsummary: field, count, distinct_count, is_exact, max, mean, min,
// numeric_count, stdev and values, its most common values with counts.
func applyFieldSummary(ctx context.Context, res *Result, c *query.FieldSummary) error {
	ev := evaluatorFor(ctx)
	stats := map[string]*fieldStats{}
	wanted := fieldMatcher(ev, len(c.Fields), func(f string) bool {
		if strings.HasPrefix(f, "\x00") {
			return false
		}
		if len(c.Fields) == 0 {
			return true
		}
		for _, p := range c.Fields {
			if query.MatchField(p, f) {
				return true
			}
		}
		return false
	})
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		for f, v := range r {
			if v == nil {
				continue
			}
			want, ok := wanted(f)
			if !ok {
				return ev.err
			}
			if !want {
				continue
			}
			s := stats[f]
			if s == nil {
				if len(stats) >= maxSummaryFields {
					res.Truncated = true
					continue
				}
				if !ev.charge(len(f) + fieldOverhead) {
					return ev.err
				}
				s = &fieldStats{values: map[string]int64{}, exact: true, min: math.Inf(1), max: math.Inf(-1)}
				stats[f] = s
			}
			s.count++
			for _, e := range asList(v) {
				if !ev.step() {
					return ev.err
				}
				if n, ok := evNum(e); ok {
					s.numeric++
					s.min, s.max = math.Min(s.min, n), math.Max(s.max, n)
					s.sum += n
					s.sumSq += n * n
				}
				k, _ := evStr(e)
				if _, seen := s.values[k]; seen {
					s.values[k]++
					continue
				}
				if len(s.values) >= maxSummaryDistinct {
					s.exact = false
					continue
				}
				if !ev.charge(len(k) + fieldOverhead) {
					return ev.err
				}
				s.values[k] = 1
			}
		}
	}
	names := make([]string, 0, len(stats))
	for f := range stats {
		names = append(names, f)
	}
	sort.Strings(names)
	type valueCount struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	}
	rows := make([]Row, 0, len(names))
	for _, f := range names {
		s := stats[f]
		top := make([]valueCount, 0, len(s.values))
		for v, n := range s.values {
			top = append(top, valueCount{v, n})
		}
		sort.Slice(top, func(i, j int) bool {
			if top[i].Count != top[j].Count {
				return top[i].Count > top[j].Count
			}
			return top[i].Value < top[j].Value
		})
		top = top[:min(len(top), c.MaxVals)]
		vals, _ := json.Marshal(top)
		if !ev.charge(len(vals)) {
			return ev.err
		}
		exact := int64(1)
		if !s.exact {
			exact = 0
		}
		row := Row{"field": f, "count": s.count, "distinct_count": int64(len(s.values)), "is_exact": exact,
			"numeric_count": s.numeric, "values": string(vals)}
		if s.numeric > 0 {
			mean := s.sum / float64(s.numeric)
			row["min"], row["max"], row["mean"] = numOut(s.min), numOut(s.max), numOut(mean)
			if s.numeric > 1 {
				variance := (s.sumSq - float64(s.numeric)*mean*mean) / float64(s.numeric-1)
				row["stdev"] = numOut(math.Sqrt(math.Max(variance, 0)))
			}
		}
		rows = append(rows, row)
	}
	res.Kind = "table"
	res.Rows = rows
	res.Columns = []string{"field", "count", "distinct_count", "is_exact", "max", "mean", "min", "numeric_count", "stdev", "values"}
	return nil
}
