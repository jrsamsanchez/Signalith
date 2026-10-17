package search

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// maxExtractKey bounds the length of a key extract reads.
const maxExtractKey = 256

// applyExtract reads up to c.Limit key=value pairs from the first
// c.MaxChars bytes of each row's _raw into fields. A field the row
// already has keeps its value, and keys that start with _ or hold control
// characters are skipped.
func applyExtract(ctx context.Context, res *Result, c *query.Extract) error {
	ev := evaluatorFor(ctx)
	added := map[string]bool{}
	var order []string
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		s, ok := evStr(r[RawField])
		if !ok || s == "" {
			continue
		}
		if len(s) > c.MaxChars {
			s = s[:c.MaxChars]
		}
		if !ev.stepN(len(s)) {
			return ev.err
		}
		vals := map[string][]any{}
		var names []string
		for _, kv := range kvPairs(s, c.PairDelim, c.KVDelim, c.Limit) {
			key := kv[0]
			if c.CleanKeys {
				key = cleanKey(key)
			}
			if !extractKey(key) {
				continue
			}
			if _, had := r[key]; had {
				continue
			}
			if _, seen := vals[key]; !seen {
				names = append(names, key)
			} else if !c.MVAdd || len(vals[key]) >= maxMultiValues {
				continue
			}
			vals[key] = append(vals[key], kv[1])
		}
		for _, name := range names {
			if !added[name] && len(order) >= maxSpathNames {
				res.Truncated = true
				continue
			}
			v := mvOut(vals[name])
			if !ev.newField(r, name) || !ev.charge(valueSize(v)) {
				return ev.err
			}
			r[name] = v
			if !added[name] {
				added[name] = true
				order = append(order, name)
			}
		}
	}
	for _, name := range order {
		addColumn(res, name)
	}
	return nil
}

// kvPairs returns up to limit (key, value) pairs in s: pairs are split by
// any byte of pairDelim and keys from values by the first byte of kvDelim.
// A value in double quotes runs to the next double quote, delimiters and
// all. Pieces with no kvDelim and empty keys or values are skipped.
func kvPairs(s, pairDelim, kvDelim string, limit int) [][2]string {
	isPair := func(b byte) bool { return strings.IndexByte(pairDelim, b) >= 0 }
	isKV := func(b byte) bool { return strings.IndexByte(kvDelim, b) >= 0 }
	var out [][2]string
	for i := 0; i < len(s) && len(out) < limit; {
		for i < len(s) && isPair(s[i]) {
			i++
		}
		start := i
		for i < len(s) && !isPair(s[i]) && !isKV(s[i]) {
			i++
		}
		if i >= len(s) || !isKV(s[i]) {
			continue
		}
		key := strings.Trim(s[start:i], `"'`)
		i++
		vstart := i
		var val string
		if i < len(s) && s[i] == '"' {
			// No closing quote means no quote after this one, so this
			// scan to the end happens at most once per row.
			if n := strings.IndexByte(s[i+1:], '"'); n >= 0 {
				val, i = s[i+1:i+1+n], i+n+2
			}
		}
		if i == vstart {
			for i < len(s) && !isPair(s[i]) {
				i++
			}
			val = s[vstart:i]
		}
		if key != "" && val != "" {
			out = append(out, [2]string{key, val})
		}
	}
	return out
}

// cleanKey replaces each byte of k other than a letter, digit or _ with _.
func cleanKey(k string) string {
	b := []byte(k)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			b[i] = '_'
		}
	}
	return string(b)
}

// extractKey reports whether extract may write a field named k: not
// empty or too long, not starting with _ (the event's own fields), and
// with no control characters (internal fields start with one).
func extractKey(k string) bool {
	if k == "" || len(k) > maxExtractKey || k[0] == '_' {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x20 || k[i] == 0x7f {
			return false
		}
	}
	return true
}

// applyOutlier clamps each field's numbers above its 75th percentile plus
// c.Param times the interquartile range (and with c.UseLower, below its
// 25th percentile minus it) to that bound, or with c.Remove drops their
// rows.
func applyOutlier(ctx context.Context, res *Result, c *query.Outlier) error {
	ev := evaluatorFor(ctx)
	var fields []string
	seen := map[string]bool{}
	add := func(f string) {
		if !seen[f] && f != RawField && !strings.HasPrefix(f, "\x00") {
			seen[f] = true
			fields = append(fields, f)
		}
	}
	if len(c.Fields) == 0 {
		for _, f := range res.Columns {
			if !strings.HasPrefix(f, "_") {
				add(f)
			}
		}
	} else {
		for _, p := range c.Fields {
			if !strings.Contains(p, "*") {
				add(p)
				continue
			}
			for _, f := range res.Columns {
				if !ev.step() {
					return ev.err
				}
				if query.MatchField(p, f) {
					add(f)
				}
			}
		}
	}
	type bounds struct{ lo, hi float64 }
	limits := map[string]bounds{}
	for _, f := range fields {
		var nums []float64
		for i, r := range res.Rows {
			if i%checkEvery == 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			if !ev.step() {
				return ev.err
			}
			if n, ok := outlierNum(r[f]); ok {
				if !ev.charge(8) {
					return ev.err
				}
				nums = append(nums, n)
			}
		}
		if len(nums) == 0 {
			continue
		}
		sort.Float64s(nums)
		q1, q3 := rankValue(nums, 25), rankValue(nums, 75)
		iqr := q3 - q1
		limits[f] = bounds{q1 - c.Param*iqr, q3 + c.Param*iqr}
	}
	var rows []Row
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		drop := false
		for _, f := range fields {
			b, ok := limits[f]
			if !ok {
				continue
			}
			if !ev.step() {
				return ev.err
			}
			n, ok := outlierNum(r[f])
			if !ok {
				continue
			}
			bound := n
			if n > b.hi {
				bound = b.hi
			} else if c.UseLower && n < b.lo {
				bound = b.lo
			}
			if bound == n {
				continue
			}
			if c.Remove {
				drop = true
				break
			}
			v := numOut(bound)
			if c.Mark {
				v = "000" + strconv.FormatFloat(bound, 'f', -1, 64)
			}
			if !ev.charge(valueSize(v)) {
				return ev.err
			}
			r[f] = v
		}
		if !drop {
			rows = append(rows, r)
		}
	}
	res.Rows = rows
	return nil
}

// outlierNum reads a finite number from a single value.
func outlierNum(v any) (float64, bool) {
	if _, multi := v.([]any); multi || v == nil {
		return 0, false
	}
	n, ok := evNum(v)
	return n, ok && finite(n)
}

// rankValue interpolates the p-th percentile of sorted nums, as
// percentile does.
func rankValue(nums []float64, p float64) float64 {
	rank := p / 100 * float64(len(nums)-1)
	lo, hi := int(math.Floor(rank)), int(math.Ceil(rank))
	return nums[lo] + (nums[hi]-nums[lo])*(rank-float64(lo))
}

// applyGauge replaces the rows with one row for a gauge chart: x holds
// c.Value, a number or the first row's value of that field, and y1, y2,
// ... the range's bounds.
func applyGauge(ctx context.Context, res *Result, c *query.Gauge) error {
	ev := evaluatorFor(ctx)
	row := Row{}
	cols := []string{query.GaugeValueField}
	if f, err := strconv.ParseFloat(c.Value, 64); err == nil {
		row[query.GaugeValueField] = numOut(f)
	} else if len(res.Rows) > 0 && res.Rows[0][c.Value] != nil {
		row[query.GaugeValueField] = res.Rows[0][c.Value]
	}
	ranges := c.Range
	if len(ranges) == 0 {
		ranges = query.DefaultGaugeRange
	}
	for i, f := range ranges {
		name := "y" + strconv.Itoa(i+1)
		row[name] = numOut(f)
		cols = append(cols, name)
	}
	if !ev.charge(len(row) * (fieldOverhead + 16)) {
		return ev.err
	}
	res.Rows, res.Columns, res.Kind = []Row{row}, cols, "table"
	return nil
}
