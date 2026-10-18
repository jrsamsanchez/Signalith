package search

import (
	"container/heap"
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// endHeap holds the end times of the rows still in progress, soonest first.
type endHeap []float64

func (h endHeap) Len() int           { return len(h) }
func (h endHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h endHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *endHeap) Push(x any)        { *h = append(*h, x.(float64)) }
func (h *endHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// applyConcurrency sets c.Output on each row with a start time and a
// duration to how many rows were in progress when it started: itself,
// and the rows that started no later and had not yet ended. Rows that
// start at the same time count each other.
func applyConcurrency(ctx context.Context, res *Result, c *query.Concurrency) error {
	ev := evaluatorFor(ctx)
	type span struct {
		row        int
		start, end float64
	}
	var spans []span
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		t, ok := toTime(r[c.Start])
		if !ok {
			continue
		}
		d, ok := evNum(r[c.Duration])
		if !ok || !finite(d) || d < 0 {
			continue
		}
		s := float64(t.Unix()) + float64(t.Nanosecond())/1e9
		spans = append(spans, span{i, s, s + d})
	}
	if len(spans) == 0 {
		return nil
	}
	sort.SliceStable(spans, func(a, b int) bool { return spans[a].start < spans[b].start })
	// Each row costs a push and a pop on the heap.
	if !ev.stepN(2 * len(spans) * (bitsLen(len(spans)) + 1)) {
		return ev.err
	}
	var active endHeap
	for i := 0; i < len(spans); {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		s := spans[i].start
		j := i
		for j < len(spans) && spans[j].start == s {
			j++
		}
		for active.Len() > 0 && active[0] <= s {
			heap.Pop(&active)
		}
		instant := 0 // rows here that end as they start
		for _, sp := range spans[i:j] {
			if sp.end > s {
				heap.Push(&active, sp.end)
			} else {
				instant++
			}
		}
		n := int64(active.Len() + instant)
		for _, sp := range spans[i:j] {
			r := res.Rows[sp.row]
			if !ev.newField(r, c.Output) {
				return ev.err
			}
			r[c.Output] = n
		}
		i = j
	}
	addColumn(res, c.Output)
	return nil
}

func bitsLen(n int) int {
	b := 0
	for ; n > 0; n >>= 1 {
		b++
	}
	return b
}

// applyContingency replaces the rows with a table counting each pair of
// c.RowField and c.ColField values: one row per row value and one column
// per column value, the most common first, with totals when c.UseTotal.
func applyContingency(ctx context.Context, res *Result, c *query.Contingency) error {
	ev := evaluatorFor(ctx)
	type pair struct{ r, c string }
	counts := map[pair]int64{}
	rowTotal, colTotal := map[string]int64{}, map[string]int64{}
	var grand int64
	values := func(v any) []string {
		var out []string
		for _, e := range asList(v) {
			if _, multi := e.([]any); multi {
				continue
			}
			if s, ok := evStr(e); ok {
				out = append(out, s)
			}
		}
		return out
	}
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		rs, cs := values(r[c.RowField]), values(r[c.ColField])
		if !ev.stepN(len(rs)*len(cs) + 1) {
			return ev.err
		}
		for _, a := range rs {
			for _, b := range cs {
				k := pair{a, b}
				if _, ok := counts[k]; !ok && !ev.charge(len(a)+len(b)+fieldOverhead) {
					return ev.err
				}
				counts[k]++
				rowTotal[a]++
				colTotal[b]++
				grand++
			}
		}
	}
	byCount := func(m map[string]int64, max int) []string {
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if m[keys[i]] != m[keys[j]] {
				return m[keys[i]] > m[keys[j]]
			}
			return keys[i] < keys[j]
		})
		if len(keys) > max {
			keys = keys[:max]
		}
		return keys
	}
	rowVals, colVals := byCount(rowTotal, c.MaxRows), byCount(colTotal, c.MaxCols)
	// A column value may be the row field's name or the total's.
	used := map[string]bool{c.RowField: true}
	if c.UseTotal {
		used[c.TotalStr] = true
	}
	var cols []string
	for _, v := range colVals {
		name := v
		for n := 2; used[name]; n++ {
			name = v + "_" + strconv.Itoa(n)
		}
		used[name] = true
		cols = append(cols, name)
	}
	width := len(cols) + 1
	if c.UseTotal {
		width++
	}
	var rows []Row
	for _, rv := range rowVals {
		if !ev.stepN(width) || !ev.charge(width*(fieldOverhead+8)+len(rv)) {
			return ev.err
		}
		row := Row{c.RowField: rv}
		for i, cv := range colVals {
			row[cols[i]] = counts[pair{rv, cv}]
		}
		if c.UseTotal {
			row[c.TotalStr] = rowTotal[rv]
		}
		rows = append(rows, row)
	}
	if c.UseTotal {
		if !ev.stepN(width) || !ev.charge(width*(fieldOverhead+8)+len(c.TotalStr)) {
			return ev.err
		}
		row := Row{c.RowField: c.TotalStr}
		for i, cv := range colVals {
			row[cols[i]] = colTotal[cv]
		}
		row[c.TotalStr] = grand
		rows = append(rows, row)
	}
	columns := append([]string{c.RowField}, cols...)
	if c.UseTotal {
		columns = append(columns, c.TotalStr)
	}
	res.Rows, res.Columns, res.Kind = rows, columns, "table"
	return nil
}

// applyFormat replaces the rows with one row whose search field matches
// them: ( ( a="1" AND b="2" ) OR ( a="3" ) ). Fields whose names start
// with _ are left out; a multivalue field becomes ( a="1" OR a="2" ).
func applyFormat(ctx context.Context, res *Result, c *query.Format) error {
	ev := evaluatorFor(ctx)
	var fields []string
	for _, f := range res.Columns {
		if !strings.HasPrefix(f, "_") && !strings.HasPrefix(f, "\x00") && f != RawField {
			fields = append(fields, f)
		}
	}
	rows := res.Rows
	if c.MaxResults > 0 && len(rows) > c.MaxResults {
		rows = rows[:c.MaxResults]
	}
	p := c.Parts
	var b strings.Builder
	wrote := 0
	for i, r := range rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		if !ev.stepN(len(fields) + 1) {
			return ev.err
		}
		var terms []string
		size := 0
		for _, f := range fields {
			v := r[f]
			if v == nil {
				continue
			}
			var t string
			if vs, multi := v.([]any); multi {
				var alts []string
				for _, e := range vs {
					if !ev.step() {
						return ev.err
					}
					if q, ok := searchTerm(f, e); ok {
						alts = append(alts, q)
					}
				}
				if len(alts) == 0 {
					continue
				}
				t = "( " + strings.Join(alts, " "+c.MVSep+" ") + " )"
			} else if q, ok := searchTerm(f, v); ok {
				t = q
			} else {
				continue
			}
			size += len(t)
			if !ev.fits(b.Len() + size) {
				return ev.err
			}
			terms = append(terms, t)
		}
		if len(terms) == 0 {
			// A row with no fields to match adds nothing.
			continue
		}
		if wrote > 0 {
			b.WriteString(" " + p[4] + " ")
		}
		b.WriteString(p[1] + " " + strings.Join(terms, " "+p[2]+" ") + " " + p[3])
		wrote++
	}
	out := "NOT ()"
	if wrote > 0 {
		out = p[0] + " " + b.String() + " " + p[5]
	}
	if !ev.fits(len(out)) || !ev.charge(len(out)+len(query.FormatField)+fieldOverhead) {
		return ev.err
	}
	res.Rows, res.Columns, res.Kind = []Row{{query.FormatField: out}}, []string{query.FormatField}, "table"
	return nil
}

// searchTerm writes name="value" so a search reads it back as that
// field and value.
func searchTerm(name string, v any) (string, bool) {
	s, ok := evStr(v)
	if !ok {
		return "", false
	}
	return query.FormatValue(name) + `="` + searchEscape(s) + `"`, true
}

func searchEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`)
}
