package search

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// applyTranspose turns the first c.Rows rows into columns: one row per
// field, with its name in c.ColumnName and its value in each row in
// "row 1", "row 2" and so on, or in a column named by the row's
// c.HeaderField.
func applyTranspose(ctx context.Context, res *Result, c *query.Transpose) error {
	ev := evaluatorFor(ctx)
	rows := res.Rows
	if len(rows) > c.Rows {
		rows = rows[:c.Rows]
	}
	// Each row's column: its header value when it has a usable one.
	cols := make([]string, 0, len(rows))
	used := map[string]bool{c.ColumnName: true}
	for i, r := range rows {
		name := "row " + strconv.Itoa(i+1)
		if c.HeaderField != "" {
			if h, ok := evStr(r[c.HeaderField]); ok && h != "" && !used[h] {
				name = h
			}
		}
		// A header value may already be another row's name.
		for used[name] {
			name += "_" + strconv.Itoa(i+1)
		}
		if !ev.charge(len(name) + fieldOverhead) {
			return ev.err
		}
		used[name] = true
		cols = append(cols, name)
	}
	var out []Row
	for _, f := range res.Columns {
		if f == c.HeaderField || strings.HasPrefix(f, "\x00") {
			continue
		}
		if !ev.stepN(len(rows) + 1) {
			return ev.err
		}
		row := Row{c.ColumnName: f}
		empty := true
		for i, r := range rows {
			v := r[f]
			if v == nil {
				continue
			}
			if s, ok := v.(string); !ok || s != "" {
				empty = false
			}
			if !ev.charge(valueSize(v) + fieldOverhead) {
				return ev.err
			}
			row[cols[i]] = v
		}
		if empty && !c.IncludeEmpty {
			continue
		}
		if !ev.charge(len(f) + fieldOverhead) {
			return ev.err
		}
		out = append(out, row)
	}
	res.Rows, res.Columns, res.Kind = out, append([]string{c.ColumnName}, cols...), "table"
	return nil
}

// applyFillDown gives each row missing a field the field's last value in
// an earlier row: the fields c.Fields names, or every column.
func applyFillDown(ctx context.Context, res *Result, c *query.FillDown) error {
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
			add(f)
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
	last := make([]any, len(fields))
	filled := make([]bool, len(fields))
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		if !ev.stepN(len(fields)) {
			return ev.err
		}
		for j, f := range fields {
			if v := r[f]; v != nil {
				last[j] = v
				continue
			}
			if last[j] == nil {
				continue
			}
			if !ev.newField(r, f) || !ev.charge(valueSize(last[j])) {
				return ev.err
			}
			r[f] = last[j]
			filled[j] = true
		}
	}
	for j, f := range fields {
		if filled[j] {
			addColumn(res, f)
		}
	}
	return nil
}

// trend keeps the last Period numbers of one trendline average.
type trend struct {
	query.Trend
	ring      []float64
	next, n   int
	since     int     // rows since the sums were last added up
	work      int     // values added up again, for the step count
	sum, wsum float64 // the window's sum, and for wma its weighted sum
	ema       float64
}

// add takes the next number and returns the average once the window is
// full.
func (t *trend) add(x float64) (float64, bool) {
	// A non-finite number would stay in the running sums for good.
	if !finite(x) {
		return 0, false
	}
	p := t.Period
	if t.n < p {
		t.ring = append(t.ring, x)
		t.n++
		t.sum += x
		t.wsum += float64(t.n) * x
		if t.n < p {
			return 0, false
		}
		t.ema = t.sum / float64(p)
		return t.value(), true
	}
	old := t.ring[t.next]
	t.ring[t.next] = x
	t.next = (t.next + 1) % p
	// Each value's weight drops by one and the new one weighs p.
	t.wsum += float64(p)*x - t.sum
	t.sum += x - old
	// Sums that overflowed would stay Inf or NaN after the large values
	// leave the window, and rounding builds up, so every period rows, or
	// at once when they are not finite, they are added up again.
	if t.since++; t.since >= p || !finite(t.sum) || !finite(t.wsum) {
		t.recount()
	}
	alpha := 2 / float64(p+1)
	t.ema = alpha*x + (1-alpha)*t.ema
	if !finite(t.ema) {
		t.ema = t.sum / float64(p)
	}
	return t.value(), true
}

// recount adds up the window again, oldest value first.
func (t *trend) recount() {
	t.sum, t.wsum, t.since = 0, 0, 0
	t.work += t.Period
	for i := range t.Period {
		x := t.ring[(t.next+i)%t.Period]
		t.sum += x
		t.wsum += float64(i+1) * x
	}
}

func (t *trend) value() float64 {
	p := float64(t.Period)
	switch t.Kind {
	case "ema":
		return t.ema
	case "wma":
		return t.wsum / (p * (p + 1) / 2)
	}
	return t.sum / p
}

// applyTrendline adds each average's value to the rows from the one that
// fills its window on; rows without a number in the field get none.
func applyTrendline(ctx context.Context, res *Result, c *query.Trendline) error {
	ev := evaluatorFor(ctx)
	trends := make([]*trend, 0, len(c.Trends))
	for _, tr := range c.Trends {
		if !ev.charge(8 * tr.Period) {
			return ev.err
		}
		trends = append(trends, &trend{Trend: tr})
	}
	added := make([]bool, len(trends))
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		// Every input is read before any average is set, so an average
		// written over its own field still reads the old value.
		xs := make([]any, len(trends))
		for j, t := range trends {
			xs[j] = r[t.Field]
		}
		for j, t := range trends {
			if !ev.step() {
				return ev.err
			}
			x, ok := evNum(xs[j])
			if !ok {
				continue
			}
			avg, ok := t.add(x)
			if t.work > 0 {
				if !ev.stepN(t.work) {
					return ev.err
				}
				t.work = 0
			}
			if !ok {
				continue
			}
			name := t.Name()
			if !ev.newField(r, name) {
				return ev.err
			}
			r[name] = numOut(avg)
			added[j] = true
		}
	}
	for j, t := range trends {
		if added[j] {
			addColumn(res, t.Name())
		}
	}
	return nil
}

// addInfo adds the search's time range and when it ran to each row, in
// seconds since 1970, as Splunk's addinfo: info_min_time is 0 for a search
// with no start, and info_max_time is the search time for one with no end.
func (e *Engine) addInfo(ctx context.Context, res *Result, q *query.Query) error {
	ev := evaluatorFor(ctx)
	now := time.Now().UTC()
	earliest := q.Earliest
	if earliest == "" {
		earliest = e.opts().DefaultEarliest
	}
	minT, maxT := 0.0, epochSeconds(now)
	if t, ok := searchTime(earliest, now); ok {
		minT = epochSeconds(t)
	}
	if t, ok := searchTime(q.Latest, now); ok {
		maxT = epochSeconds(t)
	}
	info := []struct {
		name string
		v    any
	}{
		{query.AddInfoMinTime, numOut(minT)},
		{query.AddInfoMaxTime, numOut(maxT)},
		{query.AddInfoSearchTime, numOut(epochSeconds(now))},
	}
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		for _, f := range info {
			if !ev.newField(r, f.name) {
				return ev.err
			}
			r[f.name] = f.v
		}
	}
	for _, f := range info {
		addColumn(res, f.name)
	}
	return nil
}

// searchTime resolves a search's earliest or latest as the query engine
// reads it: a relative time such as -24h@h, now, an ISO 8601 time, or
// milliseconds since 1970. "" and "0" are no bound.
func searchTime(v string, now time.Time) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v == "0" {
		return time.Time{}, false
	}
	if strings.HasPrefix(strings.ToLower(v), "now") && len(v) > 3 {
		v = v[3:]
	}
	if t, ok := relativeTime(now, v); ok {
		return t, true
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), true
		}
	}
	if ms, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.UnixMilli(ms).UTC(), true
	}
	return time.Time{}, false
}

func epochSeconds(t time.Time) float64 {
	return float64(t.UnixNano()) / 1e9
}
