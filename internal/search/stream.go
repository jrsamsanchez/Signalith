package search

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// streamVal is one value a streamstats function has seen.
type streamVal struct {
	seq int64 // the row's place in its group
	v   any
	f   float64
	num bool
}

// streamAgg is one streamstats function's running state for one group.
// Each row is added and dropped once, so a window costs no more than
// running over every row: min and max keep only the values that can
// still be the answer, oldest first.
type streamAgg struct {
	a        query.Agg
	window   bool
	vals     []streamVal // the values in the window, oldest first
	count    int64
	numeric  int64
	sum      float64
	minQ     []streamVal
	maxQ     []streamVal
	distinct map[string]int
	first    any
	last     any
}

func (s *streamAgg) add(sv streamVal) {
	s.count++
	if sv.num {
		s.numeric++
		s.sum += sv.f
		for len(s.minQ) > 0 && s.minQ[len(s.minQ)-1].f >= sv.f {
			s.minQ = s.minQ[:len(s.minQ)-1]
		}
		s.minQ = append(s.minQ, sv)
		for len(s.maxQ) > 0 && s.maxQ[len(s.maxQ)-1].f <= sv.f {
			s.maxQ = s.maxQ[:len(s.maxQ)-1]
		}
		s.maxQ = append(s.maxQ, sv)
	}
	if s.a.Func == "dc" {
		for _, x := range asList(sv.v) {
			k, _ := evStr(x)
			s.distinct[k]++
		}
	}
	if s.window {
		s.vals = append(s.vals, sv)
	} else if s.count == 1 {
		s.first = sv.v
	}
	s.last = sv.v
}

// drop removes the values of rows before seq from the window.
func (s *streamAgg) drop(seq int64) {
	n := 0
	for n < len(s.vals) && s.vals[n].seq < seq {
		sv := s.vals[n]
		s.count--
		if sv.num {
			s.numeric--
			s.sum -= sv.f
			if s.minQ[0].seq == sv.seq {
				s.minQ = s.minQ[1:]
			}
			if s.maxQ[0].seq == sv.seq {
				s.maxQ = s.maxQ[1:]
			}
		}
		if s.a.Func == "dc" {
			for _, x := range asList(sv.v) {
				k, _ := evStr(x)
				if s.distinct[k]--; s.distinct[k] <= 0 {
					delete(s.distinct, k)
				}
			}
		}
		n++
	}
	if n == 0 {
		return
	}
	s.vals = s.vals[n:]
	if s.numeric == 0 {
		s.sum = 0 // no rounding left over from values that are gone
	}
	s.first, s.last = nil, nil
	if len(s.vals) > 0 {
		s.first, s.last = s.vals[0].v, s.vals[len(s.vals)-1].v
	}
}

func (s *streamAgg) result() any {
	switch s.a.Func {
	case "count":
		return s.count
	case "dc":
		return int64(len(s.distinct))
	case "first":
		if s.window && len(s.vals) > 0 {
			return s.vals[0].v
		}
		return s.first
	case "last":
		return s.last
	}
	if s.numeric == 0 {
		return nil
	}
	switch s.a.Func {
	case "sum":
		return toNumber(s.sum)
	case "avg":
		return s.sum / float64(s.numeric)
	case "min":
		return toNumber(s.minQ[0].f)
	case "max":
		return toNumber(s.maxQ[0].f)
	case "range":
		return toNumber(s.maxQ[0].f - s.minQ[0].f)
	}
	return nil
}

// applyStreamStats adds running aggregates to each row, over the rows of
// its group so far in result order (with current=f, before it). window=N
// looks back over the last N rows of the group.
func applyStreamStats(ctx context.Context, res *Result, c *query.StreamStats) error {
	type group struct {
		seq  int64
		aggs []*streamAgg
	}
	groups := map[string]*group{}
	ev := evaluatorFor(ctx)
	put := func(r Row, g *group) error {
		for _, s := range g.aggs {
			v := s.result()
			if v == nil {
				delete(r, s.a.Column())
				continue
			}
			if !ev.charge(valueSize(v)) {
				return ev.err
			}
			r[s.a.Column()] = v
		}
		return nil
	}
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		k, ok := groupKey(r, c.By)
		if !ok {
			continue
		}
		g := groups[k]
		if g == nil {
			g = &group{}
			for _, a := range c.Aggs {
				g.aggs = append(g.aggs, &streamAgg{a: a, window: c.Window > 0, distinct: map[string]int{}})
			}
			groups[k] = g
		}
		g.seq++
		if c.Window > 0 {
			// The window is the last Window rows, this one included
			// when current=t.
			from := g.seq - int64(c.Window)
			if c.Current {
				from++
			}
			for _, s := range g.aggs {
				s.drop(from)
			}
		}
		if !c.Current {
			if err := put(r, g); err != nil {
				return err
			}
		}
		for _, s := range g.aggs {
			sv := streamVal{seq: g.seq}
			if s.a.Field == "" {
				sv.v = true
			} else if v, ok := r[s.a.Field]; ok && v != nil {
				sv.v = v
				sv.f, sv.num = asFloat(v)
				sv.num = sv.num && !math.IsNaN(sv.f) && !math.IsInf(sv.f, 0)
			} else {
				continue
			}
			s.add(sv)
		}
		if c.Current {
			if err := put(r, g); err != nil {
				return err
			}
		}
	}
	for _, a := range c.Aggs {
		addColumn(res, a.Column())
	}
	return nil
}

// weekStart puts week buckets on Mondays: Unix time 0 is a Thursday.
const weekStart = 4 * 86400

// applyBin rounds a field's values down to the start of their span. A
// time span works on times, written back as they came (epoch seconds or
// RFC 3339 in UTC); a number span turns numbers into ranges like 0-100.
func applyBin(ctx context.Context, res *Result, c *query.Bin) error {
	secs, size, err := query.BinSpan(c.Span)
	if err != nil {
		return &QueryError{Msg: fmt.Sprintf("%s span: %s", c.Name(), err.(*query.Error).Msg)}
	}
	out := c.Field
	if c.As != "" {
		out = c.As
	}
	offset := int64(0)
	if secs%604800 == 0 {
		offset = weekStart
	}
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		v, ok := r[c.Field]
		if !ok || v == nil {
			continue
		}
		if _, multi := v.([]any); multi {
			continue
		}
		var b any
		if secs > 0 {
			t, ok := toTime(v)
			if !ok {
				continue
			}
			u := t.Unix() - offset
			u = (u - ((u%secs)+secs)%secs) + offset // floor, for times before 1970 too
			if _, isNum := evNum(v); isNum {
				b = u
			} else {
				b = time.Unix(u, 0).UTC().Format(time.RFC3339)
			}
		} else {
			f, ok := asFloat(v)
			if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
				continue
			}
			lo := math.Floor(f/size) * size
			b = strconv.FormatFloat(lo, 'f', -1, 64) + "-" + strconv.FormatFloat(lo+size, 'f', -1, 64)
		}
		r[out] = b
	}
	addColumn(res, out)
	return nil
}

// applyRegex keeps rows whose field matches c's pattern (with !=, rows
// whose field does not). A multivalue field matches when any value does;
// a row without the field never matches.
func applyRegex(ctx context.Context, res *Result, c *query.Regex) error {
	re, err := regexp.Compile(c.Pattern)
	if err != nil {
		return &QueryError{Msg: fmt.Sprintf("regex pattern: %v", err)}
	}
	out := res.Rows[:0:0]
	work := 0
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		matched := false
		for _, x := range asList(r[c.Field]) {
			s, ok := evStr(x)
			if !ok {
				continue
			}
			if work += len(s); work > checkWork {
				if err := ctx.Err(); err != nil {
					return err
				}
				work = 0
			}
			if re.MatchString(s) {
				matched = true
				break
			}
		}
		if matched != c.Negate {
			out = append(out, r)
		}
	}
	res.Rows = out
	return nil
}

// applyFieldsRemove drops fields, * matching any characters, from the
// rows and the columns.
func applyFieldsRemove(res *Result, c *query.FieldsRemove) {
	var globs []glob
	for _, f := range c.Fields {
		globs = append(globs, compileGlob(f, false))
	}
	drop := func(name string) bool {
		for _, g := range globs {
			if g.match(name) {
				return true
			}
		}
		return false
	}
	cols := res.Columns[:0:0]
	for _, col := range res.Columns {
		if !drop(col) {
			cols = append(cols, col)
		}
	}
	res.Columns = cols
	for _, r := range res.Rows {
		for f := range r {
			if drop(f) {
				delete(r, f)
			}
		}
	}
}

// makeResults returns rows that hold only the time the search ran.
func makeResults(c *query.MakeResults) *Result {
	now := time.Now().UTC().Format(time.RFC3339)
	res := &Result{Kind: "table", Columns: []string{"_time"}, Matched: int64(c.Count)}
	for range c.Count {
		res.Rows = append(res.Rows, Row{"_time": now})
	}
	return res
}

// maxAppendRows caps the rows append and appendpipe give.
const maxAppendRows = maxEventsLimit

// appendRows adds rows after res's own, up to maxAppendRows, and their
// columns after res's.
func appendRows(res *Result, rows []Row, cols []string, kind string) {
	for _, r := range rows {
		if len(res.Rows) >= maxAppendRows {
			res.Truncated = true
			break
		}
		res.Rows = append(res.Rows, r)
	}
	for _, col := range cols {
		addColumn(res, col)
	}
	if kind != res.Kind {
		res.Kind = "table"
	}
}

// appendSearch runs append's subsearch and adds its rows after res's.
func (e *Engine) appendSearch(ctx context.Context, res *Result, c *query.Append, outer *query.Query) error {
	sq := subsearch(c.Sub, outer)
	p, err := e.compile(sq)
	if err != nil {
		return err
	}
	sub, err := e.run(ctx, sq, p)
	if err != nil {
		return err
	}
	appendRows(res, sub.Rows, sub.Columns, sub.Kind)
	res.Truncated = res.Truncated || sub.Truncated
	return nil
}

// appendPipe runs appendpipe's commands over a copy of the rows so far
// and adds the rows they give after them. The copy is written out with
// the result, so it counts against the search's budget.
func (e *Engine) appendPipe(ctx context.Context, res *Result, c *query.AppendPipe, outer *query.Query) error {
	ev := evaluatorFor(ctx)
	sub := &Result{Kind: res.Kind, Columns: append([]string{}, res.Columns...), Matched: res.Matched}
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		row := Row{}
		for f, v := range r {
			if !ev.charge(valueSize(v) + len(f)) {
				return ev.err
			}
			row[f] = v
		}
		sub.Rows = append(sub.Rows, row)
	}
	if err := e.post(ctx, sub, c.Commands, outer); err != nil {
		return err
	}
	appendRows(res, sub.Rows, sub.Columns, sub.Kind)
	res.Truncated = res.Truncated || sub.Truncated
	return nil
}
