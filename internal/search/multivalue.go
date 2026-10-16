package search

import (
	"context"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// rowOverhead is what the budget counts for each field of a copied row
// besides its name: the values themselves are shared, not copied.
const rowOverhead = 16

// applyMVExpand makes one row per value of c.Field.
func applyMVExpand(ctx context.Context, res *Result, c *query.MVExpand) error {
	ev := evaluatorFor(ctx)
	var out []Row
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		vs, ok := r[c.Field].([]any)
		if !ok {
			if r[c.Field] != nil {
				out = append(out, r)
			}
			continue
		}
		if c.Limit > 0 && len(vs) > c.Limit {
			vs = vs[:c.Limit]
		}
		size := 0
		for f := range r {
			size += len(f) + rowOverhead
		}
		for _, v := range vs {
			if len(out) >= maxAppendRows {
				res.Truncated = true
				break
			}
			if !ev.charge(size) {
				return ev.err
			}
			row := make(Row, len(r))
			for f, x := range r {
				row[f] = x
			}
			row[c.Field] = v
			out = append(out, row)
		}
	}
	res.Rows = out
	return nil
}

// applyMakeMV splits c.Field's text into its values.
func applyMakeMV(ctx context.Context, res *Result, c *query.MakeMV) error {
	ev := evaluatorFor(ctx)
	var re *regexp.Regexp
	if c.Tokenizer != "" {
		var err error
		if re, err = regexp.Compile(c.Tokenizer); err != nil {
			return &QueryError{Msg: "makemv tokenizer: " + err.Error()}
		}
	}
	delim := c.Delim
	if delim == "" {
		delim = " "
	}
	work := 0
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		s, ok := r[c.Field].(string)
		if !ok {
			continue
		}
		if work += len(s); work > checkWork {
			if err := ctx.Err(); err != nil {
				return err
			}
			work = 0
		}
		var parts []string
		if re != nil {
			for _, m := range re.FindAllStringSubmatch(s, maxMultiValues) {
				v := m[0]
				if len(m) > 1 {
					v = m[1]
				}
				parts = append(parts, v)
			}
		} else {
			parts = strings.SplitN(s, delim, maxMultiValues)
		}
		var vs []any
		for _, p := range parts {
			if p == "" && !c.AllowEmpty {
				continue
			}
			vs = append(vs, p)
		}
		// The values share the text's memory; the list itself is new.
		if !ev.charge(len(vs) * rowOverhead) {
			return ev.err
		}
		if v := mvOut(vs); v == nil {
			delete(r, c.Field)
		} else {
			r[c.Field] = v
		}
	}
	return nil
}

func applyReverse(res *Result) {
	for i, j := 0, len(res.Rows)-1; i < j; i, j = i+1, j-1 {
		res.Rows[i], res.Rows[j] = res.Rows[j], res.Rows[i]
	}
}

// total adds numbers up: an int64 while every number is one, else a
// float64.
type total struct {
	i      int64
	f      float64
	float  bool
	counts bool // a number was added
}

func (t *total) add(v any) {
	switch n := v.(type) {
	case int64:
		if s := t.i + n; (n > 0 && s < t.i) || (n < 0 && s > t.i) {
			t.float, t.f = true, t.f+float64(t.i)+float64(n)
			t.i = 0
		} else {
			t.i = s
		}
	case int:
		t.add(int64(n))
		return
	default:
		f, ok := asFloat(v)
		if !ok || math.IsNaN(f) {
			return
		}
		if _, isStr := v.(string); isStr && !looksNumeric(v.(string)) {
			return
		}
		t.float, t.f = true, t.f+f
	}
	t.counts = true
}

func (t *total) value() any {
	if !t.counts {
		return nil
	}
	if t.float {
		return t.f + float64(t.i)
	}
	return t.i
}

// looksNumeric reports whether text is a number, so addtotals adds "12"
// but not "12 hosts".
func looksNumeric(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	_, ok := asFloat(s)
	return ok && !strings.ContainsAny(s, " \t")
}

// applyAddTotals adds each row's numbers into a total field and, with
// c.Col, a row of column totals.
func applyAddTotals(ctx context.Context, res *Result, c *query.AddTotals) error {
	ev := evaluatorFor(ctx)
	name := c.TotalName()
	wanted := func(f string) bool {
		if f == name || f == c.LabelField {
			return false
		}
		if len(c.Fields) == 0 {
			return !strings.HasPrefix(f, "_")
		}
		for _, p := range c.Fields {
			if query.MatchField(p, f) {
				return true
			}
		}
		return false
	}
	cols := map[string]*total{}
	var keys []string
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		// In name order, so floating point totals come out the same
		// every time.
		keys = keys[:0]
		for f := range r {
			if wanted(f) {
				keys = append(keys, f)
			}
		}
		sort.Strings(keys)
		var rowTotal total
		for _, f := range keys {
			v := r[f]
			rowTotal.add(v)
			if c.Col {
				t := cols[f]
				if t == nil {
					t = &total{}
					cols[f] = t
				}
				t.add(v)
			}
		}
		if !c.NoRow {
			if v := rowTotal.value(); v != nil {
				if !ev.charge(len(name) + rowOverhead) {
					return ev.err
				}
				r[name] = v
				if c.Col {
					t := cols[name]
					if t == nil {
						t = &total{}
						cols[name] = t
					}
					t.add(v)
				}
			}
		}
	}
	if !c.NoRow {
		addColumn(res, name)
	}
	if !c.Col {
		return nil
	}
	row := Row{}
	for f, t := range cols {
		if v := t.value(); v != nil {
			row[f] = v
		}
	}
	if c.LabelField != "" {
		row[c.LabelField] = c.TotalLabel()
		addColumn(res, c.LabelField)
	}
	if !ev.charge(len(row) * rowOverhead) {
		return ev.err
	}
	if len(res.Rows) < maxAppendRows {
		res.Rows = append(res.Rows, row)
	} else {
		res.Truncated = true
	}
	return nil
}
