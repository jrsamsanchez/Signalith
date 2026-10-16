package search

import (
	"context"
	"math"
	"regexp"
	"sort"
	"strconv"
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

// applySed changes c.Field's text, each value of a multivalue field, with
// a rex mode=sed expression.
func applySed(ctx context.Context, res *Result, c *query.Rex) error {
	sed, err := query.ParseSed(c.Sed)
	if err != nil {
		return &QueryError{Msg: "rex sed expression: " + err.Error()}
	}
	ev := evaluatorFor(ctx)
	var change func(string) any
	if sed.Y {
		from, to := []rune(sed.Find), []rune(sed.Replace)
		m := make(map[rune]rune, len(from))
		for i, r := range from {
			if _, ok := m[r]; !ok {
				m[r] = to[i]
			}
		}
		change = func(s string) any {
			out := strings.Map(func(r rune) rune {
				if t, ok := m[r]; ok {
					return t
				}
				return r
			}, s)
			return ev.str(out)
		}
	} else {
		re, err := regexp.Compile(sed.Find)
		if err != nil {
			return &QueryError{Msg: "rex sed expression: " + err.Error()}
		}
		template := sed.GoTemplate()
		nth := 1
		switch {
		case sed.Global:
			nth = 0
		case sed.Nth > 0:
			nth = sed.Nth
		}
		change = func(s string) any { return ev.replaceNth(re, s, template, nth) }
	}
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		switch v := r[c.Field].(type) {
		case string:
			out := change(v)
			if ev.err != nil {
				return ev.err
			}
			r[c.Field] = out
		case []any:
			vs := make([]any, len(v))
			for j, x := range v {
				vs[j] = x
				if s, ok := x.(string); ok {
					vs[j] = change(s)
					if ev.err != nil {
						return ev.err
					}
				}
			}
			r[c.Field] = vs
		}
	}
	return nil
}

func applyTail(res *Result, c *query.Tail) {
	n := min(c.N, len(res.Rows))
	tail := res.Rows[len(res.Rows)-n:]
	out := make([]Row, n)
	for i, r := range tail {
		out[n-1-i] = r
	}
	res.Rows = out
}

// applyUniq drops rows that are the same as the row before them.
func applyUniq(ctx context.Context, res *Result) error {
	out := res.Rows[:0:0]
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		if len(out) > 0 && sameRow(out[len(out)-1], r) {
			continue
		}
		out = append(out, r)
	}
	res.Rows = out
	return nil
}

func sameRow(a, b Row) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || !sameValue(v, w) {
			return false
		}
	}
	return true
}

func sameValue(a, b any) bool {
	la, oka := a.([]any)
	lb, okb := b.([]any)
	if oka || okb {
		if !oka || !okb || len(la) != len(lb) {
			return false
		}
		for i := range la {
			if !sameValue(la[i], lb[i]) {
				return false
			}
		}
		return true
	}
	return a == b
}

// applyConvert runs convert's conversions over each row.
func applyConvert(ctx context.Context, res *Result, c *query.Convert) error {
	ev := evaluatorFor(ctx)
	format := c.TimeFormat
	if format == "" {
		format = query.DefaultTimeFormat
	}
	var none []string
	for _, f := range c.Funcs {
		if f.Func == "none" {
			none = append(none, f.Field)
		}
	}
	excluded := func(name string) bool {
		for _, p := range none {
			if query.MatchField(p, name) {
				return true
			}
		}
		return false
	}
	var keys []string
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		for _, f := range c.Funcs {
			if f.Func == "none" {
				continue
			}
			names := []string{f.Field}
			if strings.Contains(f.Field, "*") {
				keys = keys[:0]
				for k := range r {
					if query.MatchField(f.Field, k) && !excluded(k) {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys)
				names = keys
			} else if excluded(f.Field) {
				continue
			}
			for _, name := range names {
				v, ok := r[name]
				if !ok || v == nil {
					continue
				}
				out, keep := convertValue(ev, f.Func, v, format)
				if ev.err != nil {
					return ev.err
				}
				to := name
				if f.As != "" {
					to = f.As
				}
				if !keep {
					if f.As == "" {
						delete(r, to)
					}
					continue
				}
				r[to] = out
			}
		}
	}
	for _, f := range c.Funcs {
		if f.As != "" {
			addColumn(res, f.As)
		}
	}
	return nil
}

// convertValue converts one value; keep is false when the value is
// dropped (num of something that is not a number).
func convertValue(ev *evaluator, fn string, v any, format string) (any, bool) {
	if vs, ok := v.([]any); ok {
		out := make([]any, 0, len(vs))
		for _, x := range vs {
			if y, keep := convertValue(ev, fn, x, format); keep {
				out = append(out, y)
			}
		}
		return mvOut(out), len(out) > 0
	}
	s, isStr := v.(string)
	switch fn {
	case "ctime":
		t, ok := toTime(v)
		if !ok {
			return v, true
		}
		return ev.str(strftime(t, format)), true
	case "mktime":
		if !isStr {
			return v, true
		}
		t, ok := strptime(s, format)
		if !ok {
			return v, true
		}
		return numOut(float64(t.UnixNano()) / 1e9), true
	case "dur2sec":
		if f, ok := dur2sec(s); isStr && ok {
			return numOut(f), true
		}
		return v, true
	case "mstime":
		if f, ok := mstime(s); isStr && ok {
			return numOut(f), true
		}
		return v, true
	case "memk":
		if f, ok := memk(v); ok {
			return numOut(f), true
		}
		return v, true
	case "rmcomma":
		if isStr {
			if f, ok := convNumber(strings.ReplaceAll(s, ",", "")); ok {
				return numOut(f), true
			}
		}
		return v, true
	case "rmunit":
		if isStr {
			if f, ok := leadingNumber(s); ok {
				return numOut(f), true
			}
		}
		return v, true
	case "num", "auto":
		if !isStr {
			return v, true
		}
		if f, ok := convNumber(s); ok {
			return numOut(f), true
		}
		return v, fn == "auto"
	}
	return v, true
}

func convNumber(s string) (float64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f, err == nil && finite(f)
}

// leadingNumber reads the number at the start of text such as 12.5kb.
func leadingNumber(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || s[end] == '.' || end == 0 && (s[end] == '-' || s[end] == '+')) {
		end++
	}
	return convNumber(s[:end])
}

// dur2sec reads [D+]HH:MM:SS as seconds.
func dur2sec(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	days := 0.0
	if d, rest, ok := strings.Cut(s, "+"); ok {
		n, ok := convNumber(d)
		if !ok || n < 0 {
			return 0, false
		}
		days, s = n, rest
	}
	parts := strings.Split(s, ":")
	if len(parts) > 3 {
		return 0, false
	}
	total := 0.0
	for _, p := range parts {
		n, ok := convNumber(p)
		if !ok || n < 0 {
			return 0, false
		}
		total = total*60 + n
	}
	return days*86400 + total, true
}

// mstime reads [MM:]SS.SSS as seconds.
func mstime(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	m, sec, ok := strings.Cut(s, ":")
	if !ok {
		return convNumber(s)
	}
	mins, ok1 := convNumber(m)
	secs, ok2 := convNumber(sec)
	if !ok1 || !ok2 || mins < 0 || secs < 0 {
		return 0, false
	}
	return mins*60 + secs, true
}

// memk reads a size such as 512, 10k, 2.5m or 1g as kilobytes; a bare
// number is already kilobytes.
func memk(v any) (float64, bool) {
	if f, ok := evNum(v); ok {
		if _, isStr := v.(string); !isStr {
			return f, true
		}
	}
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	s = strings.TrimSpace(strings.ToLower(s))
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "k"):
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "m"):
		s, mult = s[:len(s)-1], 1024
	case strings.HasSuffix(s, "g"):
		s, mult = s[:len(s)-1], 1024*1024
	}
	f, ok := convNumber(s)
	return f * mult, ok
}
