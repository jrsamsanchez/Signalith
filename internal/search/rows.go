package search

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// checkEvery is how many rows the in-memory commands handle between checks
// that the search has not been cancelled or timed out.
const checkEvery = 512

// checkWork is how many characters a where command compares against
// wildcard patterns between those checks, so a few slow rows cannot keep
// a search running long after it timed out.
const checkWork = 1 << 20

// applyCommand runs one pipe command over rows held in memory. It stops
// with ctx's error when ctx ends.
func applyCommand(ctx context.Context, res *Result, c query.Command) error {
	switch c := c.(type) {
	case *query.Where:
		m := &matcher{ctx: ctx}
		out := res.Rows[:0:0]
		for i, r := range res.Rows {
			if i%checkEvery == 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			if m.eval(c.Expr, r) {
				out = append(out, r)
			}
			if m.err != nil {
				return m.err
			}
		}
		res.Rows = out
	case *query.Sort:
		sort.SliceStable(res.Rows, func(i, j int) bool {
			for _, k := range c.Keys {
				cmp := compareValues(res.Rows[i][k.Field], res.Rows[j][k.Field])
				if cmp == 0 {
					continue
				}
				if k.Desc {
					return cmp > 0
				}
				return cmp < 0
			}
			return false
		})
	case *query.Head:
		if len(res.Rows) > c.N {
			res.Rows = res.Rows[:c.N]
		}
	case *query.Table:
		var cols []string
		for _, f := range c.Fields {
			if strings.ContainsAny(f, "*?") {
				g := compileGlob(f, false)
				for _, col := range res.Columns {
					if g.match(col) {
						cols = append(cols, col)
					}
				}
			} else {
				cols = append(cols, f)
			}
		}
		res.Columns = cols
		for i, r := range res.Rows {
			nr := Row{}
			for _, col := range cols {
				if v, ok := r[col]; ok {
					nr[col] = v
				}
			}
			res.Rows[i] = nr
		}
		if res.Kind == "events" {
			res.Kind = "table"
		}
	case *query.Rename:
		for _, p := range c.Pairs {
			for i, col := range res.Columns {
				if col == p[0] {
					res.Columns[i] = p[1]
				}
			}
			for _, r := range res.Rows {
				if v, ok := r[p[0]]; ok {
					delete(r, p[0])
					r[p[1]] = v
				}
			}
		}
	case *query.Stats:
		rows, cols, err := goStats(ctx, res.Rows, c)
		if err != nil {
			return err
		}
		res.Rows, res.Columns = rows, cols
		res.Kind = "table"
	case *query.Top:
		var counted []Row
		groups := map[string]Row{}
		keys := append(append([]string{}, c.By...), c.Fields...)
		for i, r := range res.Rows {
			if i%checkEvery == 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			k, ok := groupKey(r, keys)
			if !ok {
				continue
			}
			g, exists := groups[k]
			if !exists {
				g = Row{"count": int64(0)}
				for _, f := range keys {
					g[f] = r[f]
				}
				groups[k] = g
				counted = append(counted, g)
			}
			g["count"] = g["count"].(int64) + 1
		}
		res.Rows, res.Columns = topRows(counted, c)
		res.Kind = "table"
	case *query.Timechart:
		return fmt.Errorf("timechart must come before other commands that change results")
	default:
		return fmt.Errorf("command %q is not supported here", c.Name())
	}
	return nil
}

// topRows turns per-value counts into a top table with percentages,
// limited per by-group.
func topRows(rows []Row, top *query.Top) ([]Row, []string) {
	groupTotals := map[string]int64{}
	byGroup := map[string][]Row{}
	var order []string
	for _, r := range rows {
		k, _ := groupKey(r, top.By)
		if _, ok := byGroup[k]; !ok {
			order = append(order, k)
		}
		byGroup[k] = append(byGroup[k], r)
		n, _ := r["count"].(int64)
		groupTotals[k] += n
	}
	var out []Row
	for _, k := range order {
		g := byGroup[k]
		sort.SliceStable(g, func(i, j int) bool { return g[i]["count"].(int64) > g[j]["count"].(int64) })
		if top.Limit > 0 && len(g) > top.Limit {
			g = g[:top.Limit]
		}
		for _, r := range g {
			if t := groupTotals[k]; t > 0 {
				r["percent"] = math.Round(float64(r["count"].(int64))*10000/float64(t)) / 100
			}
			out = append(out, r)
		}
	}
	cols := append(append(append([]string{}, top.By...), top.Fields...), "count", "percent")
	return out, cols
}

func groupKey(r Row, fields []string) (string, bool) {
	var b strings.Builder
	for _, f := range fields {
		v, ok := r[f]
		if !ok || v == nil {
			return "", false
		}
		b.WriteString(fmt.Sprint(v))
		b.WriteByte(0)
	}
	return b.String(), true
}

type aggState struct {
	count    int64
	sum      float64
	numeric  int64
	min, max float64
	distinct map[string]bool
}

// goStats aggregates rows in memory, for stats after another transform.
func goStats(ctx context.Context, rows []Row, st *query.Stats) ([]Row, []string, error) {
	type group struct {
		keys   Row
		states []*aggState
	}
	groups := map[string]*group{}
	var order []string
	for i, r := range rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		k, ok := groupKey(r, st.By)
		if !ok {
			continue
		}
		g, exists := groups[k]
		if !exists {
			g = &group{keys: Row{}}
			for _, f := range st.By {
				g.keys[f] = r[f]
			}
			for range st.Aggs {
				g.states = append(g.states, &aggState{min: math.Inf(1), max: math.Inf(-1), distinct: map[string]bool{}})
			}
			groups[k] = g
			order = append(order, k)
		}
		for i, a := range st.Aggs {
			s := g.states[i]
			if a.Field == "" {
				s.count++
				continue
			}
			v, ok := r[a.Field]
			if !ok || v == nil {
				continue
			}
			s.count++
			s.distinct[fmt.Sprint(v)] = true
			if f, ok := asFloat(v); ok {
				s.numeric++
				s.sum += f
				s.min = math.Min(s.min, f)
				s.max = math.Max(s.max, f)
			}
		}
	}
	sort.Strings(order)
	var out []Row
	for _, k := range order {
		g := groups[k]
		row := Row{}
		for f, v := range g.keys {
			row[f] = v
		}
		for i, a := range st.Aggs {
			s := g.states[i]
			var v any
			switch a.Func {
			case "count":
				v = s.count
			case "dc":
				v = int64(len(s.distinct))
			case "sum":
				v = toNumber(s.sum)
			case "avg":
				if s.numeric > 0 {
					v = s.sum / float64(s.numeric)
				}
			case "min":
				if s.numeric > 0 {
					v = toNumber(s.min)
				}
			case "max":
				if s.numeric > 0 {
					v = toNumber(s.max)
				}
			}
			row[a.Column()] = v
		}
		out = append(out, row)
	}
	if len(st.By) == 0 && len(out) == 0 {
		row := Row{}
		for _, a := range st.Aggs {
			if a.Func == "count" || a.Func == "dc" {
				row[a.Column()] = int64(0)
			} else {
				row[a.Column()] = nil
			}
		}
		out = []Row{row}
	}
	return out, append(append([]string{}, st.By...), aggColumns(st.Aggs)...), nil
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	}
	return 0, false
}

// compareValues orders numbers numerically, everything else as text
// (case-insensitively), and puts missing values last.
func compareValues(a, b any) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return 1
	}
	if b == nil {
		return -1
	}
	fa, oka := asFloat(a)
	fb, okb := asFloat(b)
	if oka && okb {
		switch {
		case fa < fb:
			return -1
		case fa > fb:
			return 1
		}
		return 0
	}
	return strings.Compare(strings.ToLower(fmt.Sprint(a)), strings.ToLower(fmt.Sprint(b)))
}

// regex reports whether a where clause's regular expression is found in
// s; a pattern that does not compile fails the search.
func (m *matcher) regex(pattern, s string) bool {
	re, ok := m.regexes[pattern]
	if !ok {
		var err error
		if re, err = ParseRegex(pattern); err != nil {
			if m.err == nil {
				m.err = err
			}
			return false
		}
		if m.regexes == nil {
			m.regexes = map[string]*Regex{}
		}
		m.regexes[pattern] = re
	}
	return re.MatchString(s)
}

// matcher evaluates where expressions over rows. Each wildcard pattern is
// compiled once and kept for the rows that follow, rather than once per
// row.
type matcher struct {
	globs   map[string]glob
	lower   map[string]string
	regexes map[string]*Regex

	// ctx is checked every checkWork characters of wildcard matching;
	// once it ends, err holds its error and every match fails.
	ctx  context.Context
	work int
	err  error
}

func (m *matcher) eval(e query.Expr, r Row) bool {
	switch e := e.(type) {
	case *query.And:
		for _, c := range e.Children {
			if !m.eval(c, r) {
				return false
			}
		}
		return true
	case *query.Or:
		for _, c := range e.Children {
			if m.eval(c, r) {
				return true
			}
		}
		return false
	case *query.Not:
		return !m.eval(e.Child, r)
	case *query.In:
		for _, v := range e.Values {
			if m.equals(r[e.Field], v) {
				return true
			}
		}
		return false
	case *query.Compare:
		v, ok := r[e.Field]
		if !ok || v == nil {
			return false
		}
		switch e.Op {
		case "=":
			return m.equals(v, e.Value)
		case "!=":
			return !m.equals(v, e.Value)
		case "=~":
			return m.regex(e.Value, fmt.Sprint(v))
		}
		cmp := compareValues(v, e.Value)
		switch e.Op {
		case "<":
			return cmp < 0
		case "<=":
			return cmp <= 0
		case ">":
			return cmp > 0
		case ">=":
			return cmp >= 0
		}
	case *query.Text:
		want := m.lowered(e.Value)
		for _, v := range r {
			if strings.Contains(strings.ToLower(fmt.Sprint(v)), want) {
				return true
			}
		}
	}
	return false
}

func (m *matcher) lowered(s string) string {
	if m.lower == nil {
		m.lower = map[string]string{}
	}
	l, ok := m.lower[s]
	if !ok {
		l = strings.ToLower(s)
		m.lower[s] = l
	}
	return l
}

func (m *matcher) equals(v any, want string) bool {
	if v == nil {
		return want == ""
	}
	if want == "*" {
		return true
	}
	if strings.ContainsAny(want, "*?") {
		if m.globs == nil {
			m.globs = map[string]glob{}
		}
		g, ok := m.globs[want]
		if !ok {
			g = compileGlob(want, true)
			m.globs[want] = g
		}
		if m.err != nil {
			return false
		}
		s := fmt.Sprint(v)
		if m.work += len(s) + len(want); m.work >= checkWork && m.ctx != nil {
			m.work = 0
			if m.err = m.ctx.Err(); m.err != nil {
				return false
			}
		}
		return g.match(s)
	}
	return compareValues(v, want) == 0
}

// glob is a compiled * and ? pattern that must match a whole string: *
// matches any run of characters (newlines too) and ? any one character.
// It is matched without regular expressions, in time linear in the string
// times the pattern's length in 64-character words.
type glob struct {
	parts []string    // the pattern split at each *
	runes []int       // characters in each part
	q     []*shiftAnd // for each part with a ?, its matcher
	fold  bool        // match case-insensitively
}

func compileGlob(pattern string, fold bool) glob {
	if fold {
		pattern = strings.ToLower(pattern)
	}
	g := glob{parts: strings.Split(pattern, "*"), fold: fold}
	for _, p := range g.parts {
		g.runes = append(g.runes, utf8.RuneCountInString(p))
		var sa *shiftAnd
		if strings.Contains(p, "?") {
			sa = newShiftAnd(p)
		}
		g.q = append(g.q, sa)
	}
	return g
}

func (g glob) match(s string) bool {
	if g.fold {
		s = strings.ToLower(s)
	}
	last := len(g.parts) - 1
	if last == 0 {
		n, ok := matchPart(g.parts[0], s)
		return ok && n == len(s)
	}
	// The first part anchors the start and the last the end; the ones
	// between go, in order, at their leftmost places, which leaves the
	// most room for the rest.
	n, ok := matchPart(g.parts[0], s)
	if !ok {
		return false
	}
	pos := n
	for i := 1; i < last; i++ {
		if g.parts[i] == "" {
			continue
		}
		end, ok := g.find(i, s[pos:])
		if !ok {
			return false
		}
		pos += end
	}
	// The last part covers the final g.runes[last] characters.
	tail := len(s)
	for k := 0; k < g.runes[last]; k++ {
		if tail <= pos {
			return false
		}
		_, size := utf8.DecodeLastRuneInString(s[pos:tail])
		tail -= size
	}
	n, ok = matchPart(g.parts[last], s[tail:])
	return ok && tail+n == len(s)
}

// find returns where the first match of part i in s ends.
func (g glob) find(i int, s string) (int, bool) {
	p := g.parts[i]
	if g.q[i] == nil {
		at := strings.Index(s, p)
		return at + len(p), at >= 0
	}
	return g.q[i].find(s)
}

// shiftAnd finds a part with ? in a string in one pass (the Shift-And
// algorithm): bit k of the state is set while the part's first k+1
// characters match the characters just read. Every match of a part has
// the same number of characters, so the first to end is also the first
// to start.
type shiftAnd struct {
	n     int               // characters in the part
	any   []uint64          // positions holding ?
	exact map[rune][]uint64 // for each other character, its positions
	state []uint64          // find's scratch; a glob is used by one goroutine
}

func newShiftAnd(p string) *shiftAnd {
	rs := []rune(p)
	words := (len(rs) + 63) / 64
	sa := &shiftAnd{n: len(rs), any: make([]uint64, words), exact: map[rune][]uint64{}, state: make([]uint64, words)}
	for k, r := range rs {
		if r == '?' {
			sa.any[k/64] |= 1 << (k % 64)
		}
	}
	for k, r := range rs {
		if r == '?' {
			continue
		}
		m, ok := sa.exact[r]
		if !ok {
			m = append([]uint64(nil), sa.any...)
			sa.exact[r] = m
		}
		m[k/64] |= 1 << (k % 64)
	}
	return sa
}

// find returns where the first match in s ends.
func (sa *shiftAnd) find(s string) (int, bool) {
	if sa.n == 0 {
		return 0, true
	}
	state := sa.state
	clear(state)
	last, lastBit := (sa.n-1)/64, uint64(1)<<((sa.n-1)%64)
	for at := 0; at < len(s); {
		r, size := utf8.DecodeRuneInString(s[at:])
		at += size
		mask, ok := sa.exact[r]
		if !ok {
			mask = sa.any
		}
		carry := uint64(1) // a match can start at every character
		for w := range state {
			next := state[w] >> 63
			state[w] = (state[w]<<1 | carry) & mask[w]
			carry = next
		}
		if state[last]&lastBit != 0 {
			return at, true
		}
	}
	return 0, false
}

// matchPart matches a part with no * (? stands for any one character) at
// the start of s and returns how many bytes of s it covered.
func matchPart(p, s string) (int, bool) {
	n := 0
	for _, pr := range p {
		if n >= len(s) {
			return 0, false
		}
		sr, size := utf8.DecodeRuneInString(s[n:])
		if pr != '?' && pr != sr {
			return 0, false
		}
		n += size
	}
	return n, true
}

// maxPatternLen caps a wildcard value in a search or where command, so a
// pattern cannot be made big enough to make every comparison slow.
const maxPatternLen = 1000

// maxWherePatterns caps the characters of all the wildcard values in a
// query's where commands together. A where command after the search runs
// over every row in memory, so many long patterns (in an IN list or an OR
// chain) would make each row slow even when each pattern is short enough.
const maxWherePatterns = 4096

// maxInValues caps the values in one IN list.
const maxInValues = 1000

// checkPatterns returns a *QueryError for a wildcard value longer than
// maxPatternLen in the search or a where command, wildcard values in where
// commands longer than maxWherePatterns together, or an IN list longer
// than maxInValues.
func checkPatterns(q *query.Query) error {
	var err error
	total := 0
	var walk func(e query.Expr, where bool)
	check := func(v string, where bool) {
		if err != nil || !strings.ContainsAny(v, "*?") {
			return
		}
		n := utf8.RuneCountInString(v)
		if n > maxPatternLen {
			err = &QueryError{Msg: fmt.Sprintf("a wildcard pattern is %d characters long; the limit is %d", n, maxPatternLen)}
			return
		}
		if where {
			if total += n; total > maxWherePatterns {
				err = &QueryError{Msg: fmt.Sprintf("the wildcard patterns in where commands are more than %d characters long together; filter in the search before the first | instead, or use fewer patterns", maxWherePatterns)}
			}
		}
	}
	walk = func(e query.Expr, where bool) {
		switch e := e.(type) {
		case *query.And:
			for _, c := range e.Children {
				walk(c, where)
			}
		case *query.Or:
			for _, c := range e.Children {
				walk(c, where)
			}
		case *query.Not:
			walk(e.Child, where)
		case *query.In:
			if err == nil && len(e.Values) > maxInValues {
				err = &QueryError{Msg: fmt.Sprintf("an IN list has %d values; the limit is %d", len(e.Values), maxInValues)}
			}
			for _, v := range e.Values {
				check(v, where)
			}
		case *query.Compare:
			check(e.Value, where)
		}
	}
	walk(q.Search, false)
	for _, c := range q.Commands {
		if w, ok := c.(*query.Where); ok {
			walk(w.Expr, true)
		}
	}
	return err
}
