// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
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
		sortRows(res.Rows, c.Keys)
		if c.Limit > 0 && len(res.Rows) > c.Limit {
			res.Rows = res.Rows[:c.Limit]
		}
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
	case *query.Transaction:
		return transaction(ctx, res, c)
	case *query.Rename:
		for _, p := range c.Pairs {
			if err := applyRename(ctx, res, p); err != nil {
				return err
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
			ks, vals, ok, err := groupCombos(r, keys)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			for gi, k := range ks {
				g, exists := groups[k]
				if !exists {
					g = Row{topCount: int64(0)}
					for _, f := range keys {
						g[f] = vals[gi][f]
					}
					groups[k] = g
					counted = append(counted, g)
				}
				g[topCount] = g[topCount].(int64) + 1
			}
		}
		res.Rows, res.Columns = topRows(counted, c)
		res.Kind = "table"
	case *query.Eval:
		return applyEval(ctx, res, c)
	case *query.Rex:
		return applyRex(ctx, res, c)
	case *query.Dedup:
		if err := applyDedup(ctx, res, c); err != nil {
			return err
		}
		sortRows(res.Rows, c.SortBy)
	case *query.Fillnull:
		applyFillnull(res, c)
	case *query.EventStats:
		return applyEventStats(ctx, res, c)
	case *query.StreamStats:
		return applyStreamStats(ctx, res, c)
	case *query.Bin:
		return applyBin(ctx, res, c)
	case *query.Regex:
		return applyRegex(ctx, res, c)
	case *query.FieldsRemove:
		return applyFieldsRemove(ctx, res, c)
	case *query.Chart:
		for _, cc := range chartCommands(c) {
			if err := applyCommand(ctx, res, cc); err != nil {
				return err
			}
		}
	case *query.XYSeries:
		return applyXYSeries(ctx, res, c)
	case *query.Untable:
		return applyUntable(ctx, res, c)
	case *query.Spath:
		return applySpath(ctx, res, c)
	case *query.FromJSON:
		return applyFromJSON(ctx, res, c)
	case *query.NoMV:
		return applyNoMV(ctx, res, c)
	case *query.MVCombine:
		return applyMVCombine(ctx, res, c)
	case *query.StrCat:
		return applyStrCat(ctx, res, c)
	case *query.RangeMap:
		return applyRangeMap(ctx, res, c)
	case *query.ForEach:
		return applyForEach(ctx, res, c)
	case *query.Replace:
		return applyReplace(ctx, res, c)
	case *query.XMLKV:
		return applyXMLKV(ctx, res, c)
	case *query.Accum:
		return applyAccum(ctx, res, c)
	case *query.Delta:
		return applyDelta(ctx, res, c)
	case *query.AutoRegress:
		return applyAutoRegress(ctx, res, c)
	case *query.FieldSummary:
		return applyFieldSummary(ctx, res, c)
	case *query.Transpose:
		return applyTranspose(ctx, res, c)
	case *query.FillDown:
		return applyFillDown(ctx, res, c)
	case *query.Trendline:
		return applyTrendline(ctx, res, c)
	case *query.Concurrency:
		return applyConcurrency(ctx, res, c)
	case *query.Contingency:
		return applyContingency(ctx, res, c)
	case *query.Format:
		return applyFormat(ctx, res, c)
	case *query.Return:
		return applyReturn(ctx, res, c)
	case *query.MakeContinuous:
		return applyMakeContinuous(ctx, res, c)
	case *query.Geostats:
		return applyGeostats(ctx, res, c)
	case *query.Extract:
		return applyExtract(ctx, res, c)
	case *query.Outlier:
		return applyOutlier(ctx, res, c)
	case *query.Gauge:
		return applyGauge(ctx, res, c)
	case *query.Timewrap:
		return applyTimewrap(ctx, res, c)
	case *query.Cluster:
		return applyCluster(ctx, res, c)
	case *query.XPath:
		return applyXPath(ctx, res, c)
	case *query.Abstract:
		return applyAbstract(ctx, res, c)
	case *query.AnomalyDetection:
		return applyAnomalyDetection(ctx, res, c)
	case *query.Correlate:
		return applyCorrelate(ctx, res, c)
	case *query.Predict:
		return applyPredict(ctx, res, c)
	case *query.SetFields:
		return applySetFields(ctx, res, c)
	case *query.KMeans:
		return applyKMeans(ctx, res, c)
	case *query.Highlight:
		// The results view marks terms itself; the rows stay as they are.
	case *query.MVExpand:
		return applyMVExpand(ctx, res, c)
	case *query.MakeMV:
		return applyMakeMV(ctx, res, c)
	case *query.Reverse:
		applyReverse(res)
	case *query.Tail:
		applyTail(res, c)
	case *query.Uniq:
		return applyUniq(ctx, res)
	case *query.Convert:
		return applyConvert(ctx, res, c)
	case *query.AddTotals:
		return applyAddTotals(ctx, res, c)
	case *query.Timechart:
		return fmt.Errorf("timechart must come before other commands that change results")
	default:
		return fmt.Errorf("command %q is not supported here", c.Name())
	}
	return nil
}

// topCount holds a value's count in the rows topRows takes; a name no
// field can have, so it never clashes with one of top's fields.
const topCount = "\x00count"

// topRows turns per-value counts into a top table with percentages,
// limited per by-group, with an other row for the rest when asked.
func topRows(rows []Row, top *query.Top) ([]Row, []string) {
	return topRowsBeyond(rows, top, 0)
}

// topRowsBeyond is topRows when, with no by fields, beyond the rows
// there are more events in values not among them.
func topRowsBeyond(rows []Row, top *query.Top, beyond int64) ([]Row, []string) {
	if len(top.By) > 0 {
		beyond = 0
	}
	groupTotals := map[string]int64{}
	byGroup := map[string][]Row{}
	var order []string
	for _, r := range rows {
		k, _ := groupKey(r, top.By)
		if _, ok := byGroup[k]; !ok {
			order = append(order, k)
		}
		byGroup[k] = append(byGroup[k], r)
		groupTotals[k] += topN(r)
	}
	for k := range groupTotals {
		groupTotals[k] += beyond // one group, with no by fields
	}
	countCol, percentCol := top.CountColumn(), top.PercentColumn()
	var out []Row
	for _, k := range order {
		g := byGroup[k]
		sort.SliceStable(g, func(i, j int) bool {
			if top.Rare {
				return topN(g[i]) < topN(g[j])
			}
			return topN(g[i]) > topN(g[j])
		})
		rest := beyond
		if top.Limit > 0 && len(g) > top.Limit {
			for _, r := range g[top.Limit:] {
				rest += topN(r)
			}
			g = g[:top.Limit]
		}
		if top.UseOther && rest > 0 {
			other := Row{topCount: rest}
			for _, f := range top.By {
				other[f] = g[0][f]
			}
			for _, f := range top.Fields {
				other[f] = top.Other()
			}
			g = append(g, other)
		}
		for _, r := range g {
			n := topN(r)
			delete(r, topCount)
			if !top.NoCount {
				r[countCol] = n
			}
			if t := groupTotals[k]; t > 0 && !top.NoPercent {
				r[percentCol] = math.Round(float64(n)*10000/float64(t)) / 100
			}
			out = append(out, r)
		}
	}
	cols := append(append([]string{}, top.By...), top.Fields...)
	if !top.NoCount {
		cols = append(cols, countCol)
	}
	if !top.NoPercent {
		cols = append(cols, percentCol)
	}
	return out, cols
}

// topN is a row's count in topRows.
func topN(r Row) int64 {
	switch n := r[topCount].(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
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

// maxGroupCombos bounds the groups one row counts in when it has several
// values in its by fields.
const maxGroupCombos = 10000

// groupCombos returns the groups row r counts in for fields, as keys (see
// groupKey) and their values: a row with several values in a by field
// counts once for each, and with several such fields once for each
// combination, as in Splunk. ok is false when a field has no value.
func groupCombos(r Row, fields []string) (keys []string, vals []Row, ok bool, err error) {
	if !slices.ContainsFunc(fields, func(f string) bool { _, multi := r[f].([]any); return multi }) {
		k, ok := groupKey(r, fields)
		return []string{k}, []Row{r}, ok, nil
	}
	keys, vals = []string{""}, []Row{{}}
	for _, f := range fields {
		v, has := r[f]
		if !has || v == nil {
			return nil, nil, false, nil
		}
		list := valueList(v)
		if len(list) == 0 {
			return nil, nil, false, nil
		}
		if len(keys)*len(list) > maxGroupCombos {
			return nil, nil, false, &QueryError{Msg: fmt.Sprintf("a row's multivalue by fields make more than %d groups; use mvexpand or fewer by fields", maxGroupCombos)}
		}
		var nk []string
		var nv []Row
		for i, k := range keys {
			for _, x := range list {
				row := Row{f: x}
				for kf, kv := range vals[i] {
					row[kf] = kv
				}
				nk = append(nk, k+fmt.Sprint(x)+"\x00")
				nv = append(nv, row)
			}
		}
		keys, vals = nk, nv
	}
	return keys, vals, true, nil
}

// goStats aggregates rows in memory, for stats after another transform.
// A row with several values in a by field counts in the group of each.
func goStats(ctx context.Context, rows []Row, st *query.Stats) ([]Row, []string, error) {
	return goStatsBy(ctx, rows, st, true)
}

// goStatsBy is goStats; with expand false a multivalue by field groups by
// its whole list, as eventstats looks its groups up.
func goStatsBy(ctx context.Context, rows []Row, st *query.Stats, expand bool) ([]Row, []string, error) {
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
		var keys []string
		var vals []Row
		if expand {
			var ok bool
			var err error
			if keys, vals, ok, err = groupCombos(r, st.By); err != nil {
				return nil, nil, err
			} else if !ok {
				continue
			}
		} else {
			k, ok := groupKey(r, st.By)
			if !ok {
				continue
			}
			keys, vals = []string{k}, []Row{r}
		}
		for gi, k := range keys {
			g, exists := groups[k]
			if !exists {
				g = &group{keys: Row{}}
				for _, f := range st.By {
					g.keys[f] = vals[gi][f]
				}
				for range st.Aggs {
					g.states = append(g.states, newAggState())
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
				s.add(a, v, r)
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
			row[a.Column()] = g.states[i].result(a)
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

// compareAs orders a and b as a sort key's function says: "num" puts
// numbers first, in order, then the rest as text; "str" orders them as
// text; "ip" orders addresses by their value, before anything else;
// otherwise as compareValues. Missing values go last.
func compareAs(as string, a, b any) int {
	if as == "" || a == nil || b == nil {
		return compareValues(a, b)
	}
	switch as {
	case "num":
		fa, oka := asFloat(a)
		fb, okb := asFloat(b)
		switch {
		case oka && okb:
			return cmp.Compare(fa, fb)
		case oka:
			return -1
		case okb:
			return 1
		}
	case "ip":
		ia, erra := netip.ParseAddr(strings.TrimSpace(fmt.Sprint(a)))
		ib, errb := netip.ParseAddr(strings.TrimSpace(fmt.Sprint(b)))
		switch {
		case erra == nil && errb == nil:
			return ia.Unmap().Compare(ib.Unmap())
		case erra == nil:
			return -1
		case errb == nil:
			return 1
		}
	}
	return strings.Compare(fmt.Sprint(a), fmt.Sprint(b))
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

	ev *evaluator // for conditions written as expressions
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
	case *query.Cond:
		if m.ev == nil {
			m.ev = evaluatorFor(m.ctx)
		}
		ok := truth(m.ev.safeEval(e.X, r))
		if m.ev.err != nil && m.err == nil {
			m.err = m.ev.err
		}
		return ok
	case *query.In:
		for _, x := range valueList(r[e.Field]) {
			for _, v := range e.Values {
				if m.equals(x, v) {
					return true
				}
			}
		}
		return false
	case *query.Compare:
		v, ok := r[e.Field]
		if !ok || v == nil {
			return false
		}
		if list, multi := v.([]any); multi {
			// A multivalue field matches when one of its values does,
			// and != when none equals the value, as search reads them
			// (SL-07).
			if e.Op == "!=" {
				eq := *e
				eq.Op = "="
				return !slices.ContainsFunc(list, func(x any) bool { return m.compare(&eq, x, r) })
			}
			return slices.ContainsFunc(list, func(x any) bool { return m.compare(e, x, r) })
		}
		return m.compare(e, v, r)
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

// compare evaluates a comparison for v, one value of row r's field.
func (m *matcher) compare(e *query.Compare, v any, r Row) bool {
	if v == nil {
		return false
	}
	if e.Ref {
		if w, ok := r[e.Value]; ok && w != nil {
			return compareOp(e.Op, compareValues(v, w))
		}
	}
	switch e.Op {
	case "=":
		return m.equals(v, e.Value)
	case "!=":
		return !m.equals(v, e.Value)
	case "=~":
		return m.regex(e.Value, fmt.Sprint(v))
	}
	if e.Field == "_time" {
		if _, isNum := asFloat(e.Value); isNum {
			v = timeNumber(v)
		}
	}
	return compareOp(e.Op, compareValues(v, e.Value))
}

// compareOp reports whether cmp, as compareValues returns it, satisfies op.
func compareOp(op string, cmp int) bool {
	switch op {
	case "=":
		return cmp == 0
	case "!=":
		return cmp != 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	}
	return false
}

// valueList is v's values: each of a multivalue field's, or v itself.
func valueList(v any) []any {
	if list, ok := v.([]any); ok {
		return list
	}
	return []any{v}
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
	// One word of bits per 64 characters, grown without a size sum that
	// could overflow.
	words := []uint64{0}
	for i := 64; i < len(rs); i += 64 {
		words = append(words, 0)
	}
	sa := &shiftAnd{n: len(rs), any: words, exact: map[rune][]uint64{}, state: make([]uint64, len(words))}
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

// sortRows sorts rows by keys, keeping the order of rows that tie.
func sortRows(rows []Row, keys []query.SortKey) {
	if len(keys) == 0 {
		return
	}
	sort.SliceStable(rows, func(i, j int) bool {
		for _, k := range keys {
			cmp := compareAs(k.As, rows[i][k.Field], rows[j][k.Field])
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
}

// catalogFields holds every field the data models name.
var catalogFields = sync.OnceValue(func() map[string]bool {
	out := map[string]bool{"_time": true}
	for _, f := range datamodel.FieldsFor("") {
		out[f.Name] = true
	}
	return out
})

// comparesCatalogFields reports whether e compares a field with a bare
// name that the data models know as a field (where bytes_out > bytes_in).
// OpenSearch cannot compare two fields of an event, so such a filter runs
// over the events it returns; a bare name no model knows (where
// action=blocked) is text, and is searched for there.
func comparesCatalogFields(e query.Expr) bool {
	switch e := e.(type) {
	case *query.And:
		return slices.ContainsFunc(e.Children, comparesCatalogFields)
	case *query.Or:
		return slices.ContainsFunc(e.Children, comparesCatalogFields)
	case *query.Not:
		return comparesCatalogFields(e.Child)
	case *query.Compare:
		return e.Ref && catalogFields()[e.Value]
	}
	return false
}
