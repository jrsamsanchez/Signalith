// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// multiSearch runs each of multisearch's subsearches and gives their
// rows together, newest first. Rows without a time come last, in order.
func (e *Engine) multiSearch(ctx context.Context, c *query.MultiSearch, outer *query.Query) (*Result, error) {
	res := &Result{}
	for i, s := range c.Subs {
		sq := subsearch(s, outer)
		sq, err := e.resolveSubsearches(ctx, sq)
		if err != nil {
			return nil, err
		}
		p, err := e.compileSub(sq)
		if err != nil {
			return nil, err
		}
		sub, err := e.run(ctx, sq, p)
		if err != nil {
			return nil, err
		}
		noteSampled(res, sub)
		if i == 0 {
			res.Kind = sub.Kind
		}
		appendRows(res, sub.Rows, sub.Columns, sub.Kind)
		res.Truncated = res.Truncated || sub.Truncated
		res.Matched += sub.Matched
	}
	type timed struct {
		row Row
		t   time.Time
		ok  bool
	}
	var rows []timed
	for _, r := range res.Rows {
		t, ok := toTime(r["_time"])
		rows = append(rows, timed{r, t, ok})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].ok != rows[j].ok {
			return rows[i].ok
		}
		return rows[i].ok && rows[i].t.After(rows[j].t)
	})
	res.Rows = res.Rows[:0]
	for _, r := range rows {
		res.Rows = append(res.Rows, r.row)
	}
	return res, nil
}

// applyTimewrap lays the periods of a timechart side by side: each row
// moves to the same point in the latest period (the one ending at the
// newest row, or with c.Now at the present), and each series gets one
// column per period, oldest first.
func applyTimewrap(ctx context.Context, res *Result, c *query.Timewrap) error {
	ev := evaluatorFor(ctx)
	period, _, err := query.BinSpan(c.Span)
	if err != nil || period <= 0 {
		return &QueryError{Msg: "timewrap takes a time span like 1d or 1w"}
	}
	var series []string
	for _, col := range res.Columns {
		if col != "_time" && !strings.HasPrefix(col, "_") && !strings.HasPrefix(col, "\x00") {
			series = append(series, col)
		}
	}
	type stamped struct {
		row  Row
		unix int64
		text bool // _time was written as text
	}
	var rows []stamped
	var end int64
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		t, ok := toTime(r["_time"])
		if !ok {
			continue
		}
		_, text := r["_time"].(string)
		rows = append(rows, stamped{r, t.Unix(), text})
		if len(rows) == 1 || t.Unix() > end {
			end = t.Unix()
		}
	}
	if c.Now {
		end = time.Now().Unix()
	}
	// Period 0 is the latest; a row falls in period k when it is k
	// periods before the end.
	periods := int64(0)
	for _, r := range rows {
		if r.unix <= end {
			periods = max(periods, (end-r.unix)/period+1)
		}
	}
	if periods*int64(len(series)) > query.MaxSeriesColumns {
		return &QueryError{Msg: fmt.Sprintf("timewrap would make more than %d columns; use a longer span or a shorter time range", query.MaxSeriesColumns)}
	}
	unit, n := timewrapUnit(period)
	name := func(s string, k int64) string {
		switch {
		case c.Short:
			return s + "_s" + strconv.FormatInt(k, 10)
		case k == 0 && n == 1:
			return s + "_latest_" + unit
		case k == 0:
			return s + "_latest_" + strconv.FormatInt(n, 10) + unit + "s"
		case k*n == 1:
			return s + "_1" + unit + "_before"
		}
		return s + "_" + strconv.FormatInt(k*n, 10) + unit + "s_before"
	}
	out := map[int64]Row{}
	var order []int64
	for i, r := range rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		if r.unix > end {
			continue
		}
		k := (end - r.unix) / period
		at := r.unix + k*period
		row, ok := out[at]
		if !ok {
			var t any = at
			if r.text {
				t = time.Unix(at, 0).UTC().Format(time.RFC3339)
			}
			if !ev.charge(valueSize(t) + fieldOverhead) {
				return ev.err
			}
			row = Row{"_time": t}
			out[at] = row
			order = append(order, at)
		}
		for _, s := range series {
			v, ok := r.row[s]
			if !ok || v == nil {
				continue
			}
			col := name(s, k)
			if !ev.newField(row, col) || !ev.charge(valueSize(v)) {
				return ev.err
			}
			row[col] = v
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	var outRows []Row
	for _, at := range order {
		outRows = append(outRows, out[at])
	}
	cols := []string{"_time"}
	for k := periods - 1; k >= 0; k-- {
		for _, s := range series {
			cols = append(cols, name(s, k))
		}
	}
	res.Rows, res.Columns, res.Kind = outRows, cols, "timechart"
	return nil
}

// timewrapUnit names a period: the largest of week, day, hour, minute and
// second it is a whole number of, and how many.
func timewrapUnit(secs int64) (string, int64) {
	for _, u := range []struct {
		name string
		secs int64
	}{{"week", 604800}, {"day", 86400}, {"hour", 3600}, {"minute", 60}} {
		if secs%u.secs == 0 {
			return u.name, secs / u.secs
		}
	}
	return "second", secs
}

// maxClusterTerms bounds the terms cluster compares from one row.
const maxClusterTerms = 1000

// applyCluster puts each row in the first group whose first row's text in
// c.Field is at least c.Threshold alike, or starts a group. It keeps the
// first row of each group (every row with c.LabelOnly), labels each with
// its group number, and with c.ShowCount adds the group's size.
func applyCluster(ctx context.Context, res *Result, c *query.Cluster) error {
	ev := evaluatorFor(ctx)
	type group struct {
		terms []string
		set   map[string]bool
		first Row
		n     int
	}
	var groups []*group
	var label []int
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		s, _ := evStr(r[c.Field])
		terms := clusterTerms(s, c.Match)
		if !ev.stepN(len(s) + 1) {
			return ev.err
		}
		var set map[string]bool
		if c.Match != "termlist" {
			set = map[string]bool{}
			for _, t := range terms {
				set[t] = true
			}
		}
		found := -1
		for g, gr := range groups {
			// A comparison costs a map lookup per term, so it counts as
			// several steps, and a long scan checks the deadline.
			if !ev.stepN(4*len(terms) + 1) {
				return ev.err
			}
			if g%checkEvery == checkEvery-1 && ctx.Err() != nil {
				return ctx.Err()
			}
			if clusterAlike(terms, set, gr.terms, gr.set, c.Match) >= c.Threshold {
				found = g
				break
			}
		}
		if found < 0 {
			size := 0
			for _, t := range terms {
				size += len(t) + 16
			}
			if !ev.charge(size + fieldOverhead) {
				return ev.err
			}
			groups = append(groups, &group{terms: terms, set: set, first: r})
			found = len(groups) - 1
		}
		groups[found].n++
		label = append(label, found)
	}
	var rows []Row
	for i, r := range res.Rows {
		g := groups[label[i]]
		if !c.LabelOnly && g.first == nil {
			continue
		}
		if !c.LabelOnly {
			r = g.first
			g.first = nil
		}
		if !ev.newField(r, c.LabelField) {
			return ev.err
		}
		r[c.LabelField] = int64(label[i] + 1)
		if c.ShowCount {
			if !ev.newField(r, c.CountField) {
				return ev.err
			}
			r[c.CountField] = int64(g.n)
		}
		rows = append(rows, r)
	}
	res.Rows = rows
	addColumn(res, c.LabelField)
	if c.ShowCount {
		addColumn(res, c.CountField)
	}
	return nil
}

// clusterTerms splits s into lowercase words, or with ngramset into its
// three-character pieces, up to maxClusterTerms.
func clusterTerms(s, match string) []string {
	var out []string
	if match == "ngramset" {
		var r []rune
		for _, c := range s {
			if len(r) >= maxClusterTerms+2 {
				break
			}
			r = append(r, unicode.ToLower(c))
		}
		for i := 0; i+3 <= len(r); i++ {
			out = append(out, string(r[i:i+3]))
		}
		return out
	}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(out) >= maxClusterTerms {
			break
		}
		out = append(out, w)
	}
	return out
}

// clusterAlike is how alike two rows' terms are, from 0 to 1: with
// termlist the share of positions holding the same term, otherwise the
// share of all their distinct terms they both have.
func clusterAlike(a []string, aset map[string]bool, b []string, bset map[string]bool, match string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	if match == "termlist" {
		same := 0
		for i := 0; i < len(a) && i < len(b); i++ {
			if a[i] == b[i] {
				same++
			}
		}
		return float64(same) / float64(max(len(a), len(b)))
	}
	both := 0
	for t := range aset {
		if bset[t] {
			both++
		}
	}
	all := len(aset) + len(bset) - both
	if all == 0 {
		return 1
	}
	return float64(both) / float64(all)
}
