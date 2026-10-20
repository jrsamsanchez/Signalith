// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// applyReturn replaces the rows with one row whose search field holds
// the first c.Count rows' fields as search terms: src="a" from one row,
// (src="a") OR (src="b") from several. A $field item writes the bare
// value. Rows with none of the fields are skipped.
func applyReturn(ctx context.Context, res *Result, c *query.Return) error {
	ev := evaluatorFor(ctx)
	var pieces []string
	size := 0
	for i, r := range res.Rows {
		if len(pieces) >= c.Count {
			break
		}
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		if !ev.stepN(len(c.Items) + 1) {
			return ev.err
		}
		var terms []string
		for _, it := range c.Items {
			name := it.Field
			if it.Alias != "" {
				name = it.Alias
			}
			var alts []string
			for _, e := range asList(r[it.Field]) {
				if !ev.step() {
					return ev.err
				}
				if _, multi := e.([]any); multi {
					continue
				}
				if it.Bare {
					if s, ok := evStr(e); ok {
						alts = append(alts, s)
					}
				} else if t, ok := searchTerm(name, e); ok {
					alts = append(alts, t)
				}
			}
			switch len(alts) {
			case 0:
				continue
			case 1:
				terms = append(terms, alts[0])
			default:
				terms = append(terms, "( "+strings.Join(alts, " OR ")+" )")
			}
			size += len(terms[len(terms)-1]) + 1
			if !ev.fits(size) {
				return ev.err
			}
		}
		if len(terms) > 0 {
			pieces = append(pieces, strings.Join(terms, " "))
		}
	}
	out := ""
	if len(pieces) == 1 {
		out = pieces[0]
	} else if len(pieces) > 1 {
		out = "(" + strings.Join(pieces, ") OR (") + ")"
	}
	if !ev.fits(len(out)) || !ev.charge(len(out)+len(query.FormatField)+fieldOverhead) {
		return ev.err
	}
	res.Rows, res.Columns, res.Kind = []Row{{query.FormatField: out}}, []string{query.FormatField}, "table"
	return nil
}

// applyMakeContinuous adds a row for each c.Span bucket between the
// smallest and largest value of c.Field that no row falls in, and sorts
// the rows by c.Field, oldest or smallest first. The new rows have only
// c.Field. Rows without a value in it come last, in their order.
func applyMakeContinuous(ctx context.Context, res *Result, c *query.MakeContinuous) error {
	secs, size, err := query.BinSpan(c.Span)
	if err != nil {
		return &QueryError{Msg: fmt.Sprintf("%s span: %s", c.Name(), err.(*query.Error).Msg)}
	}
	ev := evaluatorFor(ctx)
	offset := int64(0)
	if secs%604800 == 0 {
		offset = weekStart
	}
	// bucket reads a row's bucket number.
	bucket := func(v any) (int64, bool) {
		if _, multi := v.([]any); multi || v == nil {
			return 0, false
		}
		if secs > 0 {
			t, ok := toTime(v)
			if !ok {
				return 0, false
			}
			u := t.Unix() - offset
			return (u - ((u%secs)+secs)%secs) / secs, true
		}
		f, ok := evNum(v)
		if !ok || !finite(f) || math.Abs(f/size) > 1e15 {
			return 0, false
		}
		return int64(math.Floor(f / size)), true
	}
	type keyed struct {
		row Row
		b   int64
	}
	var with []keyed
	var without []Row
	have := map[int64]bool{}
	numeric := false
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		b, ok := bucket(r[c.Field])
		if !ok {
			without = append(without, r)
			continue
		}
		if _, isNum := evNum(r[c.Field]); isNum {
			numeric = true
		}
		have[b] = true
		with = append(with, keyed{r, b})
	}
	if len(with) == 0 {
		return nil
	}
	lo, hi := with[0].b, with[0].b
	for _, k := range with {
		lo, hi = min(lo, k.b), max(hi, k.b)
	}
	if missing := uint64(hi-lo) + 1 - uint64(len(have)); hi-lo < 0 || missing > query.MaxContinuousRows {
		return &QueryError{Msg: fmt.Sprintf("makecontinuous would add more than %d rows; use a longer span or a narrower search", query.MaxContinuousRows)}
	}
	for b := lo; b <= hi; b++ {
		if !ev.step() {
			return ev.err
		}
		if have[b] {
			continue
		}
		var v any
		switch {
		case secs > 0 && numeric:
			v = b*secs + offset
		case secs > 0:
			v = time.Unix(b*secs+offset, 0).UTC().Format(time.RFC3339)
		default:
			v = numOut(float64(b) * size)
		}
		if !ev.charge(len(c.Field) + valueSize(v) + 2*fieldOverhead) {
			return ev.err
		}
		with = append(with, keyed{Row{c.Field: v}, b})
	}
	sort.SliceStable(with, func(i, j int) bool { return with[i].b < with[j].b })
	var rows []Row
	for _, k := range with {
		rows = append(rows, k.row)
	}
	res.Rows = append(rows, without...)
	addColumn(res, c.Field)
	return nil
}
