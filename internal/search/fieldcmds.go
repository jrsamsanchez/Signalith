// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// applyNoMV joins a multivalue field's values with newlines.
func applyNoMV(ctx context.Context, res *Result, c *query.NoMV) error {
	ev := evaluatorFor(ctx)
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		vs, ok := r[c.Field].([]any)
		if !ok {
			continue
		}
		s, _ := evStr(vs)
		if !ev.charge(len(s)) {
			return ev.err
		}
		r[c.Field] = s
	}
	return nil
}

// applyMVCombine merges rows that hold the same values in every field but
// c.Field, in the order each group first appears, into one row whose
// c.Field holds the group's distinct values.
func applyMVCombine(ctx context.Context, res *Result, c *query.MVCombine) error {
	ev := evaluatorFor(ctx)
	type group struct {
		row  Row
		vals []any
		seen map[string]bool
	}
	groups := map[string]*group{}
	var order []*group
	var keys []string
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		keys = keys[:0]
		for k := range r {
			if k != c.Field {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%q=", k)
			valueKey(&b, r[k])
		}
		key := b.String()
		g := groups[key]
		if g == nil {
			if !ev.charge(len(key)) {
				return ev.err
			}
			g = &group{row: r, seen: map[string]bool{}}
			groups[key] = g
			order = append(order, g)
		}
		for _, v := range asList(r[c.Field]) {
			var vb strings.Builder
			valueKey(&vb, v)
			if g.seen[vb.String()] || len(g.vals) >= maxMultiValues {
				continue
			}
			if !ev.charge(valueSize(v) + 1) {
				return ev.err
			}
			g.seen[vb.String()] = true
			g.vals = append(g.vals, v)
		}
	}
	out := make([]Row, 0, len(order))
	for _, g := range order {
		if v := mvOut(g.vals); v != nil {
			g.row[c.Field] = v
		}
		out = append(out, g.row)
	}
	res.Rows = out
	return nil
}

// valueKey writes v so that values of different types or lists never
// write the same text.
func valueKey(b *strings.Builder, v any) {
	switch x := v.(type) {
	case []any:
		b.WriteString("[")
		for _, e := range x {
			valueKey(b, e)
		}
		b.WriteString("]")
	case string:
		fmt.Fprintf(b, "s%q;", x)
	default:
		fmt.Fprintf(b, "%T:%v;", x, x)
	}
}

// applyStrCat joins fields and texts into c.Dest.
func applyStrCat(ctx context.Context, res *Result, c *query.StrCat) error {
	ev := evaluatorFor(ctx)
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		var b strings.Builder
		missing := false
		for _, part := range c.Parts {
			if part.Literal {
				b.WriteString(part.Text)
				continue
			}
			s, ok := evStr(r[part.Text])
			if !ok {
				missing = true
				continue
			}
			if !ev.fits(b.Len() + len(s)) {
				return ev.err
			}
			b.WriteString(s)
		}
		if missing && c.AllRequired {
			continue
		}
		if !ev.fits(b.Len()) || !ev.charge(b.Len()) {
			return ev.err
		}
		r[c.Dest] = b.String()
	}
	addColumn(res, c.Dest)
	return nil
}

// applyRangeMap sets range to the names of the ranges c.Field's number
// falls in, or the default name.
func applyRangeMap(ctx context.Context, res *Result, c *query.RangeMap) error {
	ev := evaluatorFor(ctx)
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		var names []any
		if n, ok := evNum(r[c.Field]); ok {
			for _, rg := range c.Ranges {
				if n >= rg.Lo && n <= rg.Hi {
					names = append(names, rg.Name)
				}
			}
		}
		if len(names) == 0 {
			names = []any{c.DefaultName()}
		}
		v := mvOut(names)
		if !ev.charge(valueSize(v)) {
			return ev.err
		}
		r["range"] = v
	}
	addColumn(res, "range")
	return nil
}

// applyForEach runs c's eval commands for each field that matches its
// patterns, in name order. Fields whose names could read as anything but
// a field name are left alone.
func applyForEach(ctx context.Context, res *Result, c *query.ForEach) error {
	matched := map[string]string{}
	ev := evaluatorFor(ctx)
	// Each name is tried once, however many rows have it.
	try := fieldMatcher(ev, len(c.Fields), func(f string) bool {
		if !query.ForEachName.MatchString(f) {
			return false
		}
		m, ok := c.Match(f)
		if !ok {
			return false
		}
		if len(matched) >= query.MaxForEachFields {
			res.Truncated = true
			return false
		}
		matched[f] = m
		return true
	})
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		for f := range r {
			if _, ok := try(f); !ok {
				return ev.err
			}
		}
	}
	names := make([]string, 0, len(matched))
	for f := range matched {
		names = append(names, f)
	}
	sort.Strings(names)
	for _, f := range names {
		evals, err := c.Commands(f, matched[f])
		if err != nil {
			// A name the commands cannot use, such as a keyword.
			continue
		}
		for _, e := range evals {
			if err := applyEval(ctx, res, e); err != nil {
				return err
			}
		}
	}
	return nil
}
