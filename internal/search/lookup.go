// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"errors"
	"fmt"

	"github.com/jrsamsanchez/signalith/internal/lookuptables"
	"github.com/jrsamsanchez/signalith/internal/query"
)

func noTable(name string) error {
	return &QueryError{Msg: fmt.Sprintf("there is no lookup table named %s; admins add them on Settings > Lookups", name)}
}

// maxLookupMatches caps how many table rows one row takes values from.
const maxLookupMatches = 100

// lookup adds columns from a lookup table to the rows whose fields match
// its key columns. Values match as text, exactly unless the table has
// wildcard columns or ignores case; a row with no match is left as it is.
// Several matching table rows give multivalue fields.
func (e *Engine) lookup(ctx context.Context, res *Result, c *query.Lookup) error {
	if e.Lookups == nil {
		return &QueryError{Msg: "lookup tables are not available on this server"}
	}
	keys := make([]string, len(c.Keys))
	for i, k := range c.Keys {
		keys[i] = k.Column
	}
	t, idx, err := e.Lookups.Lookup(c.Table, keys)
	if errors.Is(err, lookuptables.ErrNotFound) {
		return noTable(c.Table)
	}
	if err != nil {
		return &QueryError{Msg: err.Error()}
	}
	type out struct {
		col   int
		field string
	}
	var outs []out
	if len(c.Outputs) == 0 {
		for i, col := range t.Columns {
			isKey := false
			for _, k := range keys {
				isKey = isKey || k == col
			}
			if !isKey {
				outs = append(outs, out{i, col})
			}
		}
	} else {
		for _, o := range c.Outputs {
			i := t.Column(o.Column)
			if i < 0 {
				return &QueryError{Msg: fmt.Sprintf("lookup table %s has no column %q", c.Table, o.Column)}
			}
			outs = append(outs, out{i, o.Field()})
		}
	}
	// The values a lookup copies count against the search's budget, as
	// eval's do: a few wide table rows matched on many events add up.
	ev := evaluatorFor(ctx)
	vals := make([]string, len(c.Keys))
	for n, r := range res.Rows {
		if n%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		var matched []int
		if len(c.Keys) == 1 {
			// A multivalue field matches each of its values.
			for _, v := range asList(r[c.Keys[0].Field()]) {
				if s, ok := evStr(v); ok && s != "" {
					m, ok := idx.Match(t, []string{s}, maxLookupMatches-len(matched), ev.stepN)
					if !ok {
						return ev.err
					}
					matched = append(matched, m...)
				}
				if len(matched) >= maxLookupMatches {
					break
				}
			}
		} else {
			ok := true
			for i, k := range c.Keys {
				v := r[k.Field()]
				if _, multi := v.([]any); multi {
					ok = false
					break
				}
				vals[i], ok = evStr(v)
				if !ok || vals[i] == "" {
					ok = false
					break
				}
			}
			if ok {
				if matched, ok = idx.Match(t, vals, maxLookupMatches, ev.stepN); !ok {
					return ev.err
				}
			}
		}
		if len(matched) == 0 {
			continue
		}
		matched = matched[:min(len(matched), maxLookupMatches)]
		for _, o := range outs {
			if c.New {
				if v, ok := r[o.field]; ok && v != nil {
					continue
				}
			}
			var got []any
			for _, m := range matched {
				if v := t.Rows[m][o.col]; v != "" {
					got = append(got, v)
				}
			}
			if v := mvOut(got); v != nil {
				if !ev.charge(valueSize(v)) {
					return ev.err
				}
				r[o.field] = v
			} else if !c.New {
				delete(r, o.field)
			}
		}
	}
	for _, o := range outs {
		addColumn(res, o.field)
	}
	return nil
}

// inputLookup returns the rows of a lookup table, up to c.Max or the
// search's event limit; a cell left empty is a missing field.
func (e *Engine) inputLookup(ctx context.Context, c *query.InputLookup) (*Result, error) {
	if e.Lookups == nil {
		return nil, &QueryError{Msg: "lookup tables are not available on this server"}
	}
	t, ok := e.Lookups.Get(c.Table)
	if !ok {
		return nil, noTable(c.Table)
	}
	limit := e.opts().MaxEvents
	if c.Max > 0 {
		limit = min(limit, c.Max)
	}
	if c.Where != nil {
		return inputLookupWhere(ctx, t, c, limit)
	}
	n := min(len(t.Rows), limit)
	res := &Result{Kind: "table", Matched: int64(len(t.Rows)), Truncated: n < len(t.Rows) && (c.Max == 0 || c.Max > limit)}
	res.Columns = append([]string{}, t.Columns...)
	for _, r := range t.Rows[:n] {
		res.Rows = append(res.Rows, tableRow(t, r))
	}
	return res, nil
}

// tableRow is a lookup table row as a search row; a cell left empty is a
// missing field.
func tableRow(t *lookuptables.Table, r []string) Row {
	row := make(Row, len(r))
	for i, v := range r {
		if v != "" {
			row[t.Columns[i]] = v
		}
	}
	return row
}

// inputLookupWhere returns the rows of t that match c.Where, up to limit.
func inputLookupWhere(ctx context.Context, t *lookuptables.Table, c *query.InputLookup, limit int) (*Result, error) {
	res := &Result{Kind: "table", Columns: append([]string{}, t.Columns...)}
	m := &matcher{ctx: ctx}
	for i, r := range t.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		row := tableRow(t, r)
		if !m.eval(c.Where, row) {
			if m.err != nil {
				return nil, m.err
			}
			continue
		}
		res.Matched++
		if len(res.Rows) < limit {
			res.Rows = append(res.Rows, row)
		} else if c.Max == 0 || c.Max > limit {
			res.Truncated = true
		}
	}
	return res, nil
}
