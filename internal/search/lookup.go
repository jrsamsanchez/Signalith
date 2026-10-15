package search

import (
	"context"
	"errors"
	"fmt"

	"github.com/jrsamsanchez/signalith/internal/lookuptables"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// maxLookupMatches caps how many table rows one row takes values from.
const maxLookupMatches = 100

// lookup adds columns from a lookup table to the rows whose fields match
// its key columns. Values match exactly, as text; a row with no match is
// left as it is. Several matching table rows give multivalue fields.
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
		return &QueryError{Msg: fmt.Sprintf("there is no lookup table named %s; admins add them on Settings > Lookups", c.Table)}
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
					matched = append(matched, idx[s]...)
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
				matched = idx[lookuptables.Key(vals)]
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
