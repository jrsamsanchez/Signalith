// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// maxJoinRows caps the rows a join gives, however many matches each row
// has.
const maxJoinRows = maxEventsLimit

// subsearch returns a join's or append's subsearch, which searches the
// outer query's time range unless it names its own.
func subsearch(q *query.Query, outer *query.Query) *query.Query {
	sub := *q
	sub.EventsOnly = q.EventsOnly || outer.EventsOnly
	if sub.Earliest == "" && sub.Latest == "" {
		sub.Earliest, sub.Latest = outer.Earliest, outer.Latest
	}
	return &sub
}

// noteSampled marks res Sampled when the subsearch sub was: the smallest
// number of events any of them ran over.
func noteSampled(res, sub *Result) {
	if sub.Sampled > 0 && (res.Sampled == 0 || sub.Sampled < res.Sampled) {
		res.Sampled = sub.Sampled
	}
}

// join runs a join's subsearch and adds the fields of its rows to the
// rows that share the values of the join fields; the subsearch's values
// win where both have a field. type=left keeps rows with no match.
func (e *Engine) join(ctx context.Context, res *Result, c *query.Join, outer *query.Query) error {
	sq := subsearch(c.Sub, outer)
	sq, err := e.resolveSubsearches(ctx, sq)
	if err != nil {
		return err
	}
	p, err := e.compileSub(sq)
	if err != nil {
		return err
	}
	sub, err := e.run(ctx, sq, p)
	if err != nil {
		return err
	}
	noteSampled(res, sub)
	vals := make([]string, len(c.Fields))
	key := func(r Row) (string, bool) {
		for i, f := range c.Fields {
			s, ok := evStr(r[f])
			if !ok || s == "" {
				return "", false
			}
			vals[i] = s
		}
		return strings.Join(vals, "\x00"), true
	}
	idx := map[string][]Row{}
	for n, r := range sub.Rows {
		if n%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		if k, ok := key(r); ok && len(idx[k]) < query.MaxJoinMatches {
			idx[k] = append(idx[k], r)
		}
	}
	ev := evaluatorFor(ctx)
	out := make([]Row, 0, len(res.Rows))
	for n, r := range res.Rows {
		if n%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		k, ok := key(r)
		matches := idx[k]
		if !ok || len(matches) == 0 {
			if c.Left {
				out = append(out, r)
			}
			continue
		}
		if c.Max > 0 {
			matches = matches[:min(len(matches), c.Max)]
		}
		for i, m := range matches {
			if len(out) >= maxJoinRows {
				res.Truncated = true
				break
			}
			row := r
			if i < len(matches)-1 {
				row = make(Row, len(r))
				for f, v := range r {
					row[f] = v
				}
			}
			// What a join copies counts against the search's budget, as
			// eval's values do.
			for f, v := range m {
				if !ev.charge(valueSize(v) + len(f)) {
					return ev.err
				}
				row[f] = v
			}
			out = append(out, row)
		}
	}
	res.Rows = out
	for _, col := range sub.Columns {
		addColumn(res, col)
	}
	return nil
}
