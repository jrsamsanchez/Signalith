// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// mapSearch runs map's search once for each of the first c.Max rows, with
// the row's values in place of its $field$ tokens, and replaces the rows
// with those of all the searches. A row missing a field the search names
// runs no search, so an empty value cannot widen it to every event.
func (e *Engine) mapSearch(ctx context.Context, res *Result, c *query.Map, outer *query.Query) error {
	out := &Result{Kind: "events"}
	for i, r := range res.Rows {
		if i >= c.Max {
			res.Truncated = true
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		wild := false
		text, err := query.SubstituteMap(c.Search, func(name string) (string, bool) {
			v := r[name]
			if mv, ok := v.([]any); ok && len(mv) > 0 {
				v = mv[0]
			}
			s, ok := evStr(v)
			wild = wild || strings.ContainsAny(s, "*?")
			return s, ok && s != ""
		})
		if errors.Is(err, query.ErrMapField) {
			continue
		}
		if err != nil {
			return &QueryError{Msg: err.Error()}
		}
		q, err := query.ParseMapSearch(text)
		if err != nil {
			// The search parsed with plain values, so a value made it
			// fail: a number where a name was expected, say.
			return &QueryError{Msg: "map's search for row " + strconv.Itoa(i+1) + " does not parse: " + err.Error()}
		}
		if wild {
			markMapValues(c.Search, q)
		}
		sq := subsearch(q, outer)
		sq, err = e.resolveSubsearches(ctx, sq)
		if err != nil {
			return err
		}
		// As a subsearch of join or append does, each search takes up
		// to search.max_events events, marked Sampled when more match.
		p, err := e.compileSub(sq)
		if err != nil {
			return err
		}
		sub, err := e.run(ctx, sq, p)
		if err != nil {
			return err
		}
		appendRows(out, sub.Rows, sub.Columns, sub.Kind)
		out.Matched += sub.Matched
		out.Truncated = out.Truncated || sub.Truncated
		noteSampled(out, sub)
	}
	res.Kind, res.Columns, res.Rows, res.Matched = out.Kind, out.Columns, out.Rows, out.Matched
	noteSampled(res, out)
	res.Truncated = res.Truncated || out.Truncated
	return nil
}

// mapPlaceholder stands for each $field$ when markMapValues finds where
// the values went.
const mapPlaceholder = "signalithmapvalue"

// markMapValues marks the comparisons of q, map's search for one row,
// whose whole value is a $field$ of template as Exact, so a * or ? in an
// event's value is not a wildcard (SRCH-04). It parses the template with
// a plain placeholder for every value: the values cannot change the
// search's shape (SubstituteMap), so its terms line up with q's.
func markMapValues(template string, q *query.Query) {
	text, err := query.SubstituteMap(template, func(string) (string, bool) { return mapPlaceholder, true })
	if err != nil {
		return
	}
	pq, err := query.ParseMapSearch(text)
	if err != nil {
		return
	}
	markExact(q.Search, pq.Search)
	if len(q.Commands) != len(pq.Commands) {
		return
	}
	for i, c := range q.Commands {
		w, ok := c.(*query.Where)
		pw, pok := pq.Commands[i].(*query.Where)
		if ok && pok {
			markExact(w.Expr, pw.Expr)
		}
	}
}

// markExact walks e and the same expression parsed with placeholders (p)
// together, marking each comparison whose value was the placeholder.
func markExact(e, p query.Expr) {
	switch e := e.(type) {
	case *query.And:
		if p, ok := p.(*query.And); ok && len(p.Children) == len(e.Children) {
			for i := range e.Children {
				markExact(e.Children[i], p.Children[i])
			}
		}
	case *query.Or:
		if p, ok := p.(*query.Or); ok && len(p.Children) == len(e.Children) {
			for i := range e.Children {
				markExact(e.Children[i], p.Children[i])
			}
		}
	case *query.Not:
		if p, ok := p.(*query.Not); ok {
			markExact(e.Child, p.Child)
		}
	case *query.Compare:
		if p, ok := p.(*query.Compare); ok && p.Value == mapPlaceholder && !e.Ref && (e.Op == "=" || e.Op == "!=") {
			e.Exact = true
		}
	}
}
