package search

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

const (
	// maxSubsearchTerms bounds the field values a search's subsearches
	// put among its terms, which OpenSearch caps as a query's clauses.
	maxSubsearchTerms = 1000
	// maxSubsearchTermBytes bounds the text of those values.
	maxSubsearchTermBytes = 1 << 20
)

// resolveSubsearches returns q with each subsearch among its terms (and
// those of its | search commands) run and replaced by the terms its
// rows make, or q itself when it has none. A subsearch runs as the
// search's own does, within the same limits and with its time range.
func (e *Engine) resolveSubsearches(ctx context.Context, q *query.Query) (*query.Query, error) {
	if !hasSubsearchTerms(q) {
		return q, nil
	}
	out := *q
	var err error
	if out.Search, err = e.resolveExpr(ctx, q.Search, q); err != nil {
		return nil, err
	}
	if out.Commands, err = e.resolveCommands(ctx, q.Commands, q); err != nil {
		return nil, err
	}
	return &out, nil
}

func (e *Engine) resolveCommands(ctx context.Context, cmds []query.Command, q *query.Query) ([]query.Command, error) {
	var out []query.Command
	for _, c := range cmds {
		switch c := c.(type) {
		case *query.Where:
			w := *c
			x, err := e.resolveExpr(ctx, c.Expr, q)
			if err != nil {
				return nil, err
			}
			w.Expr = x
			out = append(out, &w)
		case *query.AppendPipe:
			a := *c
			sub, err := e.resolveCommands(ctx, c.Commands, q)
			if err != nil {
				return nil, err
			}
			a.Commands = sub
			out = append(out, &a)
		default:
			out = append(out, c)
		}
	}
	return out, nil
}

func (e *Engine) resolveExpr(ctx context.Context, x query.Expr, outer *query.Query) (query.Expr, error) {
	switch x := x.(type) {
	case *query.And:
		out := &query.And{}
		for _, c := range x.Children {
			r, err := e.resolveExpr(ctx, c, outer)
			if err != nil {
				return nil, err
			}
			out.Children = append(out.Children, r)
		}
		return out, nil
	case *query.Or:
		out := &query.Or{}
		for _, c := range x.Children {
			r, err := e.resolveExpr(ctx, c, outer)
			if err != nil {
				return nil, err
			}
			out.Children = append(out.Children, r)
		}
		return out, nil
	case *query.Not:
		r, err := e.resolveExpr(ctx, x.Child, outer)
		if err != nil {
			return nil, err
		}
		return &query.Not{Child: r}, nil
	case *query.Subsearch:
		res, err := e.runSubsearch(ctx, subsearch(x.Query, outer))
		if err != nil {
			return nil, err
		}
		return subsearchTerms(res)
	}
	return x, nil
}

// runSubsearch runs a subsearch, its own subsearch terms first.
func (e *Engine) runSubsearch(ctx context.Context, sq *query.Query) (*Result, error) {
	sq, err := e.resolveSubsearches(ctx, sq)
	if err != nil {
		return nil, err
	}
	p, err := e.compile(sq)
	if err != nil {
		return nil, err
	}
	return e.run(ctx, sq, p)
}

// subsearchTerms writes a subsearch's rows as Splunk's format command
// does: each row the AND of field=value for its fields (a field with
// several values any of them), the rows ORed. A search field's value is
// read as search terms, a query field's as text. Fields that start with
// _ are left out. No rows match nothing.
func subsearchTerms(res *Result) (query.Expr, error) {
	terms, size := 0, 0
	add := func(v string) error {
		terms++
		size += len(v)
		if terms > maxSubsearchTerms || size > maxSubsearchTermBytes {
			return &QueryError{Msg: fmt.Sprintf("a subsearch gives more than %d values or %d MB to search for; narrow it with fields, dedup or head", maxSubsearchTerms, maxSubsearchTermBytes>>20)}
		}
		return nil
	}
	out := &query.Or{}
	for _, r := range res.Rows {
		var keys []string
		for k := range r {
			if !strings.HasPrefix(k, "_") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		row := &query.And{}
		for _, k := range keys {
			var vals []string
			for _, v := range asList(r[k]) {
				if s, ok := evStr(v); ok && s != "" {
					vals = append(vals, s)
				}
			}
			alt := &query.Or{}
			for _, v := range vals {
				if err := add(v); err != nil {
					return nil, err
				}
				switch k {
				case "search":
					sq, err := query.Parse(v)
					if err != nil {
						return nil, &QueryError{Msg: "a subsearch's search field does not parse: " + err.Error()}
					}
					if len(sq.Commands) > 0 || sq.Index != "" || sq.Datamodel != "" || sq.Earliest != "" || sq.Latest != "" || hasSubsearchTerms(sq) {
						return nil, &QueryError{Msg: "a subsearch's search field may hold only search terms"}
					}
					if sq.Search != nil {
						alt.Children = append(alt.Children, sq.Search)
					}
				case "query":
					alt.Children = append(alt.Children, &query.Text{Value: v})
				default:
					alt.Children = append(alt.Children, &query.Compare{Field: k, Op: "=", Value: v})
				}
			}
			switch len(alt.Children) {
			case 0:
			case 1:
				row.Children = append(row.Children, alt.Children[0])
			default:
				row.Children = append(row.Children, alt)
			}
		}
		switch len(row.Children) {
		case 0:
		case 1:
			out.Children = append(out.Children, row.Children[0])
		default:
			out.Children = append(out.Children, row)
		}
	}
	return out, nil
}

// hasSubsearchTerms reports whether a subsearch is among q's terms or
// those of its | search commands.
func hasSubsearchTerms(q *query.Query) bool {
	found := false
	mark := func(*query.Subsearch) { found = true }
	query.WalkSubsearches(q.Search, mark)
	var walk func([]query.Command)
	walk = func(cmds []query.Command) {
		for _, c := range cmds {
			switch c := c.(type) {
			case *query.Where:
				query.WalkSubsearches(c.Expr, mark)
			case *query.AppendPipe:
				walk(c.Commands)
			}
		}
	}
	walk(q.Commands)
	return found
}

// withoutSubsearches returns q with match-everything in place of the
// subsearches among its terms, for compiling it before they run.
func withoutSubsearches(q *query.Query) *query.Query {
	var strip func(x query.Expr) query.Expr
	strip = func(x query.Expr) query.Expr {
		switch x := x.(type) {
		case *query.And:
			out := &query.And{}
			for _, c := range x.Children {
				out.Children = append(out.Children, strip(c))
			}
			return out
		case *query.Or:
			out := &query.Or{}
			for _, c := range x.Children {
				out.Children = append(out.Children, strip(c))
			}
			return out
		case *query.Not:
			return &query.Not{Child: strip(x.Child)}
		case *query.Subsearch:
			return &query.And{}
		}
		return x
	}
	out := *q
	out.Search = strip(q.Search)
	out.Commands = nil
	for _, c := range q.Commands {
		if w, ok := c.(*query.Where); ok {
			s := *w
			s.Expr = strip(w.Expr)
			c = &s
		}
		out.Commands = append(out.Commands, c)
	}
	return &out
}
