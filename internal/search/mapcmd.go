package search

import (
	"context"
	"errors"
	"strconv"

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
		text, err := query.SubstituteMap(c.Search, func(name string) (string, bool) {
			v := r[name]
			if mv, ok := v.([]any); ok && len(mv) > 0 {
				v = mv[0]
			}
			s, ok := evStr(v)
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
		sq := subsearch(q, outer)
		sq, err = e.resolveSubsearches(ctx, sq)
		if err != nil {
			return err
		}
		p, err := e.compile(sq)
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
	}
	res.Kind, res.Columns, res.Rows, res.Matched = out.Kind, out.Columns, out.Rows, out.Matched
	res.Truncated = res.Truncated || out.Truncated
	return nil
}
