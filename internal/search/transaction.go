package search

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// transaction groups the rows that share the values of c.Fields into one
// row each, oldest event first: _time is the first event's, duration the
// seconds to the last, eventcount how many there were, _raw their raw
// text one per line, and every other field the distinct values of its
// events. A row with no time, or without one of the fields, is left out.
//
// An event joins its group's open transaction unless that would pass
// maxspan, maxpause or maxevents, or it matches startswith; then the open
// one ends and the event starts another. With startswith, an event that
// does not match it and has no open transaction is left out; with
// endswith, a transaction ends at the event that matches it, and one that
// never does is left out.
func transaction(ctx context.Context, res *Result, c *query.Transaction) error {
	type event struct {
		at  time.Time
		row Row
	}
	type group struct{ events []event }
	evs := make([]event, 0, len(res.Rows))
	keys := make([]string, 0, len(res.Rows))
	vals := make([]string, len(c.Fields))
rows:
	for _, r := range res.Rows {
		at, ok := toTime(r["_time"])
		if !ok {
			continue
		}
		for i, f := range c.Fields {
			s, ok := evStr(r[f])
			if !ok || s == "" {
				continue rows
			}
			vals[i] = s
		}
		evs = append(evs, event{at, r})
		keys = append(keys, strings.Join(vals, "\x00"))
	}
	// Rows come newest first; a transaction reads oldest first. A stable
	// sort keeps the order of events with the same time.
	idx := make([]int, len(evs))
	for i := range idx {
		idx[i] = len(evs) - 1 - i
	}
	sort.SliceStable(idx, func(a, b int) bool { return evs[idx[a]].at.Before(evs[idx[b]].at) })

	m := &matcher{ctx: ctx}
	open := map[string]*group{}
	var done []*group
	end := func(g *group) {
		if c.EndsWith == nil {
			done = append(done, g)
		}
	}
	span, pause := time.Duration(c.MaxSpan)*time.Second, time.Duration(c.MaxPause)*time.Second
	for n, i := range idx {
		if n%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		ev, key := evs[i], keys[i]
		g := open[key]
		if g != nil {
			first, last := g.events[0].at, g.events[len(g.events)-1].at
			if span > 0 && ev.at.Sub(first) > span || pause > 0 && ev.at.Sub(last) > pause || len(g.events) >= c.MaxEvents {
				end(g)
				g = nil
			}
		}
		starts := c.StartsWith != nil && m.eval(c.StartsWith, ev.row)
		if starts && g != nil {
			end(g)
			g = nil
		}
		if g == nil {
			delete(open, key)
			if c.StartsWith != nil && !starts {
				continue
			}
			g = &group{}
			open[key] = g
		}
		g.events = append(g.events, ev)
		if c.EndsWith != nil && m.eval(c.EndsWith, ev.row) {
			done = append(done, g)
			delete(open, key)
		}
		if m.err != nil {
			return m.err
		}
	}
	for _, g := range open {
		end(g)
	}

	ev := evaluatorFor(ctx)
	out := make([]Row, 0, len(done))
	at := make([]time.Time, 0, len(done))
	for n, g := range done {
		if n%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		row := Row{}
		var order []string
		seen := map[string]map[string]bool{}
		var raws []string
		rawBytes := 0
		for _, e := range g.events {
			for k, v := range e.row {
				switch k {
				case "_time":
					continue
				case RawField:
					// Up to the size of one computed value.
					if s, ok := evStr(v); ok && rawBytes+len(s) < maxEvalValue {
						raws = append(raws, s)
						rawBytes += len(s) + 1
					}
					continue
				}
				if seen[k] == nil {
					seen[k] = map[string]bool{}
					order = append(order, k)
				}
				for _, x := range asList(v) {
					s, ok := evStr(x)
					if !ok || seen[k][s] || len(seen[k]) >= maxMultiValues {
						continue
					}
					seen[k][s] = true
					row[k] = append(asList(row[k]), x)
				}
			}
		}
		for _, k := range order {
			row[k] = mvOut(asList(row[k]))
			if row[k] == nil {
				delete(row, k)
			}
		}
		first, last := g.events[0], g.events[len(g.events)-1]
		row["_time"] = first.row["_time"]
		row["duration"] = numOut(last.at.Sub(first.at).Seconds())
		row["eventcount"] = int64(len(g.events))
		if len(raws) > 0 {
			if !ev.charge(rawBytes) {
				return ev.err
			}
			row[RawField] = strings.Join(raws, "\n")
		}
		out = append(out, row)
		at = append(at, first.at)
	}
	// Newest first, as events are.
	order := make([]int, len(out))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return at[order[a]].After(at[order[b]]) })
	res.Rows = make([]Row, len(out))
	for i, j := range order {
		res.Rows[i] = out[j]
	}
	addColumn(res, "duration")
	addColumn(res, "eventcount")
	return nil
}
