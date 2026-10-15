package query

import "strings"

// Drill says how to find the events behind one number in a query's
// results: a dashboard opens Search on them when the number is clicked.
//
// The events query is Search, then the caller's field=value filters, then
// Pipe. When Where is set the filters cannot go in the search (a command
// before the summary makes or changes fields, or limits the events), so
// they go after Pipe as "| where field=value AND ...".
type Drill struct {
	// Search is the query's search, ready for terms to be added after it;
	// empty when it matches everything.
	Search string `json:"search"`
	// Pipe holds the commands before the summary, each starting "\n| ".
	Pipe  string `json:"pipe,omitempty"`
	Where bool   `json:"where,omitempty"`
	// Fields maps a result column to the event field its values come from:
	// the by fields of stats, top or timechart, followed through renames.
	Fields map[string]string `json:"fields,omitempty"`
	// Series is timechart's by field: each series column is one of its
	// values.
	Series string `json:"series,omitempty"`
	// Latest is the query's own latest=, if any. Its earliest= is already
	// the panel's time range.
	Latest string `json:"latest,omitempty"`
}

// Drilldown returns how to find the events behind q's results. Every
// query has one: without stats, top or timechart its results are the
// events themselves.
func (q *Query) Drilldown() *Drill {
	d := &Drill{Latest: q.Latest}
	base := &Query{Datamodel: q.Datamodel, Index: q.Index, Search: q.Search}
	if or, ok := q.Search.(*Or); ok {
		// a OR b, then host=x, would read as a OR (b AND host=x).
		base.Search = &And{Children: []Expr{or}}
	}
	if s := base.String(); s != "*" {
		d.Search = s
	}
	cut := len(q.Commands)
	for i, c := range q.Commands {
		if summarises(c) {
			cut = i
			break
		}
	}
	var pipe strings.Builder
	for _, c := range q.Commands[:cut] {
		pipe.WriteString("\n| " + CommandString(c))
		switch c := c.(type) {
		case *Where:
			if _, expr := c.Expr.(*Cond); expr {
				d.Where = true
			}
		case *ThreatMatch:
		default:
			d.Where = true
		}
	}
	d.Pipe = pipe.String()
	if cut == len(q.Commands) {
		return d
	}
	fields := map[string]string{}
	switch c := q.Commands[cut].(type) {
	case *Stats:
		for _, f := range c.By {
			fields[f] = f
		}
	case *Top:
		for _, f := range append(append([]string{}, c.Fields...), c.By...) {
			fields[f] = f
		}
	case *Timechart:
		d.Series = c.By
	}
	for _, c := range q.Commands[cut+1:] {
		switch c := c.(type) {
		case *Rename:
			for _, p := range c.Pairs {
				f, ok := fields[p[0]]
				delete(fields, p[0])
				delete(fields, p[1])
				if ok {
					fields[p[1]] = f
				}
			}
		case *Eval:
			for _, a := range c.Assigns {
				delete(fields, a.Field)
			}
		case *Fillnull:
			// A filled-in value is in no event.
			if len(c.Fields) == 0 {
				clear(fields)
			}
			for _, f := range c.Fields {
				delete(fields, f)
			}
		case *Rex:
			// Its groups can overwrite any column.
			clear(fields)
		case *Stats, *Top, *Timechart:
			// A summary of a summary: only the time range still holds.
			clear(fields)
			d.Series = ""
		}
	}
	if len(fields) > 0 {
		d.Fields = fields
	}
	return d
}

func summarises(c Command) bool {
	switch c.(type) {
	case *Stats, *Top, *Timechart:
		return true
	}
	return false
}
