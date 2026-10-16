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
	// Events is set when the query has no summary: each result row is an
	// event.
	Events bool `json:"events,omitempty"`
	// Fields maps a result column to the event field its values come from:
	// the by fields of stats, top or timechart, followed through renames.
	Fields map[string]string `json:"fields,omitempty"`
	// Series is timechart's by field: each series column is one of its
	// values.
	Series string `json:"series,omitempty"`
	// Earliest and Latest are the query's own time range, if it sets one.
	Earliest string `json:"earliest,omitempty"`
	Latest   string `json:"latest,omitempty"`
}

// Drilldown returns how to find the events behind q's results. Every
// query has one: without stats, top or timechart its results are the
// events themselves.
func (q *Query) Drilldown() *Drill {
	d := &Drill{Earliest: q.Earliest, Latest: q.Latest}
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
		case *ThreatMatch, *Table, *Sort:
		case *Head, *Dedup:
			// They pick which events a summary counts, so a filter must
			// come after them; without a summary a filter only finds one
			// of the events, which it can do first.
			if cut < len(q.Commands) {
				d.Where = true
			}
		default:
			d.Where = true
		}
	}
	d.Pipe = pipe.String()
	if cut == len(q.Commands) {
		d.Events = true
		return d
	}
	fields := map[string]string{}
	switch c := q.Commands[cut].(type) {
	case *Stats:
		for _, f := range c.By {
			fields[f] = f
		}
	case *Top:
		// An other row's value is in no event, so with one only the by
		// fields narrow the events.
		if !c.UseOther {
			for _, f := range c.Fields {
				fields[f] = f
			}
		}
		for _, f := range c.By {
			fields[f] = f
		}
	case *Timechart:
		d.Series = c.By
	case *Chart:
		fields[c.Over] = c.Over
		d.Series = c.By
	}
	for _, c := range q.Commands[cut+1:] {
		switch c := c.(type) {
		case *Rename:
			for _, p := range c.Pairs {
				// A renamed column replaces one that had its new name.
				next := map[string]string{}
				for col, f := range fields {
					if to, ok := RenameField(p, col); ok {
						next[to] = f
					}
				}
				for col, f := range fields {
					if _, renamed := RenameField(p, col); !renamed {
						if _, replaced := next[col]; !replaced {
							next[col] = f
						}
					}
				}
				fields = next
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
		case *MVExpand:
			delete(fields, c.Field)
		case *MakeMV:
			delete(fields, c.Field)
		case *AddTotals:
			// The totals row's label is in no event.
			delete(fields, c.TotalName())
			if c.LabelField != "" {
				delete(fields, c.LabelField)
			}
		case *Rex, *Spath:
			// Its fields can overwrite any column.
			clear(fields)
		case *Bin:
			// Buckets are in no event.
			if c.As != "" {
				delete(fields, c.As)
			} else {
				delete(fields, c.Field)
			}
		case *StreamStats:
			for _, a := range c.Aggs {
				delete(fields, a.Column())
			}
		case *EventStats:
			for _, a := range c.Aggs {
				delete(fields, a.Column())
			}
		case *Stats, *Top, *Timechart, *Chart, *Append, *AppendPipe, *XYSeries, *Untable:
			// A summary of a summary, or rows from elsewhere: only the
			// time range still holds.
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
	case *Stats, *Top, *Timechart, *Chart:
		return true
	}
	return false
}
