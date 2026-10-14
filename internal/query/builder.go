package query

import "strings"

// Spec is the visual query builder's model. Build turns it into query text
// and FromQuery turns simple query text back into a Spec, so the builder and
// the text editor stay in sync in both directions.
type Spec struct {
	Datamodel string   `json:"datamodel,omitempty"`
	Text      string   `json:"text,omitempty"` // free-text search
	Filters   []Filter `json:"filters,omitempty"`
	Earliest  string   `json:"earliest,omitempty"`

	// Mode is "events" (list matching events), "stats" (a table) or
	// "timechart" (a series over time).
	Mode     string   `json:"mode,omitempty"`
	AggFunc  string   `json:"agg_func,omitempty"`  // count, dc, sum, avg, min, max
	AggField string   `json:"agg_field,omitempty"` // required unless AggFunc is count
	By       []string `json:"by,omitempty"`
	Span     string   `json:"span,omitempty"` // timechart only

	Sort   string   `json:"sort,omitempty"` // e.g. "-count"
	Limit  int      `json:"limit,omitempty"`
	Fields []string `json:"fields,omitempty"` // events mode: columns to show
}

// Filter is one field condition. Op is one of = != < <= > >=.
type Filter struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// Build converts a Spec to a parsed Query.
func Build(s Spec) *Query {
	q := &Query{Datamodel: s.Datamodel, Earliest: s.Earliest}
	var terms []Expr
	if t := strings.TrimSpace(s.Text); t != "" {
		terms = append(terms, &Text{Value: t})
	}
	for _, f := range s.Filters {
		if f.Field == "" {
			continue
		}
		op := f.Op
		if op == "" {
			op = "="
		}
		terms = append(terms, &Compare{Field: f.Field, Op: op, Value: f.Value})
	}
	q.Search = simplifyAnd(terms)

	agg := Agg{Func: s.AggFunc, Field: s.AggField}
	if agg.Func == "" || (agg.Func != "count" && agg.Field == "") {
		agg = Agg{Func: "count"}
	}
	if agg.Func == "count" {
		agg.Field = ""
	}
	switch s.Mode {
	case "stats":
		q.Commands = append(q.Commands, &Stats{Aggs: []Agg{agg}, By: s.By})
	case "timechart":
		tc := &Timechart{Span: s.Span, Aggs: []Agg{agg}}
		if len(s.By) > 0 {
			tc.By = s.By[0]
		}
		q.Commands = append(q.Commands, tc)
	}
	if s.Sort != "" {
		k := SortKey{Field: strings.TrimLeft(s.Sort, "+-"), Desc: strings.HasPrefix(s.Sort, "-")}
		q.Commands = append(q.Commands, &Sort{Keys: []SortKey{k}})
	}
	if s.Limit > 0 {
		q.Commands = append(q.Commands, &Head{N: s.Limit})
	}
	if s.Mode != "stats" && s.Mode != "timechart" && len(s.Fields) > 0 {
		q.Commands = append(q.Commands, &Table{Fields: s.Fields})
	}
	return q
}

// FromQuery converts a query back to a Spec. ok is false when the query uses
// anything the builder cannot show (OR, NOT, where, several aggregations...),
// in which case the UI keeps the text editor as the source of truth.
func FromQuery(q *Query) (s Spec, ok bool) {
	s = Spec{Datamodel: q.Datamodel, Earliest: q.Earliest, Mode: "events"}
	if q.Index != "" || q.Latest != "" {
		return s, false
	}
	var terms []Expr
	switch e := q.Search.(type) {
	case nil:
	case *And:
		terms = e.Children
	default:
		terms = []Expr{e}
	}
	for _, t := range terms {
		switch t := t.(type) {
		case *Compare:
			if t.Op == "=~" {
				return s, false
			}
			s.Filters = append(s.Filters, Filter{Field: t.Field, Op: t.Op, Value: t.Value})
		case *Text:
			if s.Text != "" {
				return s, false
			}
			s.Text = t.Value
		default:
			return s, false
		}
	}
	cmds := q.Commands
	if len(cmds) > 0 {
		switch c := cmds[0].(type) {
		case *Stats:
			if len(c.Aggs) != 1 || c.Aggs[0].Alias != "" {
				return s, false
			}
			s.Mode, s.AggFunc, s.AggField, s.By = "stats", c.Aggs[0].Func, c.Aggs[0].Field, c.By
			cmds = cmds[1:]
		case *Timechart:
			if len(c.Aggs) != 1 || c.Aggs[0].Alias != "" {
				return s, false
			}
			s.Mode, s.AggFunc, s.AggField, s.Span = "timechart", c.Aggs[0].Func, c.Aggs[0].Field, c.Span
			if c.By != "" {
				s.By = []string{c.By}
			}
			cmds = cmds[1:]
		}
	}
	if s.Mode == "events" && len(cmds) > 0 {
		if c, isTable := cmds[len(cmds)-1].(*Table); isTable {
			s.Fields = c.Fields
			cmds = cmds[:len(cmds)-1]
		}
	}
	if len(cmds) > 0 {
		if c, isSort := cmds[0].(*Sort); isSort {
			if len(c.Keys) != 1 {
				return s, false
			}
			s.Sort = c.Keys[0].Field
			if c.Keys[0].Desc {
				s.Sort = "-" + s.Sort
			}
			cmds = cmds[1:]
		}
	}
	if len(cmds) > 0 {
		if c, isHead := cmds[0].(*Head); isHead {
			s.Limit = c.N
			cmds = cmds[1:]
		}
	}
	return s, len(cmds) == 0
}
