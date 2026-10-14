package query

import (
	"strconv"
	"strings"
)

// Query is a parsed query.
type Query struct {
	// Search is the filter expression before the first pipe, with the
	// special terms below removed. Nil means "match everything".
	Search Expr

	Datamodel string // datamodel=Authentication
	Index     string // index=custom-*
	Earliest  string // earliest=-24h (empty: caller's default)
	Latest    string // latest=now (empty: now)

	Commands []Command
}

// Expr is a boolean filter expression.
type Expr interface{ String() string }

// And matches when every child matches.
type And struct{ Children []Expr }

// Or matches when any child matches.
type Or struct{ Children []Expr }

// Not negates its child.
type Not struct{ Child Expr }

// Compare is field <op> value, where op is one of = != < <= > >=, or =~
// for a regular expression found anywhere in the value (RE2 syntax, ^ and
// $ to anchor it).
type Compare struct {
	Field string
	Op    string
	Value string
}

// In is field IN (v1, v2, ...).
type In struct {
	Field  string
	Values []string
}

// Text is a free-text term matched against the raw event.
type Text struct{ Value string }

func (e *And) String() string { return "(" + joinExprs(e.Children, " AND ") + ")" }
func (e *Or) String() string  { return "(" + joinExprs(e.Children, " OR ") + ")" }
func (e *Not) String() string { return "NOT " + e.Child.String() }
func (e *Compare) String() string {
	return e.Field + e.Op + FormatValue(e.Value)
}
func (e *In) String() string {
	vals := make([]string, len(e.Values))
	for i, v := range e.Values {
		vals[i] = FormatValue(v)
	}
	return e.Field + " IN (" + strings.Join(vals, ", ") + ")"
}
func (e *Text) String() string { return FormatValue(e.Value) }

func joinExprs(es []Expr, sep string) string {
	parts := make([]string, len(es))
	for i, e := range es {
		parts[i] = e.String()
	}
	return strings.Join(parts, sep)
}

// FormatValue quotes a value when it would not survive the lexer as a bare word.
func FormatValue(v string) string {
	if v == "" {
		return `""`
	}
	needs := false
	for _, r := range v {
		if !isWordRune(r) {
			needs = true
			break
		}
	}
	switch strings.ToUpper(v) {
	case "AND", "OR", "NOT", "IN", "AS", "BY":
		needs = true
	}
	if !needs {
		return v
	}
	return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
}

// Command is one pipe stage.
type Command interface{ Name() string }

// Agg is one aggregation in stats, timechart or top.
type Agg struct {
	Func  string // count, dc, sum, avg, min, max
	Field string // empty for bare count
	Alias string
}

// Column returns the output column name.
func (a Agg) Column() string {
	if a.Alias != "" {
		return a.Alias
	}
	if a.Field == "" {
		return a.Func
	}
	return a.Func + "(" + a.Field + ")"
}

func (a Agg) String() string {
	s := a.Func
	if a.Field != "" {
		s += "(" + a.Field + ")"
	}
	if a.Alias != "" {
		s += " as " + a.Alias
	}
	return s
}

// Stats aggregates events into a table: stats count, dc(user) by src.
type Stats struct {
	Aggs []Agg
	By   []string
}

// Timechart buckets events over time: timechart span=1h count by action.
type Timechart struct {
	Span string
	Aggs []Agg
	By   string
}

// Top returns the most common values: top limit=10 src by dest.
type Top struct {
	Limit  int
	Fields []string
	By     []string
}

// Where filters rows: where count > 20 AND src != "10.0.0.1".
type Where struct{ Expr Expr }

// SortKey is one sort field.
type SortKey struct {
	Field string
	Desc  bool
}

// Sort orders rows: sort -count, src.
type Sort struct{ Keys []SortKey }

// Head keeps the first N rows.
type Head struct{ N int }

// Table keeps only the listed columns, in order.
type Table struct{ Fields []string }

// Rename renames columns: rename src as source_ip.
type Rename struct{ Pairs [][2]string }

// Enrich adds asset and identity context: enrich, or enrich user, dest.
// With no fields it enriches the usual entity fields.
type Enrich struct{ Fields []string }

// Intel adds threat intel columns (<field>_intel_source and so on) for
// values that match an indicator: intel, or intel src, dest.
type Intel struct{ Fields []string }

// ThreatMatch keeps only events whose fields match threat intel. The
// matching runs inside OpenSearch, so it must come right after the search.
type ThreatMatch struct{ Fields []string }

func (*Stats) Name() string       { return "stats" }
func (*Timechart) Name() string   { return "timechart" }
func (*Top) Name() string         { return "top" }
func (*Where) Name() string       { return "where" }
func (*Sort) Name() string        { return "sort" }
func (*Head) Name() string        { return "head" }
func (*Table) Name() string       { return "table" }
func (*Rename) Name() string      { return "rename" }
func (*Enrich) Name() string      { return "enrich" }
func (*Intel) Name() string       { return "intel" }
func (*ThreatMatch) Name() string { return "threatmatch" }

// String renders the query back to canonical text.
func (q *Query) String() string {
	var parts []string
	if q.Datamodel != "" {
		parts = append(parts, "datamodel="+FormatValue(q.Datamodel))
	}
	if q.Index != "" {
		parts = append(parts, "index="+FormatValue(q.Index))
	}
	if q.Search != nil {
		parts = append(parts, topLevel(q.Search, " "))
	}
	if q.Earliest != "" {
		parts = append(parts, "earliest="+FormatValue(q.Earliest))
	}
	if q.Latest != "" {
		parts = append(parts, "latest="+FormatValue(q.Latest))
	}
	s := strings.Join(parts, " ")
	if s == "" {
		s = "*"
	}
	for _, c := range q.Commands {
		s += "\n| " + CommandString(c)
	}
	return s
}

// CommandString renders one command.
func CommandString(c Command) string {
	switch c := c.(type) {
	case *Stats:
		s := "stats " + aggList(c.Aggs)
		if len(c.By) > 0 {
			s += " by " + strings.Join(c.By, ", ")
		}
		return s
	case *Timechart:
		s := "timechart"
		if c.Span != "" {
			s += " span=" + c.Span
		}
		s += " " + aggList(c.Aggs)
		if c.By != "" {
			s += " by " + c.By
		}
		return s
	case *Top:
		s := "top"
		if c.Limit > 0 {
			s += " limit=" + strconv.Itoa(c.Limit)
		}
		s += " " + strings.Join(c.Fields, ", ")
		if len(c.By) > 0 {
			s += " by " + strings.Join(c.By, ", ")
		}
		return s
	case *Where:
		return "where " + topLevel(c.Expr, " AND ")
	case *Sort:
		keys := make([]string, len(c.Keys))
		for i, k := range c.Keys {
			if k.Desc {
				keys[i] = "-" + k.Field
			} else {
				keys[i] = k.Field
			}
		}
		return "sort " + strings.Join(keys, ", ")
	case *Head:
		return "head " + strconv.Itoa(c.N)
	case *Table:
		return "table " + strings.Join(c.Fields, ", ")
	case *Rename:
		ps := make([]string, len(c.Pairs))
		for i, p := range c.Pairs {
			ps[i] = p[0] + " as " + p[1]
		}
		return "rename " + strings.Join(ps, ", ")
	case *Enrich:
		if len(c.Fields) == 0 {
			return "enrich"
		}
		return "enrich " + strings.Join(c.Fields, ", ")
	case *Intel:
		if len(c.Fields) == 0 {
			return "intel"
		}
		return "intel " + strings.Join(c.Fields, ", ")
	case *ThreatMatch:
		if len(c.Fields) == 0 {
			return "threatmatch"
		}
		return "threatmatch " + strings.Join(c.Fields, ", ")
	}
	return c.Name()
}

func aggList(aggs []Agg) string {
	s := make([]string, len(aggs))
	for i, a := range aggs {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

// topLevel renders an expression without its outermost parentheses.
func topLevel(e Expr, andSep string) string {
	switch e := e.(type) {
	case *And:
		return joinExprs(e.Children, andSep)
	case *Or:
		return joinExprs(e.Children, " OR ")
	}
	return e.String()
}
