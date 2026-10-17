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

	// EventsOnly makes the search read events, never summary indexes:
	// detections must see events that arrived late at once, not when
	// the summaries are next checked. Set by callers, not parsed.
	EventsOnly bool
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
	v := FormatValue(e.Value)
	if e.Op == "=" && strings.HasPrefix(v, "~") {
		v = quote(v) // =~ would read as a regular expression match
	}
	return e.Field + e.Op + v
}
func (e *In) String() string {
	vals := make([]string, len(e.Values))
	for i, v := range e.Values {
		vals[i] = FormatValue(v)
	}
	return e.Field + " IN (" + strings.Join(vals, ", ") + ")"
}
func (e *Text) String() string {
	if e.Value == "*" {
		return `"*"` // a bare * is no search term at all
	}
	if strings.EqualFold(e.Value, "search") {
		return quote(e.Value) // first, a bare search is the command's name
	}
	return FormatValue(e.Value)
}

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
	// Brackets would end or open a join's subsearch.
	needs = needs || strings.ContainsAny(v, "[]")
	if !needs {
		return v
	}
	return quote(v)
}

// optionValue writes the value of a key=value option: as FormatValue,
// but quoted when it starts with ~, which after = would read as =~.
func optionValue(v string) string {
	if strings.HasPrefix(v, "~") {
		return quote(v)
	}
	return FormatValue(v)
}

func quote(v string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
}

// formatName quotes a column name in table or as rename's old name unless
// it reads back as the same name: a bare word, or a stats column such as
// dc(user). An alias or a new name is quoted with FormatValue.
func formatName(n string) string {
	if i := strings.IndexByte(n, '('); i > 0 && strings.HasSuffix(n, ")") && isAggFunc(strings.ToLower(n[:i])) {
		if inner := n[i+1 : len(n)-1]; inner != "" && FormatValue(inner) == inner {
			return n
		}
	}
	return FormatValue(n)
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
		// A name that is not a bare word, such as one an eval() alias
		// gave, is quoted: values(" ").
		s += "(" + FormatValue(a.Field) + ")"
	}
	if a.Alias != "" {
		s += " as " + FormatValue(a.Alias)
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
	Rare   bool // rare: the least common values first

	CountField   string // the count column's name; "" is count
	PercentField string // the percent column's name; "" is percent
	NoCount      bool   // showcount=f
	NoPercent    bool   // showperc=f
	// UseOther adds a row per group counting the values past the limit,
	// with OtherStr (OTHER when "") as the value of each field.
	UseOther bool
	OtherStr string
}

// CountColumn is the name top gives its count column.
func (t *Top) CountColumn() string {
	if t.CountField == "" {
		return "count"
	}
	return t.CountField
}

// PercentColumn is the name top gives its percent column.
func (t *Top) PercentColumn() string {
	if t.PercentField == "" {
		return "percent"
	}
	return t.PercentField
}

// Other is the value top's other row holds.
func (t *Top) Other() string {
	if t.OtherStr == "" {
		return "OTHER"
	}
	return t.OtherStr
}

// Where filters rows: where count > 20 AND src != "10.0.0.1". Search is
// set when it was written as a search command, | search count>20 user=adm*,
// which filters with the search's own syntax.
type Where struct {
	Expr   Expr
	Search bool
}

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

func (*Stats) Name() string     { return "stats" }
func (*Timechart) Name() string { return "timechart" }
func (t *Top) Name() string {
	if t.Rare {
		return "rare"
	}
	return "top"
}
func (w *Where) Name() string {
	if w.Search {
		return "search"
	}
	return "where"
}
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
			s += " span=" + optionValue(c.Span)
		}
		s += " " + aggList(c.Aggs)
		if c.By != "" {
			s += " by " + c.By
		}
		return s
	case *Top:
		// Always written: without it the default of 10 would apply, and
		// limit=0 (no limit) would be lost.
		s := c.Name() + " limit=" + strconv.Itoa(max(c.Limit, 0)) + topOptions(c)
		s += " " + strings.Join(c.Fields, ", ")
		if len(c.By) > 0 {
			s += " by " + strings.Join(c.By, ", ")
		}
		return s
	case *EventStats:
		s := "eventstats " + aggList(c.Aggs)
		if len(c.By) > 0 {
			s += " by " + strings.Join(c.By, ", ")
		}
		return s
	case *Where:
		if c.Search {
			return "search " + topLevel(c.Expr, " ")
		}
		return "where " + topLevel(c.Expr, " AND ")
	case *Eval:
		return evalString(c)
	case *Rex:
		return rexString(c)
	case *Dedup:
		return dedupString(c)
	case *Fillnull:
		return fillnullString(c)
	case *Sort:
		keys := make([]string, len(c.Keys))
		for i, k := range c.Keys {
			if k.Desc {
				keys[i] = "-" + k.Field
			} else if strings.HasPrefix(k.Field, "-") || strings.HasPrefix(k.Field, "+") {
				keys[i] = "+" + k.Field // the sign is part of the name
			} else {
				keys[i] = k.Field
			}
		}
		return "sort " + strings.Join(keys, ", ")
	case *Head:
		return "head " + strconv.Itoa(c.N)
	case *Table:
		names := make([]string, len(c.Fields))
		for i, f := range c.Fields {
			names[i] = formatName(f)
		}
		return "table " + strings.Join(names, ", ")
	case *MVExpand:
		return mvExpandString(c)
	case *MakeMV:
		return makeMVString(c)
	case *Reverse:
		return "reverse"
	case *Tail:
		return "tail " + strconv.Itoa(c.N)
	case *Uniq:
		return "uniq"
	case *Convert:
		return convertString(c)
	case *AddTotals:
		return addTotalsString(c)
	case *Rename:
		ps := make([]string, len(c.Pairs))
		for i, p := range c.Pairs {
			ps[i] = formatName(p[0]) + " as " + FormatValue(p[1])
		}
		return "rename " + strings.Join(ps, ", ")
	case *Lookup:
		return lookupString(c)
	case *InputLookup:
		return inputLookupString(c)
	case *Transaction:
		return transactionString(c)
	case *Join:
		return joinString(c)
	case *Append:
		return "append [search " + c.Sub.String() + "]"
	case *Union:
		return unionString(c)
	case *Geostats:
		return geostatsString(c)
	case *Extract:
		return extractString(c)
	case *Outlier:
		return outlierString(c)
	case *Gauge:
		return gaugeString(c)
	case *MultiSearch:
		return multiSearchString(c)
	case *Timewrap:
		return timewrapString(c)
	case *Cluster:
		return clusterString(c)
	case *XPath:
		return xpathString(c)
	case *Abstract:
		return abstractString(c)
	case *Highlight:
		return highlightString(c)
	case *AnomalyDetection:
		return anomalyString(c)
	case *Correlate:
		return correlateString(c)
	case *Predict:
		return predictString(c)
	case *Set:
		return setString(c)
	case *SetFields:
		return setFieldsString(c)
	case *AppendPipe:
		return appendPipeString(c)
	case *StreamStats:
		return streamStatsString(c)
	case *Bin:
		return binString(c)
	case *Regex:
		return regexString(c)
	case *MakeResults:
		return makeResultsString(c)
	case *FieldsRemove:
		return fieldsRemoveString(c)
	case *Chart:
		return chartString(c)
	case *XYSeries:
		return seriesString("xyseries", append([]string{c.X, c.Y}, c.Values...)...)
	case *Untable:
		return seriesString("untable", c.X, c.Label, c.Value)
	case *Spath:
		return spathString(c)
	case *FromJSON:
		return fromJSONString(c)
	case *NoMV:
		return "nomv " + FormatValue(c.Field)
	case *MVCombine:
		return mvCombineString(c)
	case *StrCat:
		return strCatString(c)
	case *RangeMap:
		return rangeMapString(c)
	case *ForEach:
		return forEachString(c)
	case *Replace:
		return replaceString(c)
	case *XMLKV:
		return xmlkvString(c)
	case *IPLocation:
		return ipLocationString(c)
	case *Map:
		return mapString(c)
	case *Accum, *Delta, *AutoRegress, *FieldSummary:
		return seqString(c)
	case *Transpose, *FillDown, *AddInfo, *Trendline:
		return rowCmdString(c)
	case *Concurrency, *Contingency, *Format:
		return shapeCmdString(c)
	case *Return, *MakeContinuous:
		return returnCmdString(c)
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
	// Without its parentheses, a term such as earliest=0 would read back
	// as the query's own earliest=, not as a search of that field.
	if hasReserved(e) {
		if _, ok := e.(*Compare); ok {
			return "(" + e.String() + ")"
		}
		return e.String()
	}
	switch e := e.(type) {
	case *And:
		return joinExprs(e.Children, andSep)
	case *Or:
		return joinExprs(e.Children, " OR ")
	}
	return e.String()
}

// hasReserved reports whether e, printed without parentheses at the top of
// a query, would start a term that the parser takes as datamodel=, index=,
// earliest= or latest=.
func hasReserved(e Expr) bool {
	var kids []Expr
	switch e := e.(type) {
	case *Compare:
		if e.Op != "=" {
			return false
		}
		switch strings.ToLower(e.Field) {
		case "datamodel", "index", "earliest", "latest":
			return true
		}
		return false
	case *And:
		kids = e.Children
	case *Or:
		kids = e.Children
	}
	for _, k := range kids {
		if c, ok := k.(*Compare); ok && hasReserved(c) {
			return true
		}
	}
	return false
}
