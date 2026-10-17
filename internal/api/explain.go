package api

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// Explain describes a query in plain English, one sentence per step, so
// analysts can read detections and searches someone else wrote.
func Explain(q *query.Query) []string {
	var steps []string
	if len(q.Commands) > 0 {
		if c, ok := q.Commands[0].(*query.InputLookup); ok {
			first := "Read the rows of the lookup table " + c.Table
			if c.Max > 0 {
				first += fmt.Sprintf(", at most %d", c.Max)
			}
			steps = append(steps, first+".")
			for _, c := range q.Commands[1:] {
				steps = append(steps, describeCommand(c))
			}
			return steps
		}
		if c, ok := q.Commands[0].(*query.MakeResults); ok {
			first := "Make one row holding only the current time"
			if c.Count > 1 {
				first = fmt.Sprintf("Make %d rows, each holding only the current time", c.Count)
			}
			steps = append(steps, first+".")
			for _, c := range q.Commands[1:] {
				steps = append(steps, describeCommand(c))
			}
			return steps
		}
	}
	src := "all events"
	if q.Datamodel != "" {
		src = q.Datamodel + " events"
	} else if q.Index != "" {
		src = "events in indexes matching " + q.Index
	}
	when := ""
	// 0 is all time.
	earliest := q.Earliest
	if earliest == "0" {
		earliest = ""
	}
	switch {
	case earliest != "" && q.Latest != "":
		when = fmt.Sprintf(" between %s and %s", describeTime(earliest), describeTime(q.Latest))
	case earliest != "":
		when = " from " + describeTime(earliest) + " until now"
	case q.Latest != "":
		when = " until " + describeTime(q.Latest)
	}
	first := "Take " + src + when
	if q.Search != nil {
		first += " where " + describeExpr(q.Search)
	}
	steps = append(steps, first+".")
	for _, c := range q.Commands {
		steps = append(steps, describeCommand(c))
	}
	return steps
}

func describeTime(v string) string {
	if v == "now" {
		return "now"
	}
	if strings.HasPrefix(v, "-") {
		n := strings.TrimLeft(v[1:], "0123456789")
		num := v[1 : len(v)-len(n)]
		unit, snap, _ := strings.Cut(n, "@")
		names := map[string]string{"s": "second", "m": "minute", "h": "hour", "d": "day", "w": "week", "mon": "month", "y": "year"}
		name := names[unit]
		if name == "" {
			return v
		}
		if num == "" {
			num = "1"
		}
		if num != "1" {
			name += "s"
		}
		out := num + " " + name + " ago"
		if snap != "" {
			out += ", rounded down to the start of the " + names[snap]
		}
		return out
	}
	return v
}

func describeExpr(e query.Expr) string {
	switch e := e.(type) {
	case *query.And:
		parts := make([]string, len(e.Children))
		for i, c := range e.Children {
			parts[i] = describeExpr(c)
		}
		return strings.Join(parts, " and ")
	case *query.Or:
		parts := make([]string, len(e.Children))
		for i, c := range e.Children {
			parts[i] = describeExpr(c)
		}
		return "(" + strings.Join(parts, " or ") + ")"
	case *query.Not:
		return "not " + describeExpr(e.Child)
	case *query.Text:
		return fmt.Sprintf("the raw event contains %q", e.Value)
	case *query.In:
		return fmt.Sprintf("%s is one of %s", e.Field, strings.Join(e.Values, ", "))
	case *query.Compare:
		if e.Value == "*" && e.Op == "=" {
			return e.Field + " has any value"
		}
		if e.Op == "=~" {
			return fmt.Sprintf("%s matches the regular expression %s", e.Field, e.Value)
		}
		verb := map[string]string{"=": "is", "!=": "is not", "<": "is less than", "<=": "is at most", ">": "is greater than", ">=": "is at least"}[e.Op]
		if strings.ContainsAny(e.Value, "*?") && (e.Op == "=" || e.Op == "!=") {
			verb = map[string]string{"=": "matches", "!=": "does not match"}[e.Op]
		}
		return fmt.Sprintf("%s %s %s", e.Field, verb, e.Value)
	case *query.Cond:
		return e.String() + " holds"
	}
	return e.String()
}

func describeAggs(aggs []query.Agg) string {
	parts := make([]string, len(aggs))
	for i, a := range aggs {
		var s string
		switch a.Func {
		case "count":
			if a.Field == "" {
				s = "the number of events"
			} else {
				s = "the number of events with " + a.Field
			}
		case "dc":
			s = "the number of distinct " + a.Field + " values"
		case "sum":
			s = "the total " + a.Field
		case "avg":
			s = "the average " + a.Field
		case "min":
			s = "the smallest " + a.Field
		case "max":
			s = "the largest " + a.Field
		case "median":
			s = "the median " + a.Field
		case "stdev":
			s = "the standard deviation of " + a.Field
		case "var":
			s = "the variance of " + a.Field
		case "range":
			s = "the range (largest minus smallest) of " + a.Field
		case "mode":
			s = "the most common " + a.Field
		case "values":
			s = "the distinct values of " + a.Field
		case "list":
			s = "every value of " + a.Field
		case "first", "latest":
			s = "the newest " + a.Field
		case "last", "earliest":
			s = "the oldest " + a.Field
		default:
			if n := query.Percentile(a.Func); n > 0 {
				s = fmt.Sprintf("the %s percentile of %s", ordinal(n), a.Field)
			} else {
				s = a.String()
			}
		}
		if a.Alias != "" {
			s += fmt.Sprintf(" (as %s)", a.Alias)
		}
		parts[i] = s
	}
	return strings.Join(parts, ", ")
}

func ordinal(n int) string {
	suffix := "th"
	switch {
	case n%100 >= 11 && n%100 <= 13:
	case n%10 == 1:
		suffix = "st"
	case n%10 == 2:
		suffix = "nd"
	case n%10 == 3:
		suffix = "rd"
	}
	return strconv.Itoa(n) + suffix
}

func describeCommand(c query.Command) string {
	switch c := c.(type) {
	case *query.Stats:
		s := "Calculate " + describeAggs(c.Aggs)
		if len(c.By) > 0 {
			s += " for each " + strings.Join(c.By, " and ")
		}
		return s + "."
	case *query.Timechart:
		span := c.Span
		if span == "" {
			span = "an automatic interval"
		}
		s := "Chart " + describeAggs(c.Aggs) + " over time in buckets of " + span
		if c.By != "" {
			s += ", one line per " + c.By
		}
		return s + "."
	case *query.EventStats:
		s := "Add " + describeAggs(c.Aggs)
		if len(c.By) > 0 {
			s += " for each " + strings.Join(c.By, " and ")
		}
		return s + " to every row, keeping the rows."
	case *query.Eval:
		parts := make([]string, len(c.Assigns))
		for i, a := range c.Assigns {
			parts[i] = a.Field + " to " + a.Expr.String()
		}
		if c.Format {
			return "Set " + strings.Join(parts, ", then ") + " (fieldformat runs as eval)."
		}
		return "Set " + strings.Join(parts, ", then ") + "."
	case *query.NoMV:
		return "Join the values of " + c.Field + " into one, a line each."
	case *query.MVCombine:
		return "Merge rows that differ only in " + c.Field + " into one row holding all their " + c.Field + " values."
	case *query.StrCat:
		parts := make([]string, len(c.Parts))
		for i, p := range c.Parts {
			parts[i] = p.Text
			if p.Literal {
				parts[i] = strconv.Quote(p.Text)
			}
		}
		s := "Join " + strings.Join(parts, ", ") + " into " + c.Dest
		if c.AllRequired {
			s += ", only where every field has a value"
		}
		return s + "."
	case *query.RangeMap:
		parts := make([]string, len(c.Ranges))
		for i, r := range c.Ranges {
			parts[i] = fmt.Sprintf("%s for %g to %g", r.Name, r.Lo, r.Hi)
		}
		return "Set range by " + c.Field + ": " + strings.Join(parts, ", ") + ", otherwise " + c.DefaultName() + "."
	case *query.Replace:
		parts := make([]string, 0, len(c.Pairs))
		for _, p := range c.Pairs {
			parts = append(parts, strconv.Quote(p[0])+" with "+strconv.Quote(p[1]))
		}
		where := "every field"
		if len(c.Fields) > 0 {
			where = strings.Join(c.Fields, ", ")
		}
		return "Replace " + strings.Join(parts, ", ") + " in " + where + "."
	case *query.Accum:
		return "Set " + c.AccumName() + " to the running total of " + c.Field + "."
	case *query.Delta:
		return fmt.Sprintf("Set %s to %s minus its value %d rows with a number earlier.", c.DeltaName(), c.Field, c.P)
	case *query.AutoRegress:
		return "Copy " + c.Field + " from earlier rows into " + strings.Join(c.Names(), ", ") + "."
	case *query.Transpose:
		s := fmt.Sprintf("Turn the first %d rows into columns, one row per field with its name in %s", c.Rows, c.ColumnName)
		if c.HeaderField != "" {
			s += " and columns named by " + c.HeaderField
		}
		return s + "."
	case *query.FillDown:
		if len(c.Fields) == 0 {
			return "Give each row missing a field that field's value in the last row that has it."
		}
		return "Give each row missing " + strings.Join(c.Fields, ", ") + " the value in the last row that has it."
	case *query.AddInfo:
		return "Add the search's time range and run time (info_min_time, info_max_time, info_search_time) to each row."
	case *query.Trendline:
		names := make([]string, 0, len(c.Trends))
		for _, t := range c.Trends {
			names = append(names, t.Name())
		}
		return "Add the moving averages " + strings.Join(names, ", ") + "."
	case *query.Concurrency:
		return fmt.Sprintf("Set %s to how many rows were in progress when each started, using %s as the start and %s as the duration in seconds.", c.Output, c.Start, c.Duration)
	case *query.Contingency:
		return "Count each pair of " + c.RowField + " and " + c.ColField + " values in a table, one row per " + c.RowField + " and one column per " + c.ColField + "."
	case *query.Format:
		return "Turn the rows into one search that matches them, in a field named search."
	case *query.Return:
		return fmt.Sprintf("Turn the first %d rows with a value into search terms, in a field named search.", c.Count)
	case *query.MakeContinuous:
		return "Add an empty row for each " + c.Span + " of " + c.Field + " that no row has, and sort the rows by " + c.Field + "."
	case *query.FieldSummary:
		return "Describe each field: how many rows have it, its distinct and most common values, and for numbers min, max, mean and stdev."
	case *query.Map:
		return fmt.Sprintf("For each of the first %d rows, run the search %s with the row's values in place of its $field$ names, and keep the rows those searches find.", c.Max, strconv.Quote(c.Search))
	case *query.IPLocation:
		return "Add where the IP address in " + c.Field + " is, from the GeoIP database: " + strings.Join(c.Fields(), ", ") + "."
	case *query.XMLKV:
		return "Extract the text of each XML element in " + c.Field + " as a field named by its tag."
	case *query.ForEach:
		return "For each field matching " + strings.Join(c.Fields, ", ") + ", run: " + c.Body + "."
	case *query.Rex:
		if c.Sed != "" {
			return "Change the text of " + c.Field + " with the sed expression " + c.Sed + "."
		}
		re, err := regexp.Compile(c.Pattern)
		var names []string
		if err == nil {
			for _, n := range re.SubexpNames() {
				if n != "" {
					names = append(names, n)
				}
			}
		}
		s := "Extract " + strings.Join(names, ", ") + " from " + c.Field + " with the regular expression " + c.Pattern
		switch c.MaxMatch {
		case 1:
		case 0:
			s += ", keeping every match"
		default:
			s += fmt.Sprintf(", keeping up to %d matches", c.MaxMatch)
		}
		return s + "."
	case *query.Join:
		s := "Join each row to the rows of a subsearch that share its " + strings.Join(c.Fields, " and ")
		switch c.Max {
		case 0:
			s += fmt.Sprintf(" (every match, up to %d)", query.MaxJoinMatches)
		case 1:
			s += " (the first match)"
		default:
			s += fmt.Sprintf(" (up to %d matches)", c.Max)
		}
		s += ", adding their fields"
		if c.Left {
			s += "; rows with no match are kept"
		} else {
			s += "; rows with no match are dropped"
		}
		return s + ". The subsearch: " + strings.Join(Explain(c.Sub), " ")
	case *query.Transaction:
		s := "Group the events"
		if len(c.Fields) > 0 {
			s += " by " + strings.Join(c.Fields, " and ")
		}
		s += " into transactions, oldest event first"
		var limits []string
		if c.MaxSpan > 0 {
			limits = append(limits, fmt.Sprintf("at most %d seconds long", c.MaxSpan))
		}
		if c.MaxPause > 0 {
			limits = append(limits, fmt.Sprintf("with at most %d seconds between events", c.MaxPause))
		}
		limits = append(limits, fmt.Sprintf("of at most %d events", c.MaxEvents))
		s += ", each " + strings.Join(limits, ", ")
		if c.StartsWith != nil {
			s += "; an event where " + describeExpr(c.StartsWith) + " starts one"
		}
		if c.EndsWith != nil {
			s += "; an event where " + describeExpr(c.EndsWith) + " ends one, and one that never ends is dropped"
		}
		return s + ". Each gets duration (seconds) and eventcount."
	case *query.Dedup:
		s := "Keep only the first row"
		if c.N > 1 {
			s = fmt.Sprintf("Keep only the first %d rows", c.N)
		}
		s += " for each " + strings.Join(c.Fields, " and ")
		if c.Consecutive {
			s += ", dropping only repeats that follow each other"
		}
		if c.KeepEmpty {
			s += "; rows missing one of these fields are kept"
		} else {
			s += "; rows missing one of these fields are dropped"
		}
		return s + "."
	case *query.Fillnull:
		what := "every column"
		if len(c.Fields) > 0 {
			what = strings.Join(c.Fields, ", ")
		}
		return fmt.Sprintf("Fill missing values in %s with %s.", what, c.Value)
	case *query.Top:
		which := "most"
		if c.Rare {
			which = "least"
		}
		var with []string
		if !c.NoCount {
			with = append(with, "count")
		}
		if !c.NoPercent {
			with = append(with, "percentage")
		}
		s := fmt.Sprintf("List the %d %s common values of %s", c.Limit, which, strings.Join(c.Fields, " and "))
		if len(with) > 0 {
			s += " with their " + strings.Join(with, " and ")
		}
		if len(c.By) > 0 {
			s += " for each " + strings.Join(c.By, " and ")
		}
		if c.UseOther {
			s += ", and a row counting the rest as " + c.Other()
		}
		return s + "."
	case *query.Where:
		if c.Search {
			return "Keep only rows matching " + describeExpr(c.Expr) + "."
		}
		return "Keep only rows where " + describeExpr(c.Expr) + "."
	case *query.MVExpand:
		s := "Make one row for each value of " + c.Field
		if c.Limit > 0 {
			s += fmt.Sprintf(" (up to %d per row)", c.Limit)
		}
		return s + "."
	case *query.MakeMV:
		switch {
		case c.Tokenizer != "":
			return "Split " + c.Field + " into a value for each match of " + c.Tokenizer + "."
		case c.Delim != "":
			return "Split " + c.Field + " into values at each " + strconv.Quote(c.Delim) + "."
		}
		return "Split " + c.Field + " into values at each space."
	case *query.Reverse:
		return "Turn the order of the rows around."
	case *query.Tail:
		return fmt.Sprintf("Keep the last %d rows, last first.", c.N)
	case *query.Uniq:
		return "Drop rows that repeat the row before them exactly."
	case *query.Convert:
		parts := make([]string, 0, len(c.Funcs))
		for _, f := range c.Funcs {
			s := f.Func + "(" + f.Field + ")"
			if f.As != "" {
				s += " into " + f.As
			}
			parts = append(parts, s)
		}
		return "Convert " + strings.Join(parts, ", ") + "."
	case *query.AddTotals:
		var parts []string
		what := "the numeric fields"
		if len(c.Fields) > 0 {
			what = strings.Join(c.Fields, ", ")
		}
		if !c.NoRow {
			parts = append(parts, "add up "+what+" of each row into "+c.TotalName())
		}
		if c.Col {
			parts = append(parts, "add a last row with each column's total")
		}
		s := strings.Join(parts, " and ")
		return strings.ToUpper(s[:1]) + s[1:] + "."
	case *query.Sort:
		parts := make([]string, len(c.Keys))
		for i, k := range c.Keys {
			dir := "lowest first"
			if k.Desc {
				dir = "highest first"
			}
			parts[i] = k.Field + " (" + dir + ")"
		}
		return "Sort by " + strings.Join(parts, ", then ") + "."
	case *query.Head:
		return fmt.Sprintf("Keep the first %d rows.", c.N)
	case *query.Table:
		return "Show only the columns " + strings.Join(c.Fields, ", ") + "."
	case *query.Chart:
		s := "Chart " + describeAggs(c.Aggs) + " for each " + c.Over
		if c.By != "" {
			s += ", one column per " + c.By
			if c.Limit > 0 {
				s += fmt.Sprintf(" (the %d largest)", c.Limit)
			}
		}
		return s + "."
	case *query.XYSeries:
		return "Make one row per " + c.X + " with one column per " + c.Y + ", holding " + strings.Join(c.Values, " and ") + "."
	case *query.Untable:
		return "Make one row per cell: " + c.X + ", the column's name as " + c.Label + " and its value as " + c.Value + "."
	case *query.Spath:
		if c.Path == "" {
			return "Extract every value from the JSON in " + c.Input + ", each named by its path."
		}
		out := c.Output
		if out == "" {
			out = c.Path
		}
		return "Extract " + c.Path + " from the JSON in " + c.Input + " into " + out + "."
	case *query.FromJSON:
		if c.Prefix != "" {
			return "Extract each top-level key of the JSON object in " + c.Field + " as a field named " + c.Prefix + " and the key."
		}
		return "Extract each top-level key of the JSON object in " + c.Field + " as a field of the same name."
	case *query.FieldsRemove:
		return "Remove the fields " + strings.Join(c.Fields, ", ") + "."
	case *query.StreamStats:
		s := "Add a running " + describeAggs(c.Aggs)
		if len(c.By) > 0 {
			s += " for each " + strings.Join(c.By, " and ")
		}
		s += " to every row, over the rows before it"
		if c.Current {
			s += " and the row itself"
		}
		if c.Window > 0 {
			s += fmt.Sprintf(", looking back at most %d rows", c.Window)
		}
		return s + "."
	case *query.Bin:
		s := "Round " + c.Field + " down into buckets of " + c.Span
		if c.As != "" {
			s += ", writing the bucket to " + c.As
		}
		return s + "."
	case *query.Regex:
		if c.Negate {
			return "Keep only rows where " + c.Field + " does not match the regular expression " + c.Pattern + "."
		}
		return "Keep only rows where " + c.Field + " matches the regular expression " + c.Pattern + "."
	case *query.MakeResults:
		return fmt.Sprintf("Make %d rows holding only the current time.", c.Count)
	case *query.Append:
		return "Add the rows of a subsearch after these. The subsearch: " + strings.Join(Explain(c.Sub), " ")
	case *query.Union:
		parts := make([]string, 0, len(c.Subs))
		for i, s := range c.Subs {
			parts = append(parts, fmt.Sprintf("Subsearch %d: %s", i+1, strings.Join(Explain(s), " ")))
		}
		return "Add the rows of each subsearch after these. " + strings.Join(parts, " ")
	case *query.AppendPipe:
		parts := make([]string, len(c.Commands))
		for i, cmd := range c.Commands {
			parts[i] = describeCommand(cmd)
		}
		return "Run these steps over a copy of the rows and add the rows they give after them: " + strings.Join(parts, " ")
	case *query.Rename:
		parts := make([]string, len(c.Pairs))
		for i, p := range c.Pairs {
			parts[i] = p[0] + " to " + p[1]
		}
		return "Rename " + strings.Join(parts, ", ") + "."
	case *query.Lookup:
		keys := make([]string, len(c.Keys))
		for i, k := range c.Keys {
			keys[i] = k.Field()
			if k.As != "" {
				keys[i] += " (as the table's " + k.Column + ")"
			}
		}
		what := "every other column"
		if len(c.Outputs) > 0 {
			cols := make([]string, len(c.Outputs))
			for i, o := range c.Outputs {
				cols[i] = o.Column
				if o.As != "" {
					cols[i] += " as " + o.As
				}
			}
			what = strings.Join(cols, ", ")
		}
		s := "Look up " + strings.Join(keys, " and ") + " in the lookup table " + c.Table + " and add " + what + " from the matching rows"
		if c.New {
			s += ", only where the field is not already set"
		}
		return s + "."
	case *query.Enrich:
		what := "user, src, dest and host fields"
		if len(c.Fields) > 0 {
			what = strings.Join(c.Fields, ", ")
		}
		return "Add owner, priority and category from the asset and identity lists for " + what + "."
	case *query.Intel:
		what, col := "the IP, domain, URL, hash and email fields", "src_intel_source"
		if len(c.Fields) > 0 {
			what, col = strings.Join(c.Fields, ", "), c.Fields[0]+"_intel_source"
		}
		return "Check " + what + " against threat intel and add the source, type, weight and description of any match (as " +
			col + " and so on)."
	case *query.ThreatMatch:
		what := "an IP, domain, URL, hash or email field"
		if len(c.Fields) > 0 {
			what = "any of " + strings.Join(c.Fields, ", ")
		}
		return "Keep only events where " + what + " matches a threat intel indicator, and add threat_match_field, " +
			"threat_match_value, threat_source and threat_weight describing the match."
	}
	return query.CommandString(c)
}
