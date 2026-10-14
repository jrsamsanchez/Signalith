package api

import (
	"fmt"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// Explain describes a query in plain English, one sentence per step, so
// analysts can read detections and searches someone else wrote.
func Explain(q *query.Query) []string {
	var steps []string
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
		}
		if a.Alias != "" {
			s += fmt.Sprintf(" (as %s)", a.Alias)
		}
		parts[i] = s
	}
	return strings.Join(parts, ", ")
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
	case *query.Top:
		s := fmt.Sprintf("List the %d most common values of %s with their count and percentage", c.Limit, strings.Join(c.Fields, " and "))
		if len(c.By) > 0 {
			s += " for each " + strings.Join(c.By, " and ")
		}
		return s + "."
	case *query.Where:
		return "Keep only rows where " + describeExpr(c.Expr) + "."
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
	case *query.Rename:
		parts := make([]string, len(c.Pairs))
		for i, p := range c.Pairs {
			parts[i] = p[0] + " to " + p[1]
		}
		return "Rename " + strings.Join(parts, ", ") + "."
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
