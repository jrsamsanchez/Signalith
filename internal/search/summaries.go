// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/query"
	sumidx "github.com/jrsamsanchez/signalith/internal/summary"
)

// summaryUse is how a search reads summary indexes: the whole slots of
// the models in Ranges come from summary rows, everything else from
// events.
type summaryUse struct {
	ranges   map[string][]sumidx.Range
	earliest time.Time // zero: all time
	latest   time.Time
}

// models lists the data models the search reads summaries of.
func (s *summaryUse) models() []string {
	return slices.Sorted(func(yield func(string) bool) {
		for m := range s.ranges {
			if !yield(m) {
				return
			}
		}
	})
}

// summaryPlan decides whether a search can read summaries: no index= or
// threat matching, filters only on dimensions, and a first command that
// counts or sums by dimensions (stats) or over whole 5-minute slots
// (timechart). For a search of every data model, each model qualifies
// on its own. It returns nil when no model's summaries help.
func (e *Engine) summaryPlan(q *query.Query, filters []query.Expr, cmd query.Command, earliest string, now time.Time) *summaryUse {
	if q.EventsOnly || e.Summaries == nil || e.SummaryDays() <= 0 || (q.Index != "" && q.Index != "*") {
		return nil
	}
	var aggs []query.Agg
	var by []string
	switch c := cmd.(type) {
	case *query.Stats:
		aggs, by = c.Aggs, c.By
	case *query.Timechart:
		span := c.Span
		if span == "" {
			span = autoSpan(earliest)
		}
		if !wholeSlots(span) {
			return nil
		}
		aggs = c.Aggs
		if c.By != "" {
			by = []string{c.By}
		}
	default:
		return nil
	}
	if len(aggs) == 0 {
		return nil
	}
	var fields []string
	for _, f := range filters {
		fs, ok := exprFields(f)
		if !ok {
			return nil
		}
		fields = append(fields, fs...)
	}
	fields = append(fields, by...)
	from, ok := resolveTime(earliest, now)
	if !ok {
		return nil
	}
	to, ok := resolveTime(q.Latest, now)
	if !ok || to.IsZero() {
		return nil
	}
	if !from.IsZero() && !to.After(from) {
		return nil
	}
	// Only whole slots inside the time range come from summaries.
	lo := from
	if r := lo.Truncate(sumidx.Slot); r.Before(lo) {
		lo = r.Add(sumidx.Slot)
	}
	hi := to.Truncate(sumidx.Slot)

	var models []string
	if q.Datamodel != "" {
		m, ok := datamodel.Get(q.Datamodel)
		if !ok {
			return nil
		}
		models = []string{m.Name}
	} else {
		for _, m := range sumidx.Models() {
			if m != datamodel.RiskModel { // not in a search of all events
				models = append(models, m)
			}
		}
	}
	use := &summaryUse{ranges: map[string][]sumidx.Range{}, earliest: from, latest: to}
	for _, m := range models {
		if !qualifies(m, fields, aggs) {
			continue
		}
		var rs []sumidx.Range
		for _, r := range e.Summaries.Ranges(m) {
			a, b := r.From, r.To
			if !lo.IsZero() && a.Before(lo) {
				a = lo
			}
			if b.After(hi) {
				b = hi
			}
			if b.After(a) {
				rs = append(rs, sumidx.Range{From: a, To: b})
			}
		}
		if len(rs) > 0 {
			use.ranges[m] = rs
		}
	}
	// Each range is two clauses; OpenSearch refuses a query of more than
	// 1,024. The models with the most ranges (the most gaps) read events.
	for total := countRanges(use.ranges); total > maxSummaryRanges; {
		worst := ""
		for _, m := range use.models() {
			if worst == "" || len(use.ranges[m]) > len(use.ranges[worst]) {
				worst = m
			}
		}
		total -= len(use.ranges[worst])
		delete(use.ranges, worst)
	}
	if len(use.ranges) == 0 {
		return nil
	}
	return use
}

// maxSummaryRanges caps the covered ranges one search reads summaries
// of, keeping its query well under OpenSearch's 1,024 clauses.
const maxSummaryRanges = 200

func countRanges(rs map[string][]sumidx.Range) int {
	n := 0
	for _, r := range rs {
		n += len(r)
	}
	return n
}

// qualifies reports whether a model's summaries hold what a search needs.
func qualifies(model string, fields []string, aggs []query.Agg) bool {
	for _, f := range fields {
		if !sumidx.IsDim(model, f) {
			return false
		}
	}
	for _, a := range aggs {
		switch {
		case a.Func == "count" && a.Field == "":
		case a.Func == "sum" && sumidx.IsMeasure(model, a.Field):
		default:
			return false
		}
	}
	return true
}

// exprFields lists the fields a filter reads; ok is false when it reads
// more than fields' values (free text, the raw event, its time or index).
func exprFields(e query.Expr) ([]string, bool) {
	switch e := e.(type) {
	case nil:
		return nil, true
	case *query.And:
		return childFields(e.Children)
	case *query.Or:
		return childFields(e.Children)
	case *query.Not:
		return exprFields(e.Child)
	case *query.Compare:
		return []string{e.Field}, plainField(e.Field)
	case *query.In:
		return []string{e.Field}, plainField(e.Field)
	}
	return nil, false
}

func childFields(es []query.Expr) ([]string, bool) {
	var out []string
	for _, c := range es {
		fs, ok := exprFields(c)
		if !ok {
			return nil, false
		}
		out = append(out, fs...)
	}
	return out, true
}

func plainField(f string) bool {
	return f != RawField && f != "_time" && f != IndexField && f != TimeField
}

var fixedSpan = regexp.MustCompile(`^(\d+)(s|m|h|d)$`)

// wholeSlots reports whether timechart buckets of span hold whole
// summary slots: a fixed span that is a multiple of 5 minutes, or a
// calendar week, month or year.
func wholeSlots(span string) bool {
	iv, err := spanInterval(span)
	if err != nil {
		return false
	}
	if _, ok := iv["calendar_interval"]; ok {
		return true
	}
	s, _ := iv["fixed_interval"].(string)
	m := fixedSpan.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	n, _ := strconv.Atoi(m[1])
	d := time.Duration(n) * map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
	return d >= sumidx.Slot && d%sumidx.Slot == 0
}

// resolveTime turns an earliest= or latest= value into a time, as
// toDateMath's OpenSearch date math would: empty or now is now, 0 is
// all time (zero), -24h and -7d@d are relative, and ISO 8601 or epoch
// milliseconds are absolute. ok is false for anything else.
func resolveTime(v string, now time.Time) (time.Time, bool) {
	v = strings.TrimSpace(v)
	switch {
	case v == "" || strings.EqualFold(v, "now"):
		return now, true
	case v == "0":
		return time.Time{}, true
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t.UTC(), true
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		// As OpenSearch reads the number toDateMath passes on.
		return time.UnixMilli(n).UTC(), true
	}
	m := relTime.FindStringSubmatch(v)
	if m == nil || (m[1] == "" && m[4] == "") {
		return time.Time{}, false
	}
	t := now.UTC()
	if m[3] != "" || m[2] != "" {
		n := 1
		if m[2] != "" {
			var err error
			if n, err = strconv.Atoi(m[2]); err != nil {
				return time.Time{}, false
			}
		}
		if m[1] == "-" {
			n = -n
		}
		switch unitMap[strings.ToLower(m[3])] {
		case "s":
			t = t.Add(time.Duration(n) * time.Second)
		case "m":
			t = t.Add(time.Duration(n) * time.Minute)
		case "h":
			t = t.Add(time.Duration(n) * time.Hour)
		case "d":
			t = t.AddDate(0, 0, n)
		case "w":
			t = t.AddDate(0, 0, 7*n)
		case "M":
			t = t.AddDate(0, n, 0)
		case "y":
			t = t.AddDate(n, 0, 0)
		default:
			return time.Time{}, false
		}
	}
	if m[4] != "" {
		switch unitMap[strings.ToLower(m[4])] {
		case "s":
			t = t.Truncate(time.Second)
		case "m":
			t = t.Truncate(time.Minute)
		case "h":
			t = t.Truncate(time.Hour)
		case "d":
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		case "M":
			t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
		case "y":
			t = time.Date(t.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
		default:
			// OpenSearch rounds a week to its Monday; not worth
			// copying for a snap nobody uses.
			return time.Time{}, false
		}
	}
	return t, true
}

// clause is the filter that reads, for each model, summary rows of its
// covered slots and events everywhere else: rows have ModelField, events
// never do.
func (s *summaryUse) clause() map[string]any {
	var rows, covered []any
	for _, m := range s.models() {
		var rs []any
		for _, r := range s.ranges[m] {
			rs = append(rs, map[string]any{"range": map[string]any{TimeField: map[string]any{
				"gte": r.From.UnixMilli(), "lt": r.To.UnixMilli(), "format": "epoch_millis"}}})
		}
		inRanges := map[string]any{"bool": map[string]any{"should": rs, "minimum_should_match": 1}}
		rows = append(rows, boolQuery("filter", []any{map[string]any{"term": map[string]any{sumidx.ModelField: m}}, inRanges}))
		covered = append(covered, boolQuery("filter", []any{map[string]any{"term": map[string]any{"datamodel": m}}, inRanges}))
	}
	isRow := map[string]any{"exists": map[string]any{"field": sumidx.ModelField}}
	return map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
		map[string]any{"bool": map[string]any{"filter": []any{isRow}, "should": rows, "minimum_should_match": 1}},
		map[string]any{"bool": map[string]any{"must_not": append([]any{isRow}, covered...)}},
	}}}
}

// timeFilter is the search's time range as absolute times, the ones the
// summary ranges were cut to.
func (s *summaryUse) timeFilter() map[string]any {
	r := map[string]any{"format": "epoch_millis", "lte": s.latest.UnixMilli()}
	if !s.earliest.IsZero() {
		r["gte"] = s.earliest.UnixMilli()
	}
	return map[string]any{"range": map[string]any{TimeField: r}}
}

// countAgg counts events in a search that reads summaries: a row stands
// for CountField events, an event (which has no such field) for one.
func countAgg() map[string]any {
	return map[string]any{"sum": map[string]any{"field": sumidx.CountField, "missing": 1}}
}

// eventsAgg is the aggregation that counts the events a summarized
// search matched, for Result.Matched.
const eventsAgg = "events"

// summedCount reads a countAgg's events as a whole number.
func summedCount(container map[string]any, name string) int64 {
	m, _ := container[name].(map[string]any)
	if m == nil {
		return int64(0)
	}
	if f, ok := asFloat(toNumber(m["value"])); ok {
		return int64(f)
	}
	return int64(0)
}
