// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// OpenSearch's aggregation results read as Splunk's stats functions give
// them: sample variance from the population one, ranges, and _time in
// seconds.
func TestAggValueFromOpenSearch(t *testing.T) {
	stats := map[string]any{"count": json.Number("4"), "variance": json.Number("2"), "sum_of_squares": json.Number("30"), "min": json.Number("1"), "max": json.Number("4")}
	one := map[string]any{"count": json.Number("1"), "variance": json.Number("0")}
	none := map[string]any{"count": json.Number("0"), "variance": json.Number("0"), "sum_of_squares": json.Number("0")}
	for _, c := range []struct {
		fn, field string
		m         map[string]any
		want      any
	}{
		{"var", "x", stats, 2.6666666666666665},
		{"stdev", "x", one, int64(0)},
		{"stdevp", "x", stats, 1.4142135623730951},
		{"varp", "x", stats, int64(2)},
		{"varp", "x", none, nil},
		{"stdevp", "x", none, nil},
		{"sumsq", "x", stats, int64(30)},
		{"sumsq", "x", none, nil},
		{"range", "x", stats, int64(3)},
		{"range", "x", map[string]any{"min": json.Number("1")}, nil},
		{"var", "x", map[string]any{"count": "x"}, nil},
		{"perc95", "x", map[string]any{"values": []any{}}, nil},
		{"median", "x", map[string]any{"values": []any{map[string]any{"value": json.Number("7")}}}, int64(7)},
		{"varp", "_time", map[string]any{"count": json.Number("2"), "variance": json.Number("4000000")}, int64(4)},
		{"min", "_time", map[string]any{"value": json.Number("5000")}, int64(5)},
		{"values", "_time", map[string]any{"buckets": []any{map[string]any{"key": "a"}}}, "a"},
		{"count", "_time", map[string]any{"value": json.Number("3")}, int64(3)},
		{"dc", "x", nil, nil},
	} {
		got := aggValue(query.Agg{Func: c.fn, Field: c.field}, map[string]any{"m": c.m}, "m")
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s(%s) = %#v, want %#v", c.fn, c.field, got, c.want)
		}
	}
	// A summed count reads a value, or 0 without one.
	if got := summedCount(map[string]any{"m": map[string]any{"value": json.Number("12")}}, "m"); got != 12 {
		t.Errorf("summedCount = %d", got)
	}
	if got := summedCount(map[string]any{"m": map[string]any{"value": "x"}}, "m"); got != 0 {
		t.Errorf("summedCount = %d", got)
	}
	if got := summedCount(map[string]any{}, "m"); got != 0 {
		t.Errorf("summedCount = %d", got)
	}
	if metricValue(map[string]any{}, "m") != nil || metricValue(map[string]any{"m": map[string]any{"value": json.Number("2")}}, "m") != int64(2) {
		t.Error("metricValue")
	}
}

// A filter's fields are listed when it reads only fields' values.
func TestExprFields(t *testing.T) {
	for src, want := range map[string][]string{
		`a=1 b=2`:                {"a", "b"},
		`a=1 OR NOT b IN (1, 2)`: {"a", "b"},
		`*`:                      nil,
	} {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := exprFields(q.Search)
		if !ok || !slices.Equal(got, want) {
			t.Errorf("exprFields(%s) = %v %v", src, got, ok)
		}
	}
	for _, src := range []string{`foo`, `a=1 foo`, `a=1 OR foo`, `NOT foo`} {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := exprFields(q.Search); ok {
			t.Errorf("exprFields(%s) reads only fields", src)
		}
	}
	if got, ok := exprFields(&query.Compare{Field: "a", Op: "=", Value: "b", Ref: true}); !ok || !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("field comparison = %v %v", got, ok)
	}
	if _, ok := exprFields(&query.Compare{Field: "a", Op: "=", Value: RawField, Ref: true}); ok {
		t.Error("a comparison with the raw event reads only fields")
	}
}

// A timechart's buckets become one row per time, with a column per
// aggregation.
func TestTimechartRowsFromBuckets(t *testing.T) {
	resp := map[string]any{"aggregations": map[string]any{"time": map[string]any{"buckets": []any{
		map[string]any{"key_as_string": "t1", "doc_count": json.Number("3"), "m0": map[string]any{"value": json.Number("9")}, "m1": map[string]any{"value": json.Number("2.5")}},
		map[string]any{"key_as_string": "t2", "doc_count": json.Number("1"), "m0": map[string]any{"value": json.Number("4")}, "m1": map[string]any{"value": json.Number("1")}},
	}}}}
	tc := &query.Timechart{Aggs: []query.Agg{{Func: "count"}, {Func: "avg", Field: "x"}}}
	rows, cols := timechartRows(resp, tc, false)
	want := []Row{{"_time": "t1", "count": int64(3), "avg(x)": 2.5}, {"_time": "t2", "count": int64(1), "avg(x)": int64(1)}}
	if !reflect.DeepEqual(rows, want) || !slices.Equal(cols, []string{"_time", "count", "avg(x)"}) {
		t.Errorf("rows = %v, cols = %v", rows, cols)
	}
	// Summed counts come from the summaries' sums, not the documents.
	rows, _ = timechartRows(resp, tc, true)
	if rows[0]["count"] != int64(9) || rows[1]["count"] != int64(4) {
		t.Errorf("summed rows = %v", rows)
	}
	// A list of numbers is normalized element by element.
	if got := normalize([]any{json.Number("1"), 2.0, "x", json.Number("1e400")}); !reflect.DeepEqual(got, []any{int64(1), int64(2), "x", "1e400"}) {
		t.Errorf("normalize = %#v", got)
	}
}
