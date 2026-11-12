// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// A default time range is a time in the past, or empty or 0 for all time.
func TestValidEarliest(t *testing.T) {
	for _, v := range []string{"", " 0 ", "-24h", "-7d@d", "@d", "-1mon@y", "-2qtr@q"} {
		if err := ValidEarliest(v); err != nil {
			t.Errorf("ValidEarliest(%q) = %v", v, err)
		}
	}
	for _, v := range []string{"+1h", "24h", "-1x", "@x", "-1d@x", "now", "2026-01-01"} {
		if err := ValidEarliest(v); err == nil || !strings.Contains(err.Error(), "not a time in the past") {
			t.Errorf("ValidEarliest(%q) = %v", v, err)
		}
	}
}

// Relative times become OpenSearch date math; what OpenSearch cannot
// read the same way is resolved to epoch milliseconds or passed through.
func TestToDateMathForms(t *testing.T) {
	for v, want := range map[string]string{
		"":           "now",
		"NOW":        "now",
		"now-1d":     "now-1d",
		"-24h":       "now-24h",
		"+2d":        "now+2d",
		"-d":         "now-1d",
		"@d":         "now/d",
		"-7d@d":      "now-7d/d",
		"-1mon@mon":  "now-1M/M",
		"2026-10-01": "2026-10-01",
		"-1x@d":      "-1x@d",
		"-1d@x":      "-1d@x",
		"garbage":    "garbage",
	} {
		if got := toDateMath(v); got != want {
			t.Errorf("toDateMath(%q) = %q, want %q", v, got, want)
		}
	}
	// Weeks and quarters, and epochs, are worked out here.
	for _, v := range []string{"@w", "-1q", "1700000000"} {
		got := toDateMath(v)
		if got == v || strings.HasPrefix(got, "now") {
			t.Errorf("toDateMath(%q) = %q, want epoch milliseconds", v, got)
		}
	}
}

// The timechart span follows how far back the search reaches.
func TestAutoSpanRanges(t *testing.T) {
	for earliest, want := range map[string]string{
		"-2h":        "1m",
		"-h":         "1m",
		"-24h":       "30m",
		"-7d":        "3h",
		"-30d":       "12h",
		"-1y":        "1d",
		"-2x":        "1h",
		"+1d":        "1h",
		"2026-01-01": "1h",
	} {
		if got := autoSpan(earliest); got != want {
			t.Errorf("autoSpan(%q) = %q, want %q", earliest, got, want)
		}
	}
}

// Spans become date histogram intervals, and malformed spans are refused.
func TestSpanInterval(t *testing.T) {
	got, err := spanInterval("2w")
	if err != nil || !reflect.DeepEqual(got, map[string]any{"fixed_interval": "14d", "offset": "+3d"}) {
		t.Errorf("2w = %v %v", got, err)
	}
	for _, bad := range []string{"1.5h", "h", "3x", "2mon"} {
		if _, err := spanInterval(bad); err == nil {
			t.Errorf("spanInterval(%q) succeeded", bad)
		}
	}
}

// The in-memory evaluation of an OpenSearch query agrees with what
// OpenSearch does for each kind of clause, and refuses what it cannot
// evaluate.
func TestEvalDSLClauses(t *testing.T) {
	doc := map[string]any{"message": "Hello World", "n": int64(5), "ok": true, "s": "Abc", "list": []any{"x", "y"}}
	for _, c := range []struct {
		q    map[string]any
		want bool
	}{
		{map[string]any{"match_all": map[string]any{}}, true},
		{map[string]any{"match_phrase": map[string]any{"message": "lo wor"}}, true},
		{map[string]any{"match_phrase": map[string]any{"message": "bye"}}, false},
		{map[string]any{"match_phrase": map[string]any{}}, false},
		{map[string]any{"term": map[string]any{}}, false},
		{map[string]any{"regexp": map[string]any{}}, false},
		{map[string]any{"range": map[string]any{}}, false},
		{map[string]any{"query_string": map[string]any{"default_field": "message", "query": `*o\ W*`}}, true},
		{map[string]any{"term": map[string]any{"ok": map[string]any{"value": "TRUE"}}}, true},
		{map[string]any{"term": map[string]any{"n": map[string]any{"value": "5"}}}, true},
		{map[string]any{"prefix": map[string]any{"s": map[string]any{"value": "Ab"}}}, true},
		{map[string]any{"range": map[string]any{"n": map[string]any{"lt": 6, "lte": 5, "gt": 4, "gte": 5}}}, true},
		{map[string]any{"range": map[string]any{"n": map[string]any{"lt": 5}}}, false},
		{map[string]any{"range": map[string]any{"n": map[string]any{"lt": "x"}}}, false},
		{map[string]any{"range": map[string]any{"s": map[string]any{"lt": 1}}}, false},
		{map[string]any{"range": map[string]any{"missing": map[string]any{"lt": 1}}}, false},
		{map[string]any{"regexp": map[string]any{"s": map[string]any{"value": "A.c"}}}, true},
		{map[string]any{"regexp": map[string]any{"list": map[string]any{"value": "y"}}}, true},
		{map[string]any{"regexp": map[string]any{"missing": map[string]any{"value": "y"}}}, false},
		{map[string]any{"bool": map[string]any{"should": []any{map[string]any{"match_all": map[string]any{}}}}}, true},
		{map[string]any{"bool": map[string]any{"must_not": []any{map[string]any{"match_all": map[string]any{}}}}}, false},
	} {
		got, err := evalDSL(c.q, doc)
		if err != nil || got != c.want {
			t.Errorf("%v = %v %v, want %v", c.q, got, err, c.want)
		}
	}
	for _, q := range []map[string]any{
		{},
		{"a": 1, "b": 2},
		{"fuzzy": map[string]any{}},
		{"term": map[string]any{"n": map[string]any{"value": "x"}}},
		{"wildcard": map[string]any{"n": map[string]any{"value": "5*"}}},
		{"regexp": map[string]any{"n": map[string]any{"value": "5"}}},
		{"regexp": map[string]any{"s": map[string]any{"value": "("}}},
		{"bool": map[string]any{"filter": []any{map[string]any{"fuzzy": 1}}}},
		{"bool": map[string]any{"must_not": []any{map[string]any{"fuzzy": 1}}}},
		{"bool": map[string]any{"should": []any{map[string]any{"fuzzy": 1}}}},
	} {
		if _, err := evalDSL(q, doc); err == nil {
			t.Errorf("%v evaluated", q)
		}
	}
}

// Regular expressions translate to Lucene's syntax, and what Lucene reads
// differently is refused.
func TestParseRegexLucene(t *testing.T) {
	for pattern, want := range map[string]string{
		`^a(b|c)$`:    `a([b-c])`,
		`^(ab|cd)$`:   `(ab|cd)`,
		`^(ab)+x?$`:   `(ab)+x?`,
		`^a{2,}b{3}$`: `a{2,}b{3}`,
		`^(?i)a$`:     `[Aa]`,
		`^.$`:         "[^\n]",
		`^(?s).$`:     `.`,
		`^(?:)$`:      `()`,
		`^(a|)$`:      `(a|())`,
	} {
		re, err := ParseRegex(pattern)
		if err != nil {
			t.Errorf("%s: %v", pattern, err)
			continue
		}
		if re.Lucene != want {
			t.Errorf("%s -> %q, want %q", pattern, re.Lucene, want)
		}
	}
	for _, bad := range []string{`(`, `a^b`, `(?m)^a`, `\bword`, `a$b`, `(a$)+`, `(\b)*`, `(\B){2}`, `x(?:\b|y)`} {
		if _, err := ParseRegex(bad); err == nil {
			t.Errorf("ParseRegex(%q) succeeded", bad)
		}
	}
}

// relativeDuration counts each unit of a relative time.
func TestRelativeDuration(t *testing.T) {
	for v, want := range map[string]time.Duration{
		"-90s": 90 * time.Second,
		"-2w":  14 * 24 * time.Hour,
		"-1q":  91 * 24 * time.Hour,
		"-mon": 30 * 24 * time.Hour,
	} {
		if got, ok := relativeDuration(v); !ok || got != want {
			t.Errorf("relativeDuration(%q) = %v %v", v, got, ok)
		}
	}
}
