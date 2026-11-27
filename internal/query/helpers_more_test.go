// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"testing"
	"time"
)

// A query writes lookups when outputlookup appears in it, in any of its
// subsearches, in an appendpipe or in the text of a map search.
func TestWritesLookups(t *testing.T) {
	for src, want := range map[string]bool{
		`* | outputlookup t`:                                   true,
		`* | join a [search b | outputlookup t]`:               true,
		`* | append [search b | outputlookup t]`:               true,
		`| union [search a] [search b | outputlookup t]`:       true,
		`| set union [search a] [search b | outputlookup t]`:   true,
		`| multisearch [search a] [search b | outputlookup t]`: true,
		`* | appendpipe [outputlookup t]`:                      true,
		`| map search="search a | OutputLookup t"`:             true,
		`* | appendpipe [stats count]`:                         false,
		`| map search="search a"`:                              false,
		`* | join a [search b]`:                                false,
		`* | append [search b]`:                                false,
		`| union [search a] [search b]`:                        false,
		`| set diff [search a] [search b]`:                     false,
		`| multisearch [search a] [search b]`:                  false,
		`* | stats count`:                                      false,
	} {
		q, err := Parse(src)
		if err != nil {
			t.Errorf("%s: %v", src, err)
			continue
		}
		if got := WritesLookups(q); got != want {
			t.Errorf("WritesLookups(%s) = %v, want %v", src, got, want)
		}
	}
}

// Each token kind has a name for messages.
func TestTokenKindNames(t *testing.T) {
	for k, want := range map[tokenKind]string{
		tokEOF:          "end of query",
		tokWord:         "word",
		tokString:       "quoted string",
		tokOp:           "operator",
		tokPipe:         "|",
		tokLParen:       "(",
		tokRParen:       ")",
		tokComma:        ",",
		tokRaw:          "expression",
		tokSubsearch:    "subsearch",
		tokenKind(1000): "?",
	} {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", k, got, want)
		}
	}
}

// WalkEval visits every node of an expression, parents first.
func TestWalkEval(t *testing.T) {
	e, err := ParseEvalExpr(`if(NOT a > 1, -b, lower("x"))`)
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	n := 0
	WalkEval(e, func(x EvalExpr) {
		n++
		if f, ok := x.(*Field); ok {
			fields = append(fields, f.Name)
		}
	})
	// if, NOT, >, a, 1, -, b, lower, "x"
	if n != 9 || len(fields) != 2 || fields[0] != "a" || fields[1] != "b" {
		t.Errorf("visited %d nodes, fields %v", n, fields)
	}
	WalkEval(nil, func(EvalExpr) { t.Error("nil expression visited") })
}

// A condition that would read back as a plain filter quotes its fields,
// inside calls and negations too.
func TestCondQuotesFields(t *testing.T) {
	c := &Cond{X: &Unary{Op: "NOT", X: &Binary{Op: "=", L: &Field{Name: "a"}, R: &Field{Name: "b"}}}}
	if got := c.String(); got != "NOT 'a' = 'b'" {
		t.Errorf("String() = %q", got)
	}
	q := quoteFields(&Call{Func: "lower", Args: []EvalExpr{&Field{Name: "u"}, &Str{Value: "x"}}})
	if got := q.String(); got != `lower('u', "x")` {
		t.Errorf("quoted call = %q", got)
	}
}

// Relative time modifiers move and snap a time in each unit.
func TestRelativeTimeUnits(t *testing.T) {
	base := time.Date(2026, 5, 14, 13, 45, 30, 500, time.UTC) // a Thursday
	for spec, want := range map[string]time.Time{
		"now":       base,
		"NOW":       base,
		"-30s":      base.Add(-30 * time.Second),
		"+5m":       base.Add(5 * time.Minute),
		"-2w":       base.AddDate(0, 0, -14),
		"-1y":       base.AddDate(-1, 0, 0),
		"@s":        base.Truncate(time.Second),
		"@m":        time.Date(2026, 5, 14, 13, 45, 0, 0, time.UTC),
		"@h":        time.Date(2026, 5, 14, 13, 0, 0, 0, time.UTC),
		"@y":        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		"@q":        time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		"@mon":      time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		"@w1":       time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC),
		"-1d@d+8h":  time.Date(2026, 5, 13, 8, 0, 0, 0, time.UTC),
		" -1qtr@q ": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		got, ok := RelativeTime(base, spec)
		if !ok || !got.Equal(want) {
			t.Errorf("RelativeTime(%q) = %v %v, want %v", spec, got, ok, want)
		}
	}
	for _, bad := range []string{"", "-1x", "@x", "-1000000d", "1d"} {
		if _, ok := RelativeTime(base, bad); ok {
			t.Errorf("RelativeTime(%q) succeeded", bad)
		}
	}
}

// Defaults stand in for names a command was not given.
func TestCommandDefaults(t *testing.T) {
	if got := (LookupField{Column: "c"}).Field(); got != "c" {
		t.Errorf("field = %q", got)
	}
	if got := (LookupField{Column: "c", As: "d"}).Field(); got != "d" {
		t.Errorf("field = %q", got)
	}
	if got := (&AddTotals{}).TotalLabel(); got != "Total" {
		t.Errorf("label = %q", got)
	}
	if got := (&AddTotals{Label: "Sum"}).TotalLabel(); got != "Sum" {
		t.Errorf("label = %q", got)
	}
	if got := (&Top{}).Other(); got != "OTHER" {
		t.Errorf("other = %q", got)
	}
	if got := (&Top{OtherStr: "rest"}).Other(); got != "rest" {
		t.Errorf("other = %q", got)
	}
	if got := (&Top{PercentField: "p"}).PercentColumn(); got != "p" {
		t.Errorf("percent = %q", got)
	}
}
