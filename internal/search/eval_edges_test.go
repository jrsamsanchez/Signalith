// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// Eval functions with no value to give leave the field out, filters over
// multivalues read the one field they name, and bad patterns in later
// commands are refused with why.
func TestEvalEdgeRows(t *testing.T) {
	for _, c := range []struct{ src, rows, err string }{
		{`| makeresults | eval r=log(8, 3)`, `[]search.Row{search.Row{"r":1.8927892607143724}}`, ``},
		{`| makeresults | eval x=split("1,2,3", ","), r=mvfilter(-x < -1)`, `[]search.Row{search.Row{"r":[]interface {}{"2", "3"}, "x":[]interface {}{"1", "2", "3"}}}`, ``},
		{`| makeresults | eval x=split("a,b", ","), r=mvfilter(NOT x="a")`, `[]search.Row{search.Row{"r":"b", "x":[]interface {}{"a", "b"}}}`, ``},
		{`| makeresults | eval r=1e999`, `[]search.Row{search.Row{}}`, ``},
		{`| makeresults | eval r=case(1=2, "a")`, `[]search.Row{search.Row{}}`, ``},
		{`| makeresults | eval r=coalesce(nosuch, null())`, `[]search.Row{search.Row{}}`, ``},
		{`| makeresults | eval r=5 % 0`, `[]search.Row{search.Row{}}`, ``},
		{`| makeresults | eval r=mvfilter(1 > 0)`, ``, `mvfilter's expression must use exactly one field`},
		{`| makeresults | eval r=mvmap(1, 2)`, ``, `mvmap's first argument must be a field`},
		{`| makeresults | eval x="a b" | makemv tokenizer="(" x`, ``, `makemv tokenizer: error parsing regexp`},
		{`| makeresults | eval x="a" | rex field=x mode=sed "s/(/b/"`, ``, `rex sed expression: error parsing regexp`},
		{`| makeresults | eval x="(" | regex x="("`, ``, `regex pattern: error parsing regexp`},
		{`| makeresults | eval a="x" | map search="| makeresults | head $a$"`, ``, `map's search: expected a positive number, got "x"`},
		{`| makeresults | eval a=1 | map search="| makeresults | eval b=2 | where b=$a$ OR b=2"`, `[]search.Row{search.Row{"b":2}}`, ``},
		{`| makeresults | eval a=1 | map search="| makeresults | eval b=2 | where b=$a$"`, `[]search.Row(nil)`, ``},
		{`| makeresults count=2 | streamstats count as n | eval x=if(n=1, split("1,2", ","), split("1,2", ",")) | dedup x`, `[]search.Row{search.Row{"n":1, "x":[]interface {}{"1", "2"}}}`, ``},
		{`| makeresults count=2 | streamstats count as n | eval x=if(n=1, split("1,2", ","), split("1,3", ",")) | dedup x`, `[]search.Row{search.Row{"n":1, "x":[]interface {}{"1", "2"}}, search.Row{"n":2, "x":[]interface {}{"1", "3"}}}`, ``},
		{`| makeresults count=2 | streamstats count as n | eval x=if(n=1, split("1,2", ","), split("1,2,3", ",")) | dedup x`, `[]search.Row{search.Row{"n":1, "x":[]interface {}{"1", "2"}}, search.Row{"n":2, "x":[]interface {}{"1", "2", "3"}}}`, ``},
		{`| makeresults count=2 | streamstats count as n | eval x=if(n=1, split("a,b", ","), "a") | dedup x`, `[]search.Row{search.Row{"n":1, "x":[]interface {}{"a", "b"}}, search.Row{"n":2, "x":"a"}}`, ``},
		{`| makeresults count=3 | streamstats count as n | eval x=if(n=1, "abc", if(n=2, 5, "abd")) | sort x`, `[]search.Row{search.Row{"n":2, "x":5}, search.Row{"n":1, "x":"abc"}, search.Row{"n":3, "x":"abd"}}`, ``},
		{`| makeresults count=2 | streamstats count as n | eval x=if(n=1, 9223372036854775807, 5) | stats sum(x)`, `[]search.Row{search.Row{"sum(x)":9.223372036854776e+18}}`, ``},
		{`| makeresults | eval x=split("a,b", ","), y=split("c,d", ",") | stats count by x y`, `[]search.Row{search.Row{"count":1, "x":"a", "y":"c"}, search.Row{"count":1, "x":"a", "y":"d"}, search.Row{"count":1, "x":"b", "y":"c"}, search.Row{"count":1, "x":"b", "y":"d"}}`, ``},
		{`| makeresults count=2 | streamstats count as n | eval y=if(n=1, "a", null()) | chart count over n by y`, `[]search.Row{search.Row{"a":1, "n":1}}`, ``},
		{`| makeresults | eval x="{\"a\":{\"b\":true,\"c\":false}}" | spath input=x`, `[]search.Row{search.Row{"a.b":"true", "a.c":"false", "x":"{\"a\":{\"b\":true,\"c\":false}}"}}`, ``},
	} {
		res, err := (&Engine{Store: &fakeStore{responses: []string{`{"hits":{"total":{"value":0},"hits":[]}}`}}}).Run(context.Background(), c.src)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err = %v, want %q", c.src, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.src, err)
			continue
		}
		for _, r := range res.Rows {
			delete(r, "_time")
		}
		if got := fmt.Sprintf("%#v", res.Rows); got != c.rows {
			t.Errorf("%s:\n got %s\nwant %s", c.src, got, c.rows)
		}
	}
}
