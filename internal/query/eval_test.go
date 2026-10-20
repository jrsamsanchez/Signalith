// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"errors"
	"strings"
	"testing"
)

func TestParseEval(t *testing.T) {
	q := mustParse(t, `* | eval kb=round(bytes/1024, 2), who=lower(user) . "@" . domain, 'a b'=if(x > 1 AND NOT y = "z", -5, -(3))`)
	ev, ok := q.Commands[0].(*Eval)
	if !ok || len(ev.Assigns) != 3 {
		t.Fatalf("commands = %#v", q.Commands)
	}
	if ev.Assigns[2].Field != "a b" {
		t.Errorf("field = %q", ev.Assigns[2].Field)
	}
	want := "*\n| eval kb=round(bytes / 1024, 2), who=lower(user) . \"@\" . domain, 'a b'=if(x > 1 AND NOT y = \"z\", -5, -(3))"
	if got := q.String(); got != want {
		t.Errorf("String() =\n%s\nwant\n%s", got, want)
	}
}

func TestEvalPrecedence(t *testing.T) {
	for src, want := range map[string]string{
		`a + b * c`:                   `a + b * c`,
		`(a + b) * c`:                 `(a + b) * c`,
		`a - (b - c)`:                 `a - (b - c)`,
		`a - b - c`:                   `a - b - c`,
		`NOT a = 1 AND b OR c`:        `NOT a = 1 AND b OR c`,
		`NOT (a OR b)`:                `NOT (a OR b)`,
		`a OR b XOR c AND d`:          `a OR b XOR c AND d`,
		`(a OR b) AND c`:              `(a OR b) AND c`,
		`x like "a%"`:                 `x LIKE "a%"`,
		`- - a`:                       `--a`,
		`-(a+b)`:                      `-(a + b)`,
		`a == 1`:                      `a = 1`,
		`'my.field' . "x"`:            `'my.field' . "x"`,
		`'and' = 'x'`:                 `'and' = x`,
		`LOWER(User)`:                 `lower(User)`,
		`1.5e3 + .5`:                  `1.5e3 + 0.5`,
		`"x" .5`:                      `"x" . 5`, // after a value, . joins
		`case(a=1, "x", true(), "y")`: `case(a = 1, "x", true(), "y")`,
	} {
		e, err := ParseEvalExpr(src)
		if want == "" {
			if err == nil {
				t.Errorf("ParseEvalExpr(%q) = %s, want an error", src, e)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseEvalExpr(%q): %v", src, err)
			continue
		}
		if got := e.String(); got != want {
			t.Errorf("ParseEvalExpr(%q) prints %q, want %q", src, got, want)
		}
	}
}

func TestEvalErrors(t *testing.T) {
	for src, want := range map[string]string{
		`* | eval`:                 "eval needs an assignment",
		`* | eval x`:               `expected "="`,
		`* | eval x=`:              "expected a value",
		`* | eval x=nope(1)`:       `unknown function "nope"`,
		`* | eval x=if(1, 2)`:      "if() takes 3 arguments, got 2",
		`* | eval x=case(a, 1, b)`: "pairs",
		`* | eval x=round()`:       "round() takes 1 or 2 arguments",
		`* | eval x=1 y=2`:         "separate assignments with commas",
		`* | eval AND=1`:           "keyword",
		`* | eval x="open`:         "unterminated",
		`* | eval x=a # b`:         `unexpected "#"`,
		`* | eval x=3abc`:          "quote field names that start with a digit",
		`* | eval x=` + strings.Repeat("(", 200) + "1": "nests too deeply",
		`* | rex field=process`:                        "rex needs a quoted regular expression",
		`* | rex "(\w+)"`:                              "named group",
		`* | rex "(?<x>"`:                              "rex pattern",
		`* | rex mode=sed "s/a/b/x"`:                   "unknown flags",
		`* | rex bogus=1 "(?<x>.)"`:                    "unknown rex option",
		`* | dedup`:                                    "dedup needs at least one field",
		`* | dedup 0 user`:                             "at least 1 row",
		`* | dedup sortby -_time`:                      "needs a field before sortby",
		`* | dedup user keepempty=maybe`:               "expected true or false",
		`* | dedup user bogus=1`:                       "unknown dedup option",
		`* | where len(x) >`:                           "expected a value",
		`* | rare`:                                     "rare needs at least one field",
	} {
		_, err := Parse(src)
		var pe *Error
		if err == nil || !errors.As(err, &pe) {
			t.Errorf("Parse(%q) = %v, want an *Error", src, err)
			continue
		}
		if !strings.Contains(pe.Msg, want) {
			t.Errorf("Parse(%q) = %q, want it to mention %q", src, pe.Msg, want)
		}
		if pe.Pos < 0 || pe.Pos > len(src) {
			t.Errorf("Parse(%q) position %d is outside the query", src, pe.Pos)
		}
	}
}

func TestEvalErrorPositionsPointIntoTheExpression(t *testing.T) {
	src := `* | eval x=nope(1)`
	_, err := Parse(src)
	var pe *Error
	if !errors.As(err, &pe) || src[pe.Pos:pe.Pos+4] != "nope" {
		t.Fatalf("error %v does not point at nope", err)
	}
}

func TestWhereReadsPlainFiltersAsBefore(t *testing.T) {
	for _, src := range []string{
		`* | where count > 20 AND users >= 2`,
		`* | where user=adm* OR src IN (1, 2)`,
		`* | where name=O'Brien | head 2`,
		`* | where (a) = 1`, // prints as a=1, so reads as a=1
		`* | where NOT (x=1 OR y!=2)`,
	} {
		q := mustParse(t, src)
		w := q.Commands[0].(*Where)
		if _, isCond := w.Expr.(*Cond); isCond {
			t.Errorf("Parse(%q) read the where as an expression: %s", src, w.Expr)
		}
	}
}

func TestWhereExpressions(t *testing.T) {
	for src, want := range map[string]string{
		`* | where len(process) > 200`:                     `len(process) > 200`,
		`* | where bytes_out > bytes_in * 10`:              `bytes_out > bytes_in * 10`,
		`* | where like(user, "adm%") OR match(cmd, "-e")`: `like(user, "adm%") OR match(cmd, "-e")`,
		`* | where 'src ip' = dest`:                        `'src ip' = dest`,
		`* | where isnull(user)`:                           `isnull(user)`,
	} {
		q := mustParse(t, src)
		w := q.Commands[0].(*Where)
		c, ok := w.Expr.(*Cond)
		if !ok {
			t.Errorf("Parse(%q) = %#v, want a Cond", src, w.Expr)
			continue
		}
		if got := c.String(); got != want {
			t.Errorf("Parse(%q) prints %q, want %q", src, got, want)
		}
	}
}

func TestParseRexDedupFillnullRareEventstats(t *testing.T) {
	q := mustParse(t, `* | rex field=process max_match=0 "(?<flag>-\w+)" | dedup 2 user, host keepempty=true consecutive=true | fillnull value=none a, b | rare limit=5 process_name by host | eventstats avg(bytes) as ab by src | dedup 1 3 | fillnull`)
	rex := q.Commands[0].(*Rex)
	if rex.Field != "process" || rex.MaxMatch != 0 || rex.Pattern != `(?<flag>-\w+)` {
		t.Errorf("rex = %#v", rex)
	}
	d := q.Commands[1].(*Dedup)
	if d.N != 2 || len(d.Fields) != 2 || !d.KeepEmpty || !d.Consecutive {
		t.Errorf("dedup = %#v", d)
	}
	f := q.Commands[2].(*Fillnull)
	if f.Value != "none" || len(f.Fields) != 2 {
		t.Errorf("fillnull = %#v", f)
	}
	if top := q.Commands[3].(*Top); !top.Rare || top.Limit != 5 {
		t.Errorf("rare = %#v", top)
	}
	if es := q.Commands[4].(*EventStats); es.Aggs[0].Column() != "ab" || es.By[0] != "src" {
		t.Errorf("eventstats = %#v", es)
	}
	if d := q.Commands[5].(*Dedup); d.N != 1 || d.Fields[0] != "3" {
		t.Errorf("dedup 3 = %#v", d)
	}
	want := "*\n| rex field=process max_match=0 \"(?<flag>-\\\\w+)\"\n| dedup 2 user, host keepempty=true consecutive=true\n| fillnull value=none a, b\n| rare limit=5 process_name by host\n| eventstats avg(bytes) as ab by src\n| dedup 1 3\n| fillnull"
	if got := q.String(); got != want {
		t.Errorf("String() =\n%s\nwant\n%s", got, want)
	}
}

func TestEvalTextWithPipesInQuotes(t *testing.T) {
	q := mustParse(t, `* | eval x="a|b", 'y z'=1 | head 2`)
	if len(q.Commands) != 2 {
		t.Fatalf("commands = %#v", q.Commands)
	}
	if got := q.Commands[0].(*Eval).Assigns[0].Expr.(*Str).Value; got != "a|b" {
		t.Errorf("value = %q", got)
	}
}
