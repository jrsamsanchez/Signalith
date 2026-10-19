// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// The functions' answers at their edges: missing or wrong arguments give
// null (or false for a test), as in Splunk.
func TestEvalFunctionEdges(t *testing.T) {
	r := Row{
		"n": int64(8), "s": " padded ", "mv": []any{"a", "b"}, "word": "hello", "ip": "10.1.2.3",
		"ips": []any{"192.0.2.1", "10.9.9.9"}, "pct": "a%20b", "bad": "%zz", "neg": -1234567.891,
	}
	for src, want := range map[string]any{
		`sqrt(16)`:                        int64(4),
		`exp(0)`:                          int64(1),
		`ln(1)`:                           int64(0),
		`sqrt("x")`:                       nil,
		`log(8, 2)`:                       int64(3),
		`log(100)`:                        int64(2),
		`log(8, "x")`:                     nil,
		`round(2.5, "x")`:                 nil,
		`max(3, "10", 2)`:                 "10",
		`min(3, 1, 2)`:                    int64(1),
		`trim(s)`:                         "padded",
		`ltrim(s)`:                        "padded ",
		`rtrim(s)`:                        " padded",
		`trim(word, "ho")`:                "ell",
		`trim(nothing)`:                   nil,
		`trim(word, nothing)`:             nil,
		`substr(word, 0, 2)`:              "he",
		`substr(word, -3)`:                "llo",
		`split(word, nothing)`:            nil,
		`mvfind(mv, "b")`:                 int64(1),
		`mvfind(mv, "z")`:                 nil,
		`mvfind(nothing, "b")`:            nil,
		`mvzip(mv, nothing)`:              nil,
		`mvzip(mv, mv, "-")`:              []any{"a-a", "b-b"},
		`mvzip(mv, mv, nothing)`:          nil,
		`match(nothing, "x")`:             false,
		`match(word, "^h")`:               true,
		`cidrmatch(nothing, ip)`:          false,
		`cidrmatch("nope", ip)`:           false,
		`cidrmatch("10.0.0.0/8", ip)`:     true,
		`cidrmatch("10.0.0.0/8", ips)`:    true,
		`cidrmatch("172.16.0.0/12", ips)`: false,
		`in(nothing, "a")`:                false,
		`in(mv, "b", "c")`:                true,
		`typeof("x")`:                     "String",
		`typeof(1 == 1)`:                  "Boolean",
		`typeof(mv)`:                      "Multivalue",
		`typeof(nothing)`:                 "Invalid",
		`typeof(n)`:                       "Number",
		`nullif(word, "hello")`:           nil,
		`nullif(word, "x")`:               "hello",
		`tonumber("ff", 16)`:              int64(255),
		`tonumber("ff", 40)`:              nil,
		`tonumber("ff", 2.5)`:             nil,
		`tostring(90061, "duration")`:     "1+01:01:01",
		`tostring(neg, "commas")`:         "-1,234,567.89",
		`tostring(mv)`:                    "a\nb",
		`urldecode(pct)`:                  "a b",
		`urldecode(bad)`:                  "%zz",
		`urldecode(nothing)`:              nil,
		`md5("a")`:                        "0cc175b9c0f1b6a831c399e269772661",
		`sha1("a")`:                       "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
		`n % 3`:                           int64(2),
		`n % 0`:                           nil,
		`n / 0`:                           nil,
		`-"x"`:                            nil,
		`like(nothing, "a%")`:             false,
		`like(mv, "b%")`:                  true,
		`like(word, nothing)`:             false,
	} {
		e, err := query.ParseEvalExpr(src)
		if err != nil {
			t.Errorf("parse %s: %v", src, err)
			continue
		}
		ev := newEvaluator(context.Background())
		got := ev.eval(e, r)
		if ev.err != nil {
			t.Errorf("%s: %v", src, ev.err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", src, got, want)
		}
	}
	// An unknown function is an error.
	ev := newEvaluator(context.Background())
	ev.eval(&query.Call{Func: "nosuchfunction"}, r)
	if err := ev.err; err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("unknown function: %v", err)
	}
	// So is a pattern past the length limit.
	ev = newEvaluator(context.Background())
	long := strings.Repeat("a", maxPatternLen+1)
	if err := evalErr(t, ev, `match(word, "`+long+`")`, r); err == nil || !strings.Contains(err.Error(), "characters long") {
		t.Errorf("long pattern: %v", err)
	}
	// now() and time() are the evaluator's clock.
	ev = newEvaluator(context.Background())
	ev.now = time.Unix(1_700_000_000, 500_000_000)
	if got := ev.eval(mustEval(t, "now()"), r); got != int64(1_700_000_000) {
		t.Errorf("now() = %#v", got)
	}
	if got := ev.eval(mustEval(t, "time()"), r); got != 1_700_000_000.5 {
		t.Errorf("time() = %#v", got)
	}
}

// A canceled search stops an eval, rex, dedup and eventstats.
func TestCommandsStopWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rows := func() *Result { return &Result{Rows: []Row{{"a": "x1", "b": int64(1)}, {"a": "x2", "b": int64(2)}}} }
	for _, src := range []string{
		`* | rex field=a "x(?<n>\d)"`,
		`* | dedup a`,
		`* | eventstats count by a`,
	} {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := applyCommand(ctx, rows(), q.Commands[0]); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: err = %v", src, err)
		}
	}
	// A bad rex pattern is the query's error.
	err := applyCommand(context.Background(), rows(), &query.Rex{Field: "a", Pattern: "("})
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(qe.Msg, "rex pattern") {
		t.Errorf("bad rex: %v", err)
	}
	if evaluatorFor(nil) == nil {
		t.Error("no evaluator outside a search")
	}
}
