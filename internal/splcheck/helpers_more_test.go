// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// A field holds one value when the stages before a lookup make it so: a
// stats groups by it or counts it, an eval makes it with a function of
// one value, a rex extracts it once, or a raw search's own field.
func TestFieldSingle(t *testing.T) {
	for _, c := range []struct {
		f      string
		stages []string
		raw    bool
		want   bool
	}{
		{"user", []string{"stats count by user"}, false, true},
		{"count", []string{"stats count by user"}, false, true},
		{"v", []string{"stats values(x) as v by user"}, false, false},
		{"other", []string{"stats count by user"}, false, false},
		{"c", []string{"eventstats count as c"}, true, false},
		{"u", []string{"eventstats count as c"}, true, true},
		{"u", []string{"eval u=lower(x)"}, true, true},
		{"u", []string{"eval u=lower(x)"}, false, false},
		{"u", []string{"eval u=\"x\""}, false, true},
		{"u", []string{"eval u=1"}, false, true},
		{"u", []string{"eval u=mvjoin(x, \",\")"}, false, true},
		{"u", []string{"eval u=mvcount(x)"}, false, true},
		{"u", []string{"eval u=mvindex(x, 0)"}, false, true},
		{"u", []string{"eval u=mvindex(x, 0, 1)"}, false, false},
		{"u", []string{"eval u=a . b"}, false, true},
		{"u", []string{"eval u=a + b"}, true, true},
		{"u", []string{"eval u=split(a, \",\")"}, true, false},
		{"u", []string{"eval u=-a"}, true, false},
		{"u", []string{"stats count by a", "rename a as u"}, false, true},
		{"u", []string{"rex field=x \"(?<u>\\d+)\""}, false, true},
		{"u", []string{"rex field=x max_match=0 \"(?<u>\\d+)\""}, false, false},
		{"u", []string{"lookup t k OUTPUT u"}, true, false},
		{"u", []string{"lookup t k OUTPUT v"}, true, true},
		{"u", []string{"makemv delim=\",\" u"}, true, false},
		{"u", []string{"mvexpand u"}, false, true},
		{"u", []string{"fillnull value=0 u", "where u>1", "table u", "dedup u", "sort u", "head 5"}, true, true},
		{"u", []string{"transaction x"}, true, false},
		{"u", []string{"eval u=("}, true, false},
	} {
		if got := fieldSingle(c.f, c.stages, c.raw); got != c.want {
			t.Errorf("fieldSingle(%s, %q, %v) = %v", c.f, c.stages, c.raw, got)
		}
	}
}

// walkMulti names a multivalue field an expression reads, but not one it
// only tests for.
func TestWalkMulti(t *testing.T) {
	for src, want := range map[string][]string{
		`lower(m) . k`:              {"m"},
		`isnull(m) OR isnotnull(n)`: nil,
		`-m + if(isnull(n), 1, n)`:  {"m", "n"},
		`NOT m`:                     {"m"},
		`"x"`:                       nil,
	} {
		e, err := query.ParseEvalExpr(src)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		walkMulti(e, []string{"m", "n"}, false, func(f string) { got = append(got, f) })
		if !slices.Equal(got, want) {
			t.Errorf("walkMulti(%s) = %v, want %v", src, got, want)
		}
	}
}

// A place's value is the field's, a piece of it split, or a rex group of
// it.
func TestPlaceValue(t *testing.T) {
	own := func(f string) string {
		return map[string]string{"a": "x,y,z", "b": "id=42"}[f]
	}
	for _, c := range []struct {
		p    place
		want string
		ok   bool
	}{
		{place{base: "a"}, "x,y,z", true},
		{place{base: "a", steps: []step{{kind: 's', arg: ",", group: "1"}}}, "y", true},
		{place{base: "a", steps: []step{{kind: 's', arg: ",", group: "-1"}}}, "z", true},
		{place{base: "a", steps: []step{{kind: 's', arg: ",", group: "5"}}}, "", false},
		{place{base: "a", steps: []step{{kind: 's', arg: ",", group: "x"}}}, "", false},
		{place{base: "b", steps: []step{{kind: 'r', arg: `id=(?<n>\d+)`, group: "n"}}}, "42", true},
		{place{base: "b", steps: []step{{kind: 'r', arg: `id=(?<n>\d+)`, group: "m"}}}, "", false},
		{place{base: "b", steps: []step{{kind: 'r', arg: `(`, group: "n"}}}, "", false},
		{place{base: "b", steps: []step{{kind: 'j', arg: "k"}}}, "", false},
		{place{base: "none", steps: []step{{kind: 'j', arg: "k"}}}, "", false},
	} {
		got, ok := placeValue(c.p, own)
		if got != c.want || ok != c.ok {
			t.Errorf("placeValue(%+v) = %q %v, want %q %v", c.p, got, ok, c.want, c.ok)
		}
	}
}

// An eval's if() or case() is read as its test and the value it gives,
// except where it gives nothing.
func TestCondOf(t *testing.T) {
	for expr, want := range map[string]evalCond{
		`if(a="x", "1", "0")`:    {`a="x"`, "1"},
		`case(a="x", 'y')`:       {`a="x"`, "y"},
		`if(a="x", "1")`:         {},
		`case(a)`:                {},
		`case(true(), "1")`:      {},
		`if(a="x", null(), "0")`: {},
	} {
		got, ok := condOf(expr)
		if got != want || ok != (want != evalCond{}) {
			t.Errorf("condOf(%s) = %+v %v", expr, got, ok)
		}
	}
}

// A side of a comparison is a field's place, a piece of one split, or
// not a field at all.
func TestSidePlace(t *testing.T) {
	resolve := func(s string) place { return place{base: s} }
	if p, fold, ok := sidePlace("lower(user)", resolve); !ok || !fold || p.base != "user" {
		t.Errorf("lower(user) = %+v %v %v", p, fold, ok)
	}
	if p, _, ok := sidePlace(`mvindex(split(user, "@"), 0)`, resolve); !ok || p.base != "user" || len(p.steps) != 1 || p.steps[0].kind != 's' || p.steps[0].arg != "@" {
		t.Errorf("split piece = %+v %v", p, ok)
	}
	for _, w := range []string{"AND", "null", "'true'", "in"} {
		if _, _, ok := sidePlace(w, resolve); ok {
			t.Errorf("%s is a field", w)
		}
	}
	if !isWordByte('a') || !isWordByte('_') || !isWordByte('9') || isWordByte('-') {
		t.Error("isWordByte")
	}
	for _, e := range []Expr{&And{}, &Or{}, &Not{}, &Cmp{}} {
		e.isExpr()
	}
}

// A transaction's later filter keeps only short transactions when it
// tests duration below a bound, or a field set only for short ones.
func TestTransactionShortTests(t *testing.T) {
	ts := &txnStages{single: map[string]bool{"user": true}, short: map[string]shortField{"quick": {value: "TRUE", span: 5 * time.Minute}}}
	for src, want := range map[string]time.Duration{
		`duration<300`: 300 * time.Second,
		`quick=TRUE`:   5 * time.Minute,
		`quick=true`:   5 * time.Minute,
		`duration>300`: 0,
		`quick=TRU*`:   0,
	} {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := ts.shortTest(q.Search, true)
		if got != want || ok != (want != 0) {
			t.Errorf("shortTest(%s) = %v %v", src, got, ok)
		}
	}
	for src, want := range map[string]time.Duration{
		`where duration <= 60`:         time.Minute,
		`where quick == "TRUE"`:        5 * time.Minute,
		`where duration < x`:           0,
		`where len(x) < 5`:             0,
		`where duration < 0`:           0,
		`where duration < 10000000000`: 0,
	} {
		q, err := query.Parse("* | " + src)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := ts.shortTest(q.Commands[0].(*query.Where).Expr, false)
		if got != want || ok != (want != 0) {
			t.Errorf("shortTest(%s) = %v %v", src, got, ok)
		}
	}
	for src, want := range map[string]bool{
		`case(duration<300, "TRUE")`:   true,
		`case(duration>300, "TRUE")`:   false,
		`case(other<300, "TRUE")`:      false,
		`case(duration<300, 1)`:        false,
		`case(true(), "TRUE")`:         false,
		`if(duration<300, "TRUE", "")`: false,
		`"x"`:                          false,
	} {
		e, err := query.ParseEvalExpr(src)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := shortCase(e); ok != want {
			t.Errorf("shortCase(%s) = %v", src, ok)
		}
	}
	for src, want := range map[string]string{
		`user=a`:             "",
		`user=a OR (host=b)`: "host",
		`NOT user IN (a, b)`: "",
		`host IN (a, b)`:     "host",
		`foo`:                "_raw",
		`user=a host=b`:      "host",
	} {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		if got := ts.multiFilter(q.Search); got != want {
			t.Errorf("multiFilter(%s) = %q, want %q", src, got, want)
		}
	}
}

// Small helpers: spans print in hours or minutes, and the first error
// wins.
func TestSpanAndErrHelpers(t *testing.T) {
	if got := formatSpan(2 * time.Hour); got != "2h" {
		t.Errorf("formatSpan = %q", got)
	}
	if got := formatSpan(90 * time.Minute); got != "90m" {
		t.Errorf("formatSpan = %q", got)
	}
	a, b := errors.New("a"), errors.New("b")
	if firstErr(a, b) != a || firstErr(nil, b) != b || firstErr(nil, nil) != nil {
		t.Error("firstErr")
	}
}

// Other events like a rule's: a program in another folder, at the end of
// the folder the rule names, a side-loaded library, a write to a share.
func TestVariants(t *testing.T) {
	got := variants("ImageLoad", map[string]string{"process_name": "app.exe"})
	if len(got) == 0 || got[0]["loaded_file_path"] == "" || !strings.HasSuffix(got[0]["process_path"], `\app.exe`) {
		t.Errorf("image load variants = %v", got)
	}
	got = variants("ShareAccess", map[string]string{})
	if len(got) != 1 || got[0]["access_mask"] != "0x2" {
		t.Errorf("share variants = %v", got)
	}
	got = variants("Processes", map[string]string{"process_name": "a.exe", "process_path": `C:\Tools\`})
	if len(got) != 1 || got[0]["process_path"] != `C:\Tools\a.exe` {
		t.Errorf("path variants = %v", got)
	}
	got = variants("Processes", map[string]string{"parent_process_name": "p.exe"})
	if len(got) != len(imageDirs) {
		t.Errorf("parent variants = %v", got)
	}
	if got := variants("Processes", map[string]string{"process_name": "a.exe", "process_path": `C:\x\a.exe`}); len(got) != 0 {
		t.Errorf("variants of a full path = %v", got)
	}
}

// With no test events, the reason names where the rule's events come
// from.
func TestNoEventsReasonSources(t *testing.T) {
	for node, want := range map[string]string{
		SensorDNSNode:  "network sensor",
		AuditdNode:     "Linux audit",
		CloudTrailNode: "CloudTrail",
		AzureNode:      "Entra ID or Azure",
		O365Node:       "Microsoft 365",
		OktaAuthNode:   "Okta",
		KubernetesNode: "Kubernetes audit",
		GitHubNode:     "GitHub audit",
		"Web":          "web access log",
		"Processes":    "Windows",
	} {
		got := NoEventsReason(&Rule{Node: node}, nil)
		if got != "no test events: no "+want+" event as Signalith stores it matches the rule" {
			t.Errorf("%s: %q", node, got)
		}
	}
}
