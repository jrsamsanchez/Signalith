// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

const winEvent = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><Computer>dc1</Computer></System>` +
	`<EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">10.0.0.5</Data><Data Name="TargetUserName">bob</Data></EventData></Event>`

func TestXPath(t *testing.T) {
	cases := []struct {
		path string
		want any
	}{
		{"//EventID", "4625"},
		{"/Event/System/Computer", "dc1"},
		{"//Data[@Name='TargetUserName']", []any{"alice", "bob"}},
		{`//Data[@Name="TargetUserName"][2]`, "bob"},
		{"//Data[2]/@Name", "IpAddress"},
		{"/Event/*/Data[1]/text()", "alice"},
		{"//System", "4625dc1"},
		{"//Nothing", nil},
	}
	for _, tc := range cases {
		res := &Result{Rows: []Row{{RawField: winEvent}, {RawField: "not xml"}}}
		if err := applyXPath(context.Background(), res, &query.XPath{Path: tc.path, Field: RawField, OutField: "x"}); err != nil {
			t.Fatal(err)
		}
		if got := res.Rows[0]["x"]; !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s = %#v, want %#v", tc.path, got, tc.want)
		}
		if _, ok := res.Rows[1]["x"]; ok {
			t.Errorf("%s wrote x on a row without XML", tc.path)
		}
	}
	res := &Result{Rows: []Row{{RawField: "<a><b>1</b></a>"}, {}}}
	if err := applyXPath(context.Background(), res, &query.XPath{Path: "//c", Field: RawField, OutField: "x", Default: "none", HasDefault: true}); err != nil {
		t.Fatal(err)
	}
	if res.Rows[0]["x"] != "none" || res.Rows[1]["x"] != "none" {
		t.Errorf("default = %v", res.Rows)
	}
	// Too many elements, too deep and unknown entities read as no match.
	for _, s := range []string{strings.Repeat("<a></a>", maxXMLNodes+1), strings.Repeat("<a>", maxXMLDepth+1), `<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>`} {
		res := &Result{Rows: []Row{{RawField: s}}}
		if err := applyXPath(context.Background(), res, &query.XPath{Path: "//a", Field: RawField, OutField: "x"}); err != nil {
			t.Fatal(err)
		}
		if v, _ := res.Rows[0]["x"].(string); strings.Contains(v, "x") && !strings.Contains(v, "&e;") {
			t.Errorf("entity expanded: %q", v)
		}
	}
	for _, bad := range []string{"", "//", "/a/", "a//text()", "/a[@b]", "/a[0]", "/@x/b", "/a[x='1']", "/a[@b='1]"} {
		if _, err := query.CompileXPath(bad); err == nil {
			t.Errorf("%q compiled", bad)
		}
	}
}

func TestAbstract(t *testing.T) {
	raw := "one\ntwo words here\nthree\nfour five six seven\nx"
	res := &Result{Rows: []Row{{RawField: raw}, {RawField: "short"}}}
	if err := applyAbstract(context.Background(), res, &query.Abstract{MaxTerms: 1000, MaxLines: 2}); err != nil {
		t.Fatal(err)
	}
	if got := res.Rows[0][RawField]; got != "...two words here\n...four five six seven" {
		t.Errorf("abstract = %q", got)
	}
	if res.Rows[1][RawField] != "short" {
		t.Errorf("short = %q", res.Rows[1][RawField])
	}
}
