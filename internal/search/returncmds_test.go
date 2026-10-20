// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"reflect"
	"testing"
)

func TestReturn(t *testing.T) {
	base := `| makeresults count=3 | streamstats count as n | eval src=case(n=1, "a", n=2, "b\"c", n=3, "d"), u=if(n=2, null(), "x")`
	cases := map[string]string{
		"return src":        `src="a"`,
		"return 2 ip=src":   `(ip="a") OR (ip="b\"c")`,
		"return 3 $src u":   `(a u="x") OR (b"c) OR (d u="x")`,
		"return nope":       ``,
		"return 2 nope, $u": `(x) OR (x)`,
	}
	for q, want := range cases {
		res := runSeq(t, base+" | "+q)
		if len(res.Rows) != 1 || res.Rows[0]["search"] != want {
			t.Errorf("%s: search = %v, want %s", q, res.Rows, want)
		}
	}
	res := runSeq(t, `| makeresults | eval m=split("p,q", ",") | return m`)
	if want := `( m="p" OR m="q" )`; res.Rows[0]["search"] != want {
		t.Errorf("multivalue = %v, want %s", res.Rows[0]["search"], want)
	}
	for _, bad := range []string{"return", "return 0 a", "return 10001 a", "return a=", "return (", "return 2"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestMakeContinuous(t *testing.T) {
	res := runSeq(t, `| makeresults count=3 | streamstats count as n | eval t=case(n=1, "2026-10-16T03:00:00Z", n=2, "2026-10-16T00:00:00Z", n=3, null()), c=n | makecontinuous t span=1h | table t c`)
	var got []any
	for _, r := range res.Rows {
		got = append(got, r["t"])
	}
	want := []any{"2026-10-16T00:00:00Z", "2026-10-16T01:00:00Z", "2026-10-16T02:00:00Z", "2026-10-16T03:00:00Z", nil}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("times = %v", got)
	}
	if res.Rows[1]["c"] != nil || res.Rows[4]["c"] != int64(3) {
		t.Errorf("rows = %v", res.Rows)
	}

	res = runSeq(t, `| makeresults count=2 | streamstats count as n | eval x=if(n=1, 5, 37) | makecontinuous x span=10 | table x`)
	got = got[:0]
	for _, r := range res.Rows {
		got = append(got, r["x"])
	}
	if want := []any{int64(5), int64(10), int64(20), int64(37)}; !reflect.DeepEqual(got, want) {
		t.Errorf("numbers = %v", got)
	}

	if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), `| makeresults count=2 | streamstats count as n | eval x=if(n=1, 0, 1000000000) | makecontinuous x span=1`); err == nil {
		t.Error("a billion new rows were allowed")
	}
	for _, bad := range []string{"makecontinuous", "makecontinuous x", "makecontinuous span=0", "makecontinuous span=1q", "makecontinuous a b span=1", "makecontinuous foo=1"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}
