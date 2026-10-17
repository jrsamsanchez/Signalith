package search

import (
	"context"
	"reflect"
	"testing"
)

func TestConcurrency(t *testing.T) {
	// Starts 0, 5, 5, 20, 30 with durations 10, 3, 0, 15, 1.
	res := runSeq(t, `| makeresults count=5 | streamstats count as n | eval st=case(n=1, 0, n=2, 5, n=3, 5, n=4, 20, n=5, 30), d=case(n=1, 10, n=2, 3, n=3, 0, n=4, 15, n=5, 1) | concurrency duration=d start=st | table n concurrency`)
	want := []any{int64(1), int64(3), int64(3), int64(1), int64(2)}
	for i, r := range res.Rows {
		if r["concurrency"] != want[i] {
			t.Errorf("row %d concurrency = %v, want %v", i+1, r["concurrency"], want[i])
		}
	}

	// Rows without a duration or start get none; output= names the field.
	res = runSeq(t, `| makeresults count=2 | streamstats count as n | eval st=n, d=if(n=1, -1, "x") | concurrency duration=d start=st output=c`)
	for _, r := range res.Rows {
		if _, ok := r["c"]; ok {
			t.Errorf("row without a usable duration got %v", r["c"])
		}
	}

	for _, bad := range []string{"concurrency", "concurrency d", "concurrency duration=", "concurrency duration=d foo=x"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestContingency(t *testing.T) {
	q := `| makeresults count=6 | streamstats count as n | eval src=if(n<=4, "a", "b"), act=case(n<=3, "allow", n=4, "deny", n=5, "allow", n=6, "src") | contingency src act`
	res := runSeq(t, q)
	if want := []string{"src", "allow", "deny", "src_2", "TOTAL"}; !reflect.DeepEqual(res.Columns, want) {
		t.Fatalf("columns = %v", res.Columns)
	}
	want := []Row{
		{"src": "a", "allow": int64(3), "deny": int64(1), "src_2": int64(0), "TOTAL": int64(4)},
		{"src": "b", "allow": int64(1), "deny": int64(0), "src_2": int64(1), "TOTAL": int64(2)},
		{"src": "TOTAL", "allow": int64(4), "deny": int64(1), "src_2": int64(1), "TOTAL": int64(6)},
	}
	if !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}

	res = runSeq(t, q+` maxrows=1 maxcols=1 usetotal=false`)
	if !reflect.DeepEqual(res.Columns, []string{"src", "allow"}) || !reflect.DeepEqual(res.Rows, []Row{{"src": "a", "allow": int64(3)}}) {
		t.Errorf("limited table = %v %v", res.Columns, res.Rows)
	}
	res = runSeq(t, `| makeresults | eval a=split("x,y", ","), b="z" | ctable a b`)
	if len(res.Rows) != 3 || res.Rows[2]["TOTAL"] != int64(2) {
		t.Errorf("multivalue pairs = %v", res.Rows)
	}

	for _, bad := range []string{"contingency a", "contingency a b c", "contingency maxrows=0 a b", "contingency maxcols=1001 a b", "contingency totalstr= a b"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestFormat(t *testing.T) {
	res := runSeq(t, `| makeresults count=3 | streamstats count as n | eval user=case(n=1, "a", n=2, "b\"c", n=3, null()), h=if(n=2, split("x,y", ","), null()), _hidden=1 | table user h _hidden n | fields - n | format`)
	if want := `( ( user="a" ) OR ( user="b\"c" AND ( h="x" OR h="y" ) ) )`; len(res.Rows) != 1 || res.Rows[0]["search"] != want {
		t.Errorf("search = %v, want %s", res.Rows, want)
	}
	res = runSeq(t, `| makeresults count=3 | streamstats count as n | table n | format maxresults=2 "[" "{" "&&" "}" "||" "]"`)
	if want := `[ { n="1" } || { n="2" } ]`; res.Rows[0]["search"] != want {
		t.Errorf("custom parts = %v, want %s", res.Rows[0]["search"], want)
	}
	res = runSeq(t, `| makeresults | eval _x=1 | table _x | format`)
	if res.Rows[0]["search"] != "NOT ()" {
		t.Errorf("no fields = %v", res.Rows[0]["search"])
	}

	for _, bad := range []string{`format "("`, "format maxresults=-1", "format maxresults=10001", "format foo", "format mvsep="} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}
