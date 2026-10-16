package search

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func runSeq(t *testing.T, src string) *Result {
	t.Helper()
	res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), src)
	if err != nil {
		t.Fatalf("%s: %v", src, err)
	}
	return res
}

func seqColumn(res *Result, f string) []any {
	out := make([]any, 0, len(res.Rows))
	for _, r := range res.Rows {
		out = append(out, r[f])
	}
	return out
}

const fiveRows = `| makeresults count=5 | streamstats count as n | eval v=case(n=1, 10, n=2, 15, n=3, "x", n=4, 12, n=5, 20)`

func TestAccumDeltaAutoRegress(t *testing.T) {
	res := runSeq(t, fiveRows+` | accum v AS total | delta v | delta v AS d2 p=2 | autoregress v p=1-2 | autoregress n AS n`)
	checks := map[string][]any{
		"total":    {int64(10), int64(25), nil, int64(37), int64(57)},
		"delta(v)": {nil, int64(5), nil, int64(-3), int64(8)},
		"d2":       {nil, nil, nil, int64(2), int64(5)},
		"v_p1":     {nil, int64(10), int64(15), "x", int64(12)},
		"v_p2":     {nil, nil, int64(10), int64(15), "x"},
		// AS onto the field itself copies the old values.
		"n": {int64(1), int64(1), int64(2), int64(3), int64(4)},
	}
	for f, want := range checks {
		if got := seqColumn(res, f); !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", f, got, want)
		}
	}
	res = runSeq(t, fiveRows+` | accum v`)
	if got := seqColumn(res, "v"); !reflect.DeepEqual(got, []any{int64(10), int64(25), "x", int64(37), int64(57)}) {
		t.Errorf("accum in place = %v", got)
	}
	for _, bad := range []string{"accum", "delta v p=0", "delta v p=10001", "autoregress v p=3-1", "autoregress v p=1-101", "autoregress v AS x p=1-2", "accum v AS", "delta v q=1"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestFieldSummary(t *testing.T) {
	res := runSeq(t, fiveRows+` | eval u=if(n<3, "amy", "bob"), m=split("a,b", ",") | fields - _time | fieldsummary maxvals=1`)
	byField := map[any]Row{}
	for _, r := range res.Rows {
		byField[r["field"]] = r
	}
	v := byField["v"]
	if v["count"] != int64(5) || v["numeric_count"] != int64(4) || v["min"] != int64(10) || v["max"] != int64(20) || v["mean"] != 14.25 || v["distinct_count"] != int64(5) || v["is_exact"] != int64(1) {
		t.Errorf("v = %v", v)
	}
	if u := byField["u"]; u["values"] != `[{"value":"bob","count":3}]` || u["min"] != nil || u["numeric_count"] != int64(0) {
		t.Errorf("u = %v", u)
	}
	if m := byField["m"]; m["count"] != int64(5) || m["distinct_count"] != int64(2) {
		t.Errorf("m = %v", m)
	}
	res = runSeq(t, fiveRows+` | fieldsummary v`)
	if len(res.Rows) != 1 || res.Rows[0]["field"] != "v" {
		t.Errorf("named = %v", res.Rows)
	}
}

func TestFieldPatternsTriedOncePerName(t *testing.T) {
	rows := make([]Row, 5000)
	for i := range rows {
		r := Row{}
		for f := 0; f < 50; f++ {
			r[fmt.Sprintf("field_a_a_a_a_%d", f)] = int64(i)
		}
		rows[i] = r
	}
	var pats []string
	for i := 0; i < query.MaxFieldSummaryFields; i++ {
		pats = append(pats, fmt.Sprintf("*a*a*a*a*q%d", i))
	}
	q, err := query.Parse("* | fieldsummary " + strings.Join(pats, " "))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	ctx := withEvaluator(context.Background())
	if err := applyFieldSummary(ctx, &Result{Rows: rows}, q.Commands[0].(*query.FieldSummary)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v", d)
	}
	if _, err := query.Parse("* | fieldsummary " + strings.Join(append(pats, "x"), " ")); err == nil {
		t.Error("101 patterns accepted")
	}
	for _, src := range []string{"* | fields - " + strings.Join(pats, ", "), "* | replace a WITH b IN " + strings.Join(pats, ", "), "* | addtotals " + strings.Join(pats, " ")} {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatalf("%s: %v", src[:30], err)
		}
		start := time.Now()
		if err := applyCommand(withEvaluator(context.Background()), &Result{Rows: rows}, q.Commands[0]); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%s took %v", q.Commands[0].Name(), d)
		}
	}
}
