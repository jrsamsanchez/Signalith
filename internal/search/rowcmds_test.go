package search

import (
	"context"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestTranspose(t *testing.T) {
	res := runSeq(t, `| makeresults count=3 | streamstats count as n | eval host=case(n=1, "a", n=2, "b", n=3, "a"), e=null() | table host n e | transpose`)
	if want := []string{"column", "row 1", "row 2", "row 3"}; !reflect.DeepEqual(res.Columns, want) {
		t.Fatalf("columns = %v", res.Columns)
	}
	want := []Row{
		{"column": "host", "row 1": "a", "row 2": "b", "row 3": "a"},
		{"column": "n", "row 1": int64(1), "row 2": int64(2), "row 3": int64(3)},
		{"column": "e"},
	}
	if !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}

	// Header values name the columns; a repeated one falls back to the
	// row's number.
	res = runSeq(t, `| makeresults count=3 | streamstats count as n | eval host=case(n=1, "a", n=2, "row 1", n=3, "a"), e="" | table host n e | transpose 2 header_field=host column_name=field include_empty=false`)
	if want := []string{"field", "a", "row 1"}; !reflect.DeepEqual(res.Columns, want) {
		t.Errorf("columns = %v", res.Columns)
	}
	if want := []Row{{"field": "n", "a": int64(1), "row 1": int64(2)}}; !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}
	res = runSeq(t, `| makeresults count=3 | streamstats count as n | eval h="x" | table h n | transpose header_field=h`)
	if want := []string{"column", "x", "row 2", "row 3"}; !reflect.DeepEqual(res.Columns, want) {
		t.Errorf("columns with a repeated header = %v", res.Columns)
	}
	res = runSeq(t, `| makeresults count=2 | streamstats count as n | eval h=if(n=1, "row 2", "y") | table h n | transpose header_field=h`)
	if want := []string{"column", "row 2", "y"}; !reflect.DeepEqual(res.Columns, want) {
		t.Errorf("columns with a header named like a row = %v", res.Columns)
	}

	for _, bad := range []string{"transpose 0", "transpose 1001", "transpose x", "transpose 2 3", "transpose header_field=", "transpose include_empty=maybe", "transpose rows=2"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestFillDown(t *testing.T) {
	src := `| makeresults count=4 | streamstats count as n | eval a=case(n=1, "x", n=3, "y"), b_1=if(n=2, 5, null()), c=if(n=4, 1, null()) | table n a b_1 c`
	res := runSeq(t, src+` | filldown a b_*`)
	if got := seqColumn(res, "a"); !reflect.DeepEqual(got, []any{"x", "x", "y", "y"}) {
		t.Errorf("a = %v", got)
	}
	if got := seqColumn(res, "b_1"); !reflect.DeepEqual(got, []any{nil, int64(5), int64(5), int64(5)}) {
		t.Errorf("b_1 = %v", got)
	}
	if got := seqColumn(res, "c"); !reflect.DeepEqual(got, []any{nil, nil, nil, int64(1)}) {
		t.Errorf("c was filled: %v", got)
	}
	res = runSeq(t, src+` | filldown`)
	if got := seqColumn(res, "b_1"); !reflect.DeepEqual(got, []any{nil, int64(5), int64(5), int64(5)}) {
		t.Errorf("filldown of every field: b_1 = %v", got)
	}
	// A field no row has yet adds nothing.
	res = runSeq(t, src+` | filldown nothere`)
	for _, c := range res.Columns {
		if c == "nothere" {
			t.Errorf("columns = %v", res.Columns)
		}
	}
}

func TestTrendline(t *testing.T) {
	res := runSeq(t, `| makeresults count=6 | streamstats count as n | eval v=case(n=3, "x", true(), n*2) | trendline sma2(v) wma3(v) AS w ema2(v) AS e sma3(n) AS n`)
	num := func(f string) []any {
		out := seqColumn(res, f)
		for i, v := range out {
			if x, ok := evNum(v); ok {
				out[i] = math.Round(x*1000) / 1000
			}
		}
		return out
	}
	// v is 2, 4, x, 8, 10, 12: rows without a number get no average.
	checks := map[string][]any{
		"sma2(v)": {nil, 3.0, nil, 6.0, 9.0, 11.0},
		// (1*2 + 2*4 + 3*8)/6, (1*4 + 2*8 + 3*10)/6, (1*8 + 2*10 + 3*12)/6
		"w": {nil, nil, nil, 5.667, 8.333, 10.667},
		// Seeded with the first two's mean, 3; then alpha 2/3.
		"e": {nil, 3.0, nil, 6.333, 8.778, 10.926},
		// Written over its own field, it still averages the old values,
		// and rows before the window fills keep theirs.
		"n": {1.0, 2.0, 2.0, 3.0, 4.0, 5.0},
	}
	for f, want := range checks {
		if got := num(f); !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", f, got, want)
		}
	}
	for _, bad := range []string{"trendline", "trendline sma1(v)", "trendline sma10001(v)", "trendline sma05(v)", "trendline avg5(v)", "trendline sma5 v", "trendline sma5()", "trendline sma5(v) AS"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestAddInfo(t *testing.T) {
	before := float64(time.Now().Unix())
	res := runSeq(t, `| makeresults | addinfo`)
	r := res.Rows[0]
	now, _ := evNum(r[query.AddInfoSearchTime])
	minT, _ := evNum(r[query.AddInfoMinTime])
	maxT, _ := evNum(r[query.AddInfoMaxTime])
	if now < before || now > before+60 || minT != 0 || maxT < now-1 || maxT > now+1 {
		t.Errorf("no range: min %v max %v search %v", minT, maxT, now)
	}

	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":1},"hits":[{"_source":{"@timestamp":"2026-10-15T11:00:00Z","user":"a"}}]}}`}}
	res, err := (&Engine{Store: fs}).Run(context.Background(), `earliest=-24h latest=2026-10-16T00:00:00Z user=a | addinfo`)
	if err != nil {
		t.Fatal(err)
	}
	r = res.Rows[0]
	now, _ = evNum(r[query.AddInfoSearchTime])
	minT, _ = evNum(r[query.AddInfoMinTime])
	maxT, _ = evNum(r[query.AddInfoMaxTime])
	if math.Abs(now-minT-86400) > 1 || maxT != float64(time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC).Unix()) {
		t.Errorf("range: min %v max %v search %v", minT, maxT, now)
	}
	if !strings.Contains(strings.Join(res.Columns, ","), query.AddInfoMaxTime) {
		t.Errorf("columns = %v", res.Columns)
	}

	q, err := query.Parse("* | addinfo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RunCommands(context.Background(), []map[string]any{{"a": 1}}, q.Commands); err == nil {
		t.Error("addinfo ran without a search")
	}
}

func TestSearchTime(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 30, 0, 0, time.UTC)
	cases := map[string]time.Time{
		"-1h":                  now.Add(-time.Hour),
		"now-1d":               now.AddDate(0, 0, -1),
		"-1d@d":                time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC),
		"now":                  now,
		"2026-10-01T00:00:00Z": time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		"1760000000000":        time.UnixMilli(1760000000000).UTC(),
	}
	for in, want := range cases {
		if got, ok := searchTime(in, now); !ok || !got.Equal(want) {
			t.Errorf("searchTime(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "0", "soon"} {
		if _, ok := searchTime(in, now); ok {
			t.Errorf("searchTime(%q) has a time", in)
		}
	}
}
