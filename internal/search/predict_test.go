package search

import (
	"context"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

const setSub = `{"hits":{"total":{"value":2},"hits":[
	{"_source":{"@timestamp":"2026-10-15T10:30:00Z","user":"bob"}},
	{"_source":{"@timestamp":"2026-10-15T07:00:00Z","user":"dan"}},
	{"_source":{"@timestamp":"2026-10-15T06:00:00Z","user":"dan"}}]}}`

func TestSet(t *testing.T) {
	for op, want := range map[string][]string{
		"union":     {"amy", "bob", "cat", "<nil>", "dan"},
		"diff":      {"amy", "cat", "<nil>", "dan"},
		"intersect": {"bob"},
	} {
		e, fs := joinEngine(joinMain, setSub)
		got := runRows(t, e, `| set `+op+` [search earliest=-7d | table user] [search datamodel=Change | table user]`, "user")
		if !reflect.DeepEqual(got, want) {
			t.Errorf("set %s:\n got %v\nwant %v", op, got, want)
		}
		if len(fs.bodies) != 2 || !strings.Contains(asJSON(fs.bodies[0]), `"gte":"now-7d"`) {
			t.Errorf("searches = %v", fs.bodies)
		}
	}
	for _, bad := range []string{"| set diff [search a]", "| set diff [a] [b] [c]", "index=x | set union [search a] [search b]", "| set", "| set both [a] [b]", "| set diff [a] [b] x"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestSetFields(t *testing.T) {
	got := runRows(t, &Engine{}, `| makeresults count=2 | setfields status="reviewed", owner=soc`, "status", "owner")
	if want := []string{"reviewed soc", "reviewed soc"}; !reflect.DeepEqual(got, want) {
		t.Errorf("setfields = %v", got)
	}
}

func near(a any, want float64, tol float64) bool {
	f, ok := evNum(a)
	return ok && math.Abs(f-want) <= tol
}

func series(n int, f func(i int) float64) []Row {
	var rows []Row
	for i := range n {
		rows = append(rows, Row{"_time": int64(1700000000 + 3600*i), "count": f(i)})
	}
	return rows
}

func TestPredict(t *testing.T) {
	// A straight line: the trend model carries it on.
	res := &Result{Columns: []string{"_time", "count"}, Rows: series(30, func(i int) float64 { return 2*float64(i) + 1 })}
	if err := applyPredict(context.Background(), res, &query.Predict{Fields: []query.PredictField{{Field: "count"}}, Algorithm: "LLT", FutureTimespan: 3, Upper: 95, Lower: 95}); err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 33 || res.Rows[32]["_time"] != int64(1700000000+3600*32) {
		t.Fatalf("rows = %d, last = %v", len(res.Rows), res.Rows[len(res.Rows)-1])
	}
	for k, want := range []float64{61, 63, 65} {
		if r := res.Rows[30+k]; !near(r["prediction(count)"], want, 1) || r["count"] != nil {
			t.Errorf("future %d = %v, want about %v", k, r, want)
		}
	}
	if up, _ := evNum(res.Rows[31]["upper95(prediction(count))"]); up < 63 {
		t.Errorf("upper bound %v is below the forecast", up)
	}
	if !reflect.DeepEqual(res.Columns, []string{"_time", "count", "prediction(count)", "upper95(prediction(count))", "lower95(prediction(count))"}) {
		t.Errorf("columns = %v", res.Columns)
	}

	// A repeating day: the season is found and forecast.
	pattern := []float64{10, 20, 30, 20}
	res = &Result{Columns: []string{"_time", "count"}, Rows: series(40, func(i int) float64 { return pattern[i%4] })}
	if err := applyPredict(context.Background(), res, &query.Predict{Fields: []query.PredictField{{Field: "count", As: "p"}}, Algorithm: "LLP", FutureTimespan: 4, Upper: 90, Lower: 80}); err != nil {
		t.Fatal(err)
	}
	for k := range 4 {
		if r := res.Rows[40+k]; !near(r["p"], pattern[k], 1.5) {
			t.Errorf("season %d = %v, want about %v", k, r["p"], pattern[k])
		}
	}
	if _, ok := res.Rows[0]["upper90(p)"]; !ok {
		t.Errorf("bounds = %v", res.Rows[0])
	}

	// holdback forecasts the last rows from the ones before; no rows are
	// added while future_timespan does not pass them.
	res = &Result{Columns: []string{"_time", "count"}, Rows: series(20, func(int) float64 { return 7 })}
	if err := applyPredict(context.Background(), res, &query.Predict{Fields: []query.PredictField{{Field: "count"}}, Algorithm: "LL", FutureTimespan: 3, Holdback: 3, Upper: 95, Lower: 95}); err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 20 || !near(res.Rows[19]["prediction(count)"], 7, 1e-9) || !near(res.Rows[19]["upper95(prediction(count))"], 7, 1e-9) {
		t.Errorf("holdback = %d rows, last %v", len(res.Rows), res.Rows[19])
	}

	for _, bad := range []struct {
		rows []Row
		c    *query.Predict
	}{
		{series(3, func(int) float64 { return 1 }), &query.Predict{Fields: []query.PredictField{{Field: "count"}}, Algorithm: "LL", Holdback: 2}},
		{[]Row{{"count": 1.0}, {"count": 2.0}}, &query.Predict{Fields: []query.PredictField{{Field: "count"}}, Algorithm: "LL", FutureTimespan: 1}},
		{series(5, func(int) float64 { return 1 }), &query.Predict{Fields: []query.PredictField{{Field: "missing"}}, Algorithm: "LL"}},
		{series(5, func(int) float64 { return 1 }), &query.Predict{Fields: []query.PredictField{{Field: "count"}}, Algorithm: "LLP", Period: 4}},
	} {
		if err := applyPredict(context.Background(), &Result{Rows: bad.rows}, bad.c); err == nil {
			t.Errorf("predict %+v ran", bad.c)
		}
	}
}

func TestPredictParse(t *testing.T) {
	for _, bad := range []string{"* | predict", "* | predict count algorithm=arima", "* | predict a b upper95=hi", "* | predict count upper100=x", "* | predict count period=1", "* | predict count future_timespan=5000"} {
		if _, err := query.Parse(bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
	q, err := query.Parse("* | predict count as p algorithm=llt upper90=hi")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ReplaceAll(q.String(), "\n", " "); got != "* | predict count AS p algorithm=LLT upper90=hi" {
		t.Errorf("String = %q", got)
	}
}
