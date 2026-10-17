package search

import (
	"context"
	"reflect"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestExtract(t *testing.T) {
	res := &Result{Rows: []Row{
		{RawField: `Oct 1 sshd: user=alice action="log in" src=10.0.0.1, _time=5 host=evil n=1 n=2 =x y=`, "host": "web1"},
		{RawField: "a:1|b:2|c"},
		{RawField: "no pairs here"},
	}}
	if err := applyExtract(context.Background(), res, &query.Extract{PairDelim: " ,;", KVDelim: "=", Limit: 50, MaxChars: 10240, CleanKeys: true}); err != nil {
		t.Fatal(err)
	}
	r := res.Rows[0]
	want := map[string]any{"user": "alice", "action": "log in", "src": "10.0.0.1", "host": "web1", "n": "1"}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s = %#v, want %#v", k, r[k], v)
		}
	}
	if _, ok := r["_time"]; ok {
		t.Error("extract wrote an _ field")
	}
	res = &Result{Rows: []Row{{RawField: "a:1|b:2|c|a:3"}}}
	if err := applyExtract(context.Background(), res, &query.Extract{PairDelim: "|", KVDelim: ":", Limit: 50, MaxChars: 10240, MVAdd: true}); err != nil {
		t.Fatal(err)
	}
	if got := res.Rows[0]["a"]; !reflect.DeepEqual(got, []any{"1", "3"}) {
		t.Errorf("a = %#v", got)
	}
	if res.Rows[0]["b"] != "2" {
		t.Errorf("b = %#v", res.Rows[0]["b"])
	}
	// Without clean_keys, a key with a control character is still skipped.
	res = &Result{Rows: []Row{{RawField: "\x00tenant=x ok=1"}}}
	if err := applyExtract(context.Background(), res, &query.Extract{PairDelim: " ", KVDelim: "=", Limit: 50, MaxChars: 10240}); err != nil {
		t.Fatal(err)
	}
	if len(res.Rows[0]) != 2 || res.Rows[0]["ok"] != "1" {
		t.Errorf("row = %#v", res.Rows[0])
	}
}

func TestOutlier(t *testing.T) {
	rows := func() []Row {
		var out []Row
		for _, n := range []float64{-100, 1, 2, 3, 4, 5, 100} {
			out = append(out, Row{"n": n, "_time": n})
		}
		return out
	}
	res := &Result{Rows: rows(), Columns: []string{"n", "_time"}}
	if err := applyOutlier(context.Background(), res, &query.Outlier{Param: 2.5}); err != nil {
		t.Fatal(err)
	}
	// Quartiles 1.5 and 4.5, so the bounds are -6 and 12.
	if res.Rows[6]["n"] != numOut(12) || res.Rows[0]["n"] != -100.0 || res.Rows[6]["_time"] != 100.0 {
		t.Errorf("rows = %v", res.Rows)
	}
	res = &Result{Rows: rows(), Columns: []string{"n"}}
	if err := applyOutlier(context.Background(), res, &query.Outlier{Param: 2.5, UseLower: true, Remove: true}); err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 5 {
		t.Errorf("rows = %v", res.Rows)
	}
	res = &Result{Rows: rows(), Columns: []string{"n"}}
	if err := applyOutlier(context.Background(), res, &query.Outlier{Fields: []string{"n"}, Param: 2.5, Mark: true}); err != nil {
		t.Fatal(err)
	}
	if res.Rows[6]["n"] != "00012" {
		t.Errorf("marked = %#v", res.Rows[6]["n"])
	}
}

func TestGauge(t *testing.T) {
	res := &Result{Rows: []Row{{"count": 42.0}, {"count": 7.0}}}
	if err := applyGauge(context.Background(), res, &query.Gauge{Value: "count", Range: []float64{0, 50, 100}}); err != nil {
		t.Fatal(err)
	}
	want := Row{"x": 42.0, "y1": numOut(0), "y2": numOut(50), "y3": numOut(100)}
	if !reflect.DeepEqual(res.Rows, []Row{want}) || !reflect.DeepEqual(res.Columns, []string{"x", "y1", "y2", "y3"}) {
		t.Errorf("got %v %v", res.Rows, res.Columns)
	}
	res = &Result{}
	if err := applyGauge(context.Background(), res, &query.Gauge{Value: "7"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Rows, []Row{{"x": numOut(7), "y1": numOut(0), "y2": numOut(100)}}) {
		t.Errorf("got %v", res.Rows)
	}
}
