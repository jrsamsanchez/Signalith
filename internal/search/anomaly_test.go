package search

import (
	"context"
	"reflect"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestAnomalyDetection(t *testing.T) {
	rows := func() []Row {
		var out []Row
		for i := 0; i < 200; i++ {
			out = append(out, Row{"user": "amy", "bytes": 100.0 + float64(i%5), "_time": float64(i)})
		}
		out[50]["user"] = "mallory"
		out[120]["bytes"] = 10000.0
		return out
	}
	res := &Result{Rows: rows(), Columns: []string{"user", "bytes", "_time"}}
	if err := applyAnomalyDetection(context.Background(), res, &query.AnomalyDetection{Method: "histogram", Action: "filter", PThresh: 0.01}); err != nil {
		t.Fatal(err)
	}
	// Each of these appears once in 200 rows (0.005 < 0.01); _time is skipped.
	if len(res.Rows) != 2 || res.Rows[0]["probable_cause"] != "user" || res.Rows[1]["probable_cause"] != "bytes" || res.Rows[0]["isOutlier"] != int64(1) {
		t.Errorf("histogram = %v", res.Rows)
	}

	res = &Result{Rows: rows(), Columns: []string{"user", "bytes"}}
	if err := applyAnomalyDetection(context.Background(), res, &query.AnomalyDetection{Method: "zscore", Action: "annotate", PThresh: 0.01, Fields: []string{"bytes"}}); err != nil {
		t.Fatal(err)
	}
	var outliers []int
	for i, r := range res.Rows {
		if r["isOutlier"] == int64(1) {
			outliers = append(outliers, i)
		}
	}
	if len(res.Rows) != 200 || !reflect.DeepEqual(outliers, []int{120}) {
		t.Errorf("zscore outliers = %v of %d", outliers, len(res.Rows))
	}

	res = &Result{Rows: rows(), Columns: []string{"user", "bytes"}}
	if err := applyAnomalyDetection(context.Background(), res, &query.AnomalyDetection{Method: "histogram", Action: "summary", PThresh: 0.01}); err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0]["num_anomalies"] != int64(2) || res.Rows[0]["num_events"] != int64(200) {
		t.Errorf("summary = %v", res.Rows)
	}
}

func TestCorrelate(t *testing.T) {
	res := &Result{Columns: []string{"a", "b", "_time"}, Rows: []Row{
		{"a": 1, "b": 2, "_time": 1},
		{"a": 1, "_time": 2},
		{"b": 1, "_time": 3},
		{"a": 1, "b": 1},
	}}
	if err := applyCorrelate(context.Background(), res, &query.Correlate{}); err != nil {
		t.Fatal(err)
	}
	want := []Row{
		{"RowField": "a", "a": numOut(0.75), "b": numOut(0.5)},
		{"RowField": "b", "a": numOut(0.5), "b": numOut(0.75)},
	}
	if !reflect.DeepEqual(res.Rows, want) || !reflect.DeepEqual(res.Columns, []string{"RowField", "a", "b"}) {
		t.Errorf("correlate = %v %v", res.Rows, res.Columns)
	}
}
