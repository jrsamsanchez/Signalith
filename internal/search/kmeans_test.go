// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func kmeansRows() []Row {
	var rows []Row
	for i := range 30 {
		x := float64(i % 3)
		switch {
		case i < 10:
			rows = append(rows, Row{"x": x, "y": x})
		case i < 20:
			rows = append(rows, Row{"x": 100 + x, "y": 100 - x})
		default:
			rows = append(rows, Row{"x": -100 - x, "y": 50 + x})
		}
	}
	return append(rows, Row{"x": "n/a", "y": 1.0}, Row{"_time": 5.0})
}

func TestKMeans(t *testing.T) {
	res := &Result{Rows: kmeansRows(), Columns: []string{"_time", "x", "y"}}
	c := &query.KMeans{K: 3, Reps: 5, MaxIters: 100, Distance: "l2", ShowCentroid: true, ClusterField: "CLUSTERNUM"}
	if err := applyKMeans(context.Background(), res, c); err != nil {
		t.Fatal(err)
	}
	for i, r := range res.Rows[:30] {
		if want := int64(i/10 + 1); r["CLUSTERNUM"] != want {
			t.Fatalf("row %d cluster = %v, want %d", i, r["CLUSTERNUM"], want)
		}
	}
	if r := res.Rows[0]; !near(r["centroid_x"], 0.9, 0.01) || !near(r["centroid_y"], 0.9, 0.01) {
		t.Errorf("first centroid = %v, %v", r["centroid_x"], r["centroid_y"])
	}
	if _, ok := res.Rows[30]["CLUSTERNUM"]; ok {
		t.Error("a row without numbers got a cluster")
	}
	if _, ok := res.Rows[31]["CLUSTERNUM"]; ok {
		t.Error("a row with only _time got a cluster")
	}

	// The same rows give the same clusters every time.
	again := &Result{Rows: kmeansRows(), Columns: []string{"_time", "x", "y"}}
	c.Distance, c.ShowCentroid = "l1", false
	if err := applyKMeans(context.Background(), again, c); err != nil {
		t.Fatal(err)
	}
	for i, r := range again.Rows[:30] {
		if r["CLUSTERNUM"] != res.Rows[i]["CLUSTERNUM"] || r["centroid_x"] != nil {
			t.Fatalf("l1 row %d = %v", i, r)
		}
	}

	cos := &Result{Rows: []Row{{"a": 1.0, "b": 0.0}, {"a": 5.0, "b": 0.1}, {"a": 0.0, "b": 2.0}, {"a": 0.1, "b": 9.0}}, Columns: []string{"a", "b"}}
	if err := applyKMeans(context.Background(), cos, &query.KMeans{K: 2, Reps: 3, MaxIters: 50, Distance: "cos", ClusterField: "c"}); err != nil {
		t.Fatal(err)
	}
	if r := cos.Rows; r[0]["c"] != r[1]["c"] || r[2]["c"] != r[3]["c"] || r[0]["c"] == r[2]["c"] {
		t.Errorf("cos clusters = %v", r)
	}

	for _, bad := range []*Result{
		{Rows: []Row{{"x": 1.0}}, Columns: []string{"x"}},
		{Rows: []Row{{"x": "a"}, {"x": "b"}, {"x": "c"}}, Columns: []string{"x"}},
	} {
		if err := applyKMeans(context.Background(), bad, &query.KMeans{K: 2, Reps: 1, MaxIters: 5, Distance: "l2", ClusterField: "c"}); err == nil {
			t.Errorf("kmeans on %v ran", bad.Rows)
		}
	}
}

func TestKMeansParse(t *testing.T) {
	for _, bad := range []string{"* | kmeans k=0", "* | kmeans k=101", "* | kmeans dt=hamming", "* | kmeans t=-1", "* | kmeans reps=0", "* | kmeans cfield="} {
		if _, err := query.Parse(bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}
