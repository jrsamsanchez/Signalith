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

const multiSub = `{"hits":{"total":{"value":2},"hits":[
	{"_source":{"@timestamp":"2026-10-15T10:30:00Z","user":"dan"}},
	{"_source":{"@timestamp":"2026-10-15T07:00:00Z","user":"eve"}}]}}`

func TestMultiSearch(t *testing.T) {
	e, fs := joinEngine(joinMain, multiSub)
	got := runRows(t, e, `| multisearch [search earliest=-7d user=*] [search datamodel=Change] | table user`, "user")
	want := []string{"amy", "dan", "bob", "cat", "<nil>", "eve"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("multisearch:\n got %v\nwant %v", got, want)
	}
	if len(fs.bodies) != 2 || !strings.Contains(asJSON(fs.bodies[0]), `"gte":"now-7d"`) {
		t.Errorf("searches = %v", fs.bodies)
	}
	for _, bad := range []string{"| multisearch [search a]", "* | multisearch [search a] [search b]", "| multisearch", "| multisearch [a] x"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestTimewrap(t *testing.T) {
	res := &Result{Columns: []string{"_time", "count", "_span"}, Rows: []Row{
		{"_time": "2026-10-13T12:00:00Z", "count": 1.0, "_span": 3600.0},
		{"_time": "2026-10-14T12:00:00Z", "count": 2.0},
		{"_time": "2026-10-15T11:00:00Z", "count": 3.0},
		{"_time": "2026-10-15T12:00:00Z", "count": 4.0},
	}}
	if err := applyTimewrap(context.Background(), res, &query.Timewrap{Span: "1d"}); err != nil {
		t.Fatal(err)
	}
	wantCols := []string{"_time", "count_2days_before", "count_1day_before", "count_latest_day"}
	if !reflect.DeepEqual(res.Columns, wantCols) {
		t.Errorf("columns = %v", res.Columns)
	}
	want := []Row{
		{"_time": "2026-10-15T11:00:00Z", "count_latest_day": 3.0},
		{"_time": "2026-10-15T12:00:00Z", "count_2days_before": 1.0, "count_1day_before": 2.0, "count_latest_day": 4.0},
	}
	if !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}
	res = &Result{Columns: []string{"_time", "n"}, Rows: []Row{{"_time": 0.0, "n": 1.0}, {"_time": 7200.0, "n": 2.0}}}
	if err := applyTimewrap(context.Background(), res, &query.Timewrap{Span: "2h", Short: true}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Columns, []string{"_time", "n_s1", "n_s0"}) || len(res.Rows) != 1 || res.Rows[0]["_time"] != int64(7200) {
		t.Errorf("short = %v %v", res.Columns, res.Rows)
	}
	res = &Result{Columns: []string{"_time", "n"}, Rows: []Row{{"_time": 0.0, "n": 1.0}, {"_time": 1e9, "n": 2.0}}}
	if err := applyTimewrap(context.Background(), res, &query.Timewrap{Span: "1s"}); err == nil {
		t.Error("timewrap made a column per second of 30 years")
	}
}

func TestCluster(t *testing.T) {
	rows := func() []Row {
		return []Row{
			{RawField: "Failed password for root from 10.0.0.1 port 22"},
			{RawField: "Failed password for admin from 10.0.0.2 port 22"},
			{RawField: "Accepted publickey for amy"},
			{RawField: "Failed password for root from 10.0.0.9 port 22"},
		}
	}
	res := &Result{Rows: rows()}
	if err := applyCluster(context.Background(), res, &query.Cluster{Field: RawField, Threshold: 0.7, Match: "termlist", ShowCount: true, CountField: "cluster_count", LabelField: "cluster_label"}); err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 || res.Rows[0]["cluster_count"] != int64(3) || res.Rows[1]["cluster_label"] != int64(2) || !strings.HasPrefix(res.Rows[0][RawField].(string), "Failed password for root") {
		t.Errorf("rows = %v", res.Rows)
	}
	res = &Result{Rows: rows()}
	if err := applyCluster(context.Background(), res, &query.Cluster{Field: RawField, Threshold: 0.9, Match: "termset", LabelField: "g", LabelOnly: true}); err != nil {
		t.Fatal(err)
	}
	var labels []any
	for _, r := range res.Rows {
		labels = append(labels, r["g"])
	}
	if !reflect.DeepEqual(labels, []any{int64(1), int64(2), int64(3), int64(4)}) {
		t.Errorf("labels = %v", labels)
	}
	res = &Result{Rows: rows()}
	if err := applyCluster(context.Background(), res, &query.Cluster{Field: RawField, Threshold: 0.5, Match: "ngramset", LabelField: "g", LabelOnly: true}); err != nil {
		t.Fatal(err)
	}
	if res.Rows[0]["g"] != res.Rows[3]["g"] || res.Rows[0]["g"] == res.Rows[2]["g"] {
		t.Errorf("ngram rows = %v", res.Rows)
	}
}
