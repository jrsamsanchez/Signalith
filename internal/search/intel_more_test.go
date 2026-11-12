// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"slices"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// intel reads the default fields when none are named, each value of a
// multivalue field, and leaves an empty description out.
func TestIntelEnrichDefaultsAndMultivalues(t *testing.T) {
	e := &Engine{Intel: intelStore(t)}
	res := &Result{
		Columns: []string{"_time", "src", "dest"},
		Rows: []Row{
			{"src": []any{"", 7, "198.51.100.4"}, "dest": "evil.example"},
			{"src": "192.0.2.1"},
		},
	}
	if err := e.intelEnrich(res, &query.Intel{}); err != nil {
		t.Fatal(err)
	}
	r := res.Rows[0]
	if r["src_intel_source"] != "drop" || r["src_intel_weight"] != int64(1) || r["dest_intel_source"] != "urlhaus" {
		t.Errorf("row = %v", r)
	}
	if _, ok := r["src_intel_description"]; ok {
		t.Errorf("an empty description was set: %v", r)
	}
	if len(res.Rows[1]) != 1 {
		t.Errorf("an address without indicators was enriched: %v", res.Rows[1])
	}
	if !slices.Contains(res.Columns, "src_intel_source") || !slices.Contains(res.Columns, "dest_intel_type") {
		t.Errorf("columns = %v", res.Columns)
	}
	if got := stringValues(42); got != nil {
		t.Errorf("stringValues(42) = %v", got)
	}
	if fmtWeight(1.5) != 1.5 || fmtWeight(2) != int64(2) {
		t.Error("fmtWeight")
	}
}

// threatmatch annotates matching rows with their strongest indicator and
// a target, keeps or drops the rest, and puts its columns after _time.
func TestThreatAnnotate(t *testing.T) {
	e := &Engine{Intel: intelStore(t)}
	rows := func() *Result {
		return &Result{
			Columns: []string{"_time", "src", "dest"},
			Rows: []Row{
				{"src": "203.0.113.9", "dest": "10.0.0.5"},
				{"src": "192.0.2.1", "dest": "10.0.0.6"},
			},
		}
	}
	res := rows()
	e.threatAnnotate(res, &query.ThreatMatch{}, false)
	if len(res.Rows) != 2 {
		t.Fatalf("rows = %v", res.Rows)
	}
	r := res.Rows[0]
	if r["threat_match_field"] != "src" || r["threat_weight"] != int64(2) || r["threat_description"] != "Emotet C2" || r["threat_target"] != "10.0.0.5" {
		t.Errorf("row = %v", r)
	}
	if res.Columns[0] != "_time" || res.Columns[1] != "threat_match_field" {
		t.Errorf("columns = %v", res.Columns)
	}
	res = rows()
	e.threatAnnotate(res, &query.ThreatMatch{Fields: []string{"src"}}, true)
	if len(res.Rows) != 1 {
		t.Errorf("unmatched rows were kept: %v", res.Rows)
	}
	// No match at all leaves the columns as they were.
	res = &Result{Columns: []string{"a"}, Rows: []Row{{"a": "x"}}}
	e.threatAnnotate(res, &query.ThreatMatch{Fields: []string{"a"}}, true)
	if len(res.Rows) != 0 || !slices.Equal(res.Columns, []string{"a"}) {
		t.Errorf("no match: %v %v", res.Rows, res.Columns)
	}
}
