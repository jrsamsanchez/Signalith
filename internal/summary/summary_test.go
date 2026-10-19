// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package summary_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/summary"
)

// Every dimension and measure is a field the event template maps to a
// type terms and sums can read, and every data model has summaries.
func TestDimsAreKnownFields(t *testing.T) {
	if got, want := len(summary.Models()), len(datamodel.Models); got != want {
		t.Errorf("%d models have summaries, %d exist", got, want)
	}
	for _, m := range summary.Models() {
		for _, f := range summary.Dims(m) {
			if f == "datamodel" {
				continue
			}
			typ, ok := ingest.FieldType(f)
			if !ok || typ == "text" || typ == "wildcard" {
				t.Errorf("%s dimension %s is mapped as %q", m, f, typ)
			}
			if !summary.IsDim(m, f) {
				t.Errorf("IsDim(%s, %s) is false", m, f)
			}
		}
		for _, f := range summary.Measures(m) {
			typ, ok := ingest.FieldType(f)
			if !ok || (typ != "long" && typ != "double" && typ != "integer" && typ != "float") {
				t.Errorf("%s measure %s is mapped as %q", m, f, typ)
			}
		}
	}
	if summary.IsDim("Authentication", "_raw") || summary.IsMeasure("Authentication", "bytes") {
		t.Error("IsDim or IsMeasure accepts a field that is not one")
	}
}

// Senders cannot set the fields that mark and count summary rows, so an
// event can never pass for one.
func TestRowFieldsAreReserved(t *testing.T) {
	for _, f := range []string{summary.CountField, summary.ModelField, summary.GenField} {
		if !ingest.Reserved(f) {
			t.Errorf("%s is not reserved", f)
		}
	}
}

func TestMappingIsClosed(t *testing.T) {
	m := summary.Mapping(ingest.FieldType)
	if m["dynamic"] != false {
		t.Errorf("dynamic = %v", m["dynamic"])
	}
	props := m["properties"].(map[string]any)
	if got := props[summary.CountField]; !reflect.DeepEqual(got, map[string]any{"type": "long"}) {
		t.Errorf("count field mapped as %v", got)
	}
	if got := props["bytes"]; !reflect.DeepEqual(got, map[string]any{"type": "long"}) {
		t.Errorf("bytes mapped as %v", got)
	}
}

func TestCovered(t *testing.T) {
	at := func(h int) time.Time { return time.Date(2026, 10, 1, h, 0, 0, 0, time.UTC) }
	cases := []struct {
		name string
		st   summary.State
		want []summary.Range
	}{
		{"empty", summary.State{From: at(1), Through: at(1)}, nil},
		{"whole", summary.State{From: at(1), Through: at(5)}, []summary.Range{{From: at(1), To: at(5)}}},
		{"gap inside", summary.State{From: at(1), Through: at(5), Gaps: []summary.Gap{{From: at(2), To: at(3)}}},
			[]summary.Range{{From: at(1), To: at(2)}, {From: at(3), To: at(5)}}},
		{"gap at start and end", summary.State{From: at(1), Through: at(5), Gaps: []summary.Gap{{From: at(0), To: at(2)}, {From: at(4), To: at(6)}}},
			[]summary.Range{{From: at(2), To: at(4)}}},
		{"all gap", summary.State{From: at(1), Through: at(5), Gaps: []summary.Gap{{From: at(1), To: at(5)}}}, nil},
	}
	for _, c := range cases {
		if got := c.st.Covered(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
