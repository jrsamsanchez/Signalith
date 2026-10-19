// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

// The record keeps everything under "body" next to "kind": the runtime
// index it lives in gives its other top-level fields types of their own
// (state is a server's state there, a keyword), and OpenSearch would
// refuse an object in them.
func TestRecordShape(t *testing.T) {
	doc := stateDoc{Kind: stateKind, State: &State{ID: "sample-x", Partial: true},
		Job: &Activity{Op: "load", Phase: "Writing events", Server: "siem-a", Beat: time.Now()}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range top {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"body", "kind"}) {
		t.Errorf("top-level fields %v, want body and kind", keys)
	}
	var back stateDoc
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Kind != stateKind || back.State.ID != "sample-x" || !back.State.Partial || back.Job.Server != "siem-a" {
		t.Errorf("round trip = %+v %+v %+v", back, back.State, back.Job)
	}
}
