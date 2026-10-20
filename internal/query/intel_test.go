// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import "testing"

func TestParseIntelCommands(t *testing.T) {
	q, err := Parse(`datamodel=Network_Traffic | threatmatch src, dest | stats count by src | intel src dest`)
	if err != nil {
		t.Fatal(err)
	}
	tm, ok := q.Commands[0].(*ThreatMatch)
	if !ok || len(tm.Fields) != 2 || tm.Fields[1] != "dest" {
		t.Fatalf("threatmatch = %#v", q.Commands[0])
	}
	in, ok := q.Commands[2].(*Intel)
	if !ok || len(in.Fields) != 2 {
		t.Fatalf("intel = %#v", q.Commands[2])
	}
	want := "datamodel=Network_Traffic\n| threatmatch src, dest\n| stats count by src\n| intel src, dest"
	if got := q.String(); got != want {
		t.Errorf("String() =\n%s\nwant\n%s", got, want)
	}
	q, err = Parse(`* | threatmatch | intel`)
	if err != nil || q.String() != "*\n| threatmatch\n| intel" {
		t.Errorf("bare = %v %v", q, err)
	}
	if _, err := Parse(`* | intel src=1`); err == nil {
		t.Error("intel takes field names only")
	}
}
