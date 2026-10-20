// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"testing"
)

// A network detection's tstats over a network data model reads the sensor
// node, only with the Network option, and its test events are Zeek lines.
func TestSensorRule(t *testing.T) {
	src := rule("| tstats `security_content_summariesonly` count from datamodel=Network_Traffic where All_Traffic.dest_port=4786 AND All_Traffic.transport=tcp by All_Traffic.src_ip All_Traffic.dest_ip\n| `drop_dm_object_name(\"All_Traffic\")`")
	if _, err := Parse(src, nil); err == nil {
		t.Fatal("a network data model search parsed without the Network option")
	}
	r, err := ParseWith(src, nil, ParseOptions{Network: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != SensorTrafficNode || NodeModel[r.Node] != "Network_Traffic" {
		t.Fatalf("node %s", r.Node)
	}
	cases := Cases(r)
	pos := 0
	for _, c := range cases {
		if c.Channel != "zeek:conn" {
			t.Errorf("channel %s", c.Channel)
		}
		if c.Expect {
			pos++
			doc, model := Stored(c)
			if model != "Network_Traffic" || doc["dest_port"] != int64(4786) {
				t.Errorf("stored %s %v", model, doc)
			}
		}
	}
	if pos == 0 || pos == len(cases) {
		t.Errorf("%d of %d cases positive", pos, len(cases))
	}

	r, err = ParseWith(rule(`| tstats count from datamodel=Network_Resolution where DNS.query IN ("*.ngrok.io") DNS.record_type=A by DNS.src`), nil, ParseOptions{Network: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != SensorDNSNode {
		t.Fatalf("node %s", r.Node)
	}
	for _, c := range Cases(r) {
		doc, _ := Stored(c)
		if c.Expect && (doc["query_type"] != "A" || doc["sourcetype"] != "zeek:dns") {
			t.Errorf("stored %v", doc)
		}
	}
}
