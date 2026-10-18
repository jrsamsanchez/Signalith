package detect

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

// A rule that joins a program start to the file it writes runs Signalith's
// join, its subsearch the other node's converted filter, and its tests
// are pairs of events.
func TestSplunkJoin(t *testing.T) {
	rule := func(join string) []byte {
		return []byte(`name: Windows Joined Thing
id: 22222222-3333-4444-5555-666666666666
author: Some Author, Splunk
type: TTP
status: production
description: A test.
data_source:
  - Sysmon EventID 1 AND Sysmon EventID 11
search: |
  | tstats count from datamodel=Endpoint.Processes where Processes.process_name=winword.exe by Processes.dest Processes.process_guid Processes.process_name
  | ` + "`drop_dm_object_name(Processes)`" + `
  | ` + join + `
  | ` + "`windows_joined_thing_filter`\n")
	}
	src := rule("join process_guid dest [| tstats `security_content_summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_name=*.dll by Filesystem.dest Filesystem.process_guid Filesystem.file_name | `drop_dm_object_name(Filesystem)`]")
	p := &Pack{Name: "splunk", Format: "splunk"}
	d, err := PackDetection(p, PackRule{ID: "splunk-windows-joined-thing", File: "x.yml", Path: "detections/endpoint/x.yml"}, src)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| join process_guid, dest [search datamodel=Filesystem", "signature_id IN (11, 23, 26)", "file_name=*.dll", "eval dest=host"} {
		if !strings.Contains(d.Query, want) {
			t.Errorf("query %s lacks %s", d.Query, want)
		}
	}
	q, err := query.Parse(d.Query)
	if err != nil {
		t.Fatal(err)
	}
	r, err := splcheck.Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := splcheck.Cases(r)
	pos, alone := 0, 0
	for _, c := range cases {
		if c.Expect {
			pos++
			if len(c.With) != 1 || c.With[0].EventID != "11" || c.With[0].Data["ProcessGuid"] != c.Data["ProcessGuid"] {
				t.Errorf("joined case %+v", c)
			}
		} else if len(c.With) == 0 {
			alone++
		}
	}
	if pos == 0 || alone == 0 {
		t.Fatalf("cases %+v", cases)
	}
	if errs := splcheck.Verify(r, q, &sigmacheck.TestFile{Rule: r.ID, Cases: cases}); len(errs) > 0 {
		t.Error(errs)
	}

	// A connection's src and dest, a user and a joined row's time are
	// not joined on, nor is a subsearch that is not a tstats search.
	for _, bad := range []string{
		"join process_id dest [| tstats count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=80 by All_Traffic.process_id All_Traffic.src | `drop_dm_object_name(All_Traffic)` | rename src as dest]",
		"join user [| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_name=*.dll by Filesystem.user | `drop_dm_object_name(Filesystem)`]",
		"join process_guid [search `sysmon` EventCode=11]",
		"join usetime=t process_guid [| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_name=*.dll by Filesystem.process_guid | `drop_dm_object_name(Filesystem)`]",
	} {
		if _, err := splcheck.Parse(rule(bad), nil); err == nil {
			t.Errorf("%s: converted", bad)
		}
	}
}
