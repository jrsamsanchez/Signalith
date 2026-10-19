// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck_test

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

// joinRule is a Splunk detection whose search is search, from the data
// sources given.
func joinRule(search string, sources ...string) []byte {
	ds := ""
	for _, s := range sources {
		ds += "  - " + s + "\n"
	}
	lines := strings.Split(strings.TrimSpace(search), "\n")
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return []byte("name: Windows Joined Test\nid: 33333333-4444-5555-6666-777777777777\nauthor: Some Author, Splunk\ntype: TTP\n" +
		"status: production\ndescription: A test.\ndata_source:\n" + ds + "search: |\n" + strings.Join(lines, "\n") + "\n")
}

// convert converts a Splunk detection as the pack does, and reads it as
// splcheck does.
func convert(t *testing.T, src []byte) (*splcheck.Rule, *query.Query) {
	t.Helper()
	d, err := detect.PackDetection(&detect.Pack{Name: "splunk", Format: "splunk"},
		detect.PackRule{ID: "splunk-joined-test", File: "x.yml", Path: "detections/endpoint/x.yml"}, src)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	q, err := query.Parse(d.Query)
	if err != nil {
		t.Fatalf("%s: %v", d.Query, err)
	}
	r, err := splcheck.Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, q
}

// Rules that join a program start to other events of the same host get
// joined test cases on which the Splunk rule and the converted detection
// agree, and which a detection that ignores the join gets wrong.
func TestJoinedRulesAgree(t *testing.T) {
	for _, c := range []joinCase{
		{"file", `| tstats count from datamodel=Endpoint.Processes where Processes.process_name=java.exe by Processes.dest Processes.process_guid Processes.process_name
| ` + "`drop_dm_object_name(Processes)`" + `
| join process_guid [| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.jsp" by Filesystem.dest Filesystem.process_guid Filesystem.file_name Filesystem.file_path | ` + "`drop_dm_object_name(Filesystem)`" + ` | fields process_guid file_name file_path]
| stats count by dest process_name process_guid file_name file_path`,
			[]string{"Sysmon EventID 1 AND Sysmon EventID 11"}, "11"},
		{"linux file", `| tstats count from datamodel=Endpoint.Processes where Processes.process_name=java by Processes.dest Processes.process_guid Processes.process_name
| ` + "`drop_dm_object_name(Processes)`" + `
| join process_guid [| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.jsp" by Filesystem.process_guid Filesystem.file_name | ` + "`drop_dm_object_name(Filesystem)`" + `]`,
			[]string{"Sysmon for Linux EventID 1 AND Sysmon for Linux EventID 11"}, "11"},
		{"registry", `| tstats count from datamodel=Endpoint.Processes where Processes.process_name=reg.exe by Processes.dest Processes.process_guid Processes.process_name
| ` + "`drop_dm_object_name(Processes)`" + `
| join type=left max=0 process_guid dest [| tstats count from datamodel=Endpoint.Registry where Registry.registry_path="*\\Run\\*" by Registry.dest Registry.process_guid Registry.registry_path | ` + "`drop_dm_object_name(Registry)`" + `]
| where isnotnull(registry_path)`,
			[]string{"Sysmon EventID 1 AND Sysmon EventID 13"}, "13"},
		{"network", `| tstats count from datamodel=Endpoint.Processes where Processes.process_name=msiexec.exe by Processes.dest Processes.process_id Processes.process_name
| ` + "`drop_dm_object_name(Processes)`" + `
| join process_id [| tstats count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=443 by All_Traffic.process_id All_Traffic.dest_port | ` + "`drop_dm_object_name(All_Traffic)`" + `]`,
			[]string{"Sysmon EventID 1 AND Sysmon EventID 3"}, "3"},
		{"renamed", `| tstats count from datamodel=Endpoint.Processes where Processes.parent_process_name=w3wp.exe by Processes.dest Processes.parent_process_guid Processes.process_name
| ` + "`drop_dm_object_name(Processes)`" + `
| rename parent_process_guid as guid
| join guid [| tstats count from datamodel=Endpoint.Processes where Processes.process_name=w3wp.exe by Processes.process_guid Processes.process_path | ` + "`drop_dm_object_name(Processes)`" + ` | eval guid=process_guid]`,
			[]string{"Sysmon EventID 1"}, "1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, q := convert(t, joinRule(c.search, c.sources...))
			if len(r.Joins) != 1 {
				t.Fatalf("joins = %d", len(r.Joins))
			}
			cases := splcheck.Cases(r)
			pos, alone := 0, 0
			for _, cs := range cases {
				if cs.Source != "synthesized" {
					t.Errorf("source %q", cs.Source)
				}
				if cs.Expect {
					pos++
					if len(cs.With) == 0 || cs.With[0].EventID != c.withID {
						t.Errorf("joined case %+v", cs)
					}
				} else if len(cs.With) == 0 {
					alone++
				}
			}
			if pos == 0 || alone == 0 {
				t.Fatalf("%d joined positives, %d cases alone: %+v", pos, alone, cases)
			}
			tf := &sigmacheck.TestFile{Rule: r.ID, Cases: cases}
			if errs := splcheck.Verify(r, q, tf); len(errs) > 0 {
				t.Fatal(errs)
			}
			// Every positive is read by the rule, and found with its events.
			for _, cs := range cases {
				if cs.Expect && !splcheck.Matches(r, cs) {
					t.Errorf("positive not matched: %+v", cs)
				}
			}
			// A detection whose join's subsearch reads every event of its
			// data model disagrees with the rule on a case.
			loose := *q
			loose.Commands = nil
			for _, cmd := range q.Commands {
				if j, ok := cmd.(*query.Join); ok {
					jj := *j
					sub := *j.Sub
					sub.Search = nil
					jj.Sub = &sub
					cmd = &jj
				}
				loose.Commands = append(loose.Commands, cmd)
			}
			if !c.joinLeft() {
				errs := splcheck.Verify(r, &loose, tf)
				if len(errs) == 0 && hasSubMiss(cases) {
					t.Error("a join that reads everything agrees with the rule")
				}
			}
			// A detection without the join disagrees about the count of
			// joins.
			none := *q
			none.Commands = nil
			if errs := splcheck.Verify(r, &none, tf); len(errs) != 1 || !strings.Contains(errs[0].Error(), "the detection has 0 joins, the rule 1") {
				t.Errorf("no joins: %v", errs)
			}
		})
	}
}

type joinCase struct {
	name    string
	search  string
	sources []string
	withID  string
}

func (c joinCase) joinLeft() bool { return strings.Contains(c.search, "type=left") }

// hasSubMiss reports whether a case has an event with it that the join's
// subsearch must leave out.
func hasSubMiss(cases []sigmacheck.Case) bool {
	for _, c := range cases {
		if !c.Expect && len(c.With) > 0 {
			return true
		}
	}
	return false
}
