// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"reflect"
	"strings"
	"testing"
)

func TestTstats(t *testing.T) {
	for src, want := range map[string]string{
		`| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe Processes.user!=SYSTEM by Processes.dest, Processes.user`: "datamodel=Endpoint process_name=cmd.exe user!=SYSTEM\n| stats count by dest, user\n| rename dest as Processes.dest, user as Processes.user",
		`| tstats summariesonly=t count, dc(All_Traffic.dest_ip) from datamodel=Network_Traffic where All_Traffic.app=*curl* by All_Traffic.src_ip`:      "datamodel=Network_Traffic process_path=*curl*\n| stats count, dc(dest) as \"dc(All_Traffic.dest_ip)\" by src\n| rename src as All_Traffic.src_ip",
		`| tstats count where index=* by index, sourcetype`:                                                                      "index=*\n| stats count by index, sourcetype",
		`| tstats count from datamodel=Authentication where Authentication.action=failure earliest=-1h by _time span=10m`:        "datamodel=Authentication action=failure earliest=-1h\n| bin span=10m _time\n| stats count by _time",
		`| tstats values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem by Filesystem.dest | where count > 1`: "datamodel=Filesystem\n| stats values(file_path) as paths by dest\n| rename dest as Filesystem.dest\n| where count>1",
		`| tstats count from datamodel=Malware`:                                                                                  "datamodel=Malware\n| stats count",
		`| tstats summariesonly=false allow_old_summaries=true fillnull_value=null count from datamodel=Web by Web.user`:         "datamodel=Web\n| fillnull value=null user\n| stats count by user\n| rename user as Web.user",
		`| tstats fillnull_value="N/A" count from datamodel=Malware`:                                                             "datamodel=Malware\n| stats count",
	} {
		q, err := Parse(src)
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		if got := q.String(); got != want {
			t.Errorf("Parse(%q):\n got %s\nwant %s", src, got, want)
		}
	}
	for src, want := range map[string]string{
		`x | tstats count`:                                          "tstats starts the search",
		`| tstats count from datamodel=Nope by x`:                   "tstats cannot read",
		`| tstats count from datamodel=Endpoint.Services`:           "tstats cannot read",
		`| tstats count from x=y`:                                   "datamodel=",
		`| tstats prestats=t count`:                                 "prestats",
		`| tstats fillnull_value=( count`:                           "fillnull_value",
		`| tstats count by host span=1h`:                            "needs _time",
		`| tstats count from datamodel=Web where index=signalith-*`: "not both",
		`| tstats count from datamodel=Web foo`:                     "unexpected",
		`| tstats`:                                                  "expected an aggregation",
		`* | appendpipe [tstats count]`:                             "cannot run inside appendpipe",
	} {
		if _, err := Parse(src); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want %q", src, err, want)
		}
	}
}

func TestParseChartSeriesSpath(t *testing.T) {
	for src, want := range map[string]Command{
		`* | chart count by host`:                              &Chart{Aggs: []Agg{{Func: "count"}}, Over: "host", Limit: 10},
		`* | chart count by host, action`:                      &Chart{Aggs: []Agg{{Func: "count"}}, Over: "host", By: "action", Limit: 10},
		`* | chart limit=0 avg(bytes) over host by a`:          &Chart{Aggs: []Agg{{Func: "avg", Field: "bytes"}}, Over: "host", By: "a", Limit: 0},
		`* | chart count, dc(user) over host`:                  &Chart{Aggs: []Agg{{Func: "count"}, {Func: "dc", Field: "user"}}, Over: "host", Limit: 10},
		`* | xyseries host action count`:                       &XYSeries{X: "host", Y: "action", Values: []string{"count"}},
		`* | xyseries host, action, count, dc(user)`:           &XYSeries{X: "host", Y: "action", Values: []string{"count", "dc(user)"}},
		`* | untable host action count`:                        &Untable{X: "host", Label: "action", Value: "count"},
		`* | spath`:                                            &Spath{Input: "_raw"},
		`* | spath input=body output=u path=actor.user{}.name`: &Spath{Input: "body", Output: "u", Path: "actor.user{}.name"},
		`* | spath "a b.c"`:                                    &Spath{Input: "_raw", Path: "a b.c"},
	} {
		q, err := Parse(src)
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		if got := q.Commands[len(q.Commands)-1]; !reflect.DeepEqual(got, want) {
			t.Errorf("Parse(%q) = %#v, want %#v", src, got, want)
		}
		if _, err := Parse(q.String()); err != nil {
			t.Errorf("%q printed %q: %v", src, q.String(), err)
		}
	}
	for src, want := range map[string]string{
		`* | chart count`:                    "needs a field to chart over",
		`* | chart count, dc(u) over h by a`: "one function",
		`* | chart count by a, b, c`:         "one field to chart over",
		`* | chart limit=5000 count by a`:    "at most 1000",
		`* | xyseries a b`:                   "xyseries expects",
		`* | untable a b`:                    "untable expects",
		`* | spath path=a..b`:                "empty",
		`* | spath path=a{1}.b`:              "use {}",
		`* | spath output=x`:                 "needs a path",
		`* | spath mode=x`:                   "unknown spath option",
	} {
		if _, err := Parse(src); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want %q", src, err, want)
		}
	}
}
