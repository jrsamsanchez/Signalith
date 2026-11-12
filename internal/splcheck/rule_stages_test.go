// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"strings"
	"testing"
)

// Later stages of a rule that Signalith runs differently from Splunk
// (joins of other searches, windows of time buckets, lookups that give
// several values) are refused with why, and the rest convert.
func TestRuleLaterStages(t *testing.T) {
	lookups := testLookups(t,
		[2]string{pipesMeta, pipesCSV},
		[2]string{"name: exact\nlookup_type: csv\n", "pipe,tool,note\na,A,x\nb,B,\nb,C,y\n"},
		[2]string{"name: one\nlookup_type: csv\nmax_matches: 1\n", "pipe,tool,note\na,A,x\nb,B,\n"},
		[2]string{"name: padded\nlookup_type: csv\n", "pipe,tool\na, A \nb,B\n"},
		[2]string{"name: dflt\nlookup_type: csv\ndefault_match: none\n", "pipe,tool\na,A\n"},
	)
	for _, c := range []struct{ search, want string }{
		{"`sysmon` EventCode=1 | stats count by dest | join dest [search `sysmon` EventCode=3 | stats count by dest] | transaction dest | join dest [search `sysmon` EventCode=3 | stats count by dest]", "a join of a subsearch that is not a tstats search is not sup"},
		{"`sysmon` EventCode=1 IntegrityLevel=high | where match(IntegrityLevel, \"(?i)high\")", ""},
		{"`sysmon` EventCode=1 | stats count by dest | map search=\"search dest=$dest$\"", "a later map search reads each $dest$'s events from Splunk's "},
		{"`sysmon` EventCode=1 | stats count by dest | append [search `sysmon` EventCode=3]", "a later append of another search is not supported"},
		{"`sysmon` EventCode=1 | stats count by dest | `nosuchmacro`", "`nosuchmacro`"},
		{"`sysmon` EventCode=1 | stats count by dest | union [search a] [search b]", "union"},
		{"`sysmon` EventCode=1 | stats count by dest | appendpipe [stats count]", "appendpipe"},
		{"`sysmon` EventCode=1 | stats count by dest | inputlookup t", "| inputlookup owners, or with append=true adds its rows late"},
		{"`sysmon` EventCode=1 | stats count by dest | eventcount", "| eventcount summarize=false"},
		{"`sysmon` EventCode=1 | stats count by dest | search NOT dest=x", ""},
		{"`sysmon` EventCode=1 | stats count by dest | search dest=x OR dest=y", ""},
		{"`sysmon` EventCode=1 | stats count by dest | search dest IN (x, y) dest=z", ""},
		{"`sysmon` EventCode=1 | stats count by dest | search count>5", ""},
		{"`sysmon` EventCode=1 | stats count by dest | search *", ""},
		{"`sysmon` EventCode=1 | stats count by dest | search 5", "search 5 has the bare term 5"},
		{"`sysmon` EventCode=1 | stats count by dest | search AND", "search count>20 user=adm*"},
		{"`sysmon` EventCode=1 | stats count by dest | search foo", "search foo has the bare term foo"},
		{"`sysmon` EventCode=1 | stats count by dest | search [search b]", ""},
		{"`sysmon` EventCode=1 | stats count by dest | where count > 2 | where dest=\"x\"", ""},
		{"`sysmon` EventCode=1 | stats count by dest | eval x=1 | stats count by x", ""},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest _time span=1h | `drop_dm_object_name(Processes)` | eventstats avg(count) as a by dest", "a later eventstats of a tstats search grouped by time depend"},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest _time span=1h | `drop_dm_object_name(Processes)` | stats avg(count) as a by dest", "a tstats search grouped by time with a later avg() is not su"},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest _time span=1h | `drop_dm_object_name(Processes)` | stats min(firstTime) as f by dest", ""},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest _time span=1h | `drop_dm_object_name(Processes)` | where _time > 5", "where _time reads no count of the search"},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest _time span=1h | `drop_dm_object_name(Processes)` | where count < 5", "where count <"},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest _time span=1h | `drop_dm_object_name(Processes)` | where count > 5", ""},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest _time span=2d", ""},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest _time span=90m", ""},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by _time span=1h", ""},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe", "search is not a tstats search of Endpoint.Processes, Filesys"},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest | `drop_dm_object_name(Processes)` | join dest [search `sysmon` EventCode=3 | stats count by dest]", "a join of a subsearch that is not a tstats search is not sup"},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest | `drop_dm_object_name(Processes)` | join dest [| tstats count from datamodel=Endpoint.Processes where Processes.process_name=b.exe by Processes.dest | `drop_dm_object_name(Processes)` | where count > 5]", "a join of a subsearch that counts is not supported"},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest | `drop_dm_object_name(Processes)` | join dest [| tstats count from datamodel=Endpoint.Processes where Processes.process_name=b.exe by Processes.dest | `drop_dm_object_name(Processes)` | lookup exact pipe AS dest OUTPUT tool]", "a join of a subsearch that looks values up is not supported"},
		{"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest | `drop_dm_object_name(Processes)` | join dest [| tstats count from datamodel=Endpoint.Processes where Processes.process_name=b.exe]", "search is not a tstats search of Endpoint.Processes, Filesys"},
		{"`sysmon` EventCode=1 | stats count by dest | join dest [search `linux_auditd` type=SYSCALL | stats count by dest]", "a join of a subsearch that is not a tstats search is not sup"},
		{"`sysmon` EventCode=1 | stats count by dest | join dest [search `sysmon` EventCode=3 | iplocation dest | stats count by dest]", "a join of a subsearch that is not a tstats search is not sup"},
		{"`sysmon` EventCode=1 | stats dc(user) as u, dc(host) as h by dest | where u > 2 AND h > 2", "field host has no Signalith mapping"},
		{"`sysmon` EventCode=1 | stats dc(user) as u by dest | where u > 2", ""},
		{"`sysmon` EventCode=1 | spath path=a{} output=b | where b=\"x\"", ""},
		{"`sysmon` EventCode=1 | eval x=mvindex(split(Image, \"\\\\\"), -1) | where x=\"a.exe\"", ""},
		{"`sysmon` EventCode=1 | rex field=Image \"(?<n>[^\\\\]+)$\" | where n=\"a.exe\"", "`[^\\]+)$`"},
		{"`sysmon` EventCode=1 | regex Image=\"a\\.exe$\"", ""},
	} {
		src := rule(c.search)
		_, err := ParseWith(src, testMacros, ParseOptions{Lookups: lookups})
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.search, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want %q", c.search, err, c.want)
		}
	}
}
