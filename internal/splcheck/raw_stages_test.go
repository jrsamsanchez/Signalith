// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"strings"
	"testing"
)

// Raw and tstats searches whose later stages Signalith cannot run, or
// that name event codes where it does not read them, are refused with
// why; the ones it converts get events the rule finds.
func TestRawSearchStages(t *testing.T) {
	const procs = "| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest"
	const sub = "[| tstats count from datamodel=Endpoint.Processes where Processes.process_name=b.exe by Processes.dest"
	for _, c := range []struct{ search, want string }{
		{procs + " | regex nosuch=\"a\"", "field nosuch has no Signalith mapping"},
		{procs + " | where match(nosuch, \"a\")", "field nosuch has no Signalith mapping"},
		{procs + " _time span=1h | `drop_dm_object_name(Processes)` | join dest " + sub + " | `drop_dm_object_name(Processes)`]", "a tstats search grouped by time is not supported in a join"},
		{procs + " | `drop_dm_object_name(Processes)` | join dest " + sub + " _time span=1h | `drop_dm_object_name(Processes)`]", "join's subsearch: a tstats search grouped by time is not supported in a join"},
		{procs + " | where count > 5 | eval x=1", "search has a later stage Signalith does not run: eval x=1"},
		{procs + " | where count > 5 | stats count by dest", "search has a later stage Signalith does not run: stats count by"},
		{"`linux_auditd` type=SYSCALL EventCode=1", "a linux_auditd search names no event code"},
		{"`cloudtrail` eventName=CreateUser EventCode=1", "a cloudtrail search names no event code"},
		{"`wineventlog_security` EventCode=4625 | fillnull | stats count by user | where count > 5", "a count after fillnull is not supported"},
		{"`wineventlog_security` EventCode=4698 | xmlkv Message | search EventCode=4698", "must name its event code once, at the top"},
		{"`sysmon` EventCode=1 | regex Image=\"(\"", "missing closing )"},
		{"`sysmon` EventCode=1 | where match(nosuch, \"a\")", "field nosuch is not a field of Processes events"},
		{"`sysmon` EventCode IN (1, 3)", "events of Processes and NetworkConnection together is not supported"},
		{"`sysmon` NOT EventCode=1", "must name its event code (EventCode=...) once, at the top"},
		{"`sysmon`", "search is not a tstats search"},
		{"`wineventlog_security` EventCode=4625 | fillnull value=x user | stats count by user | where count > 5", ""},
		{"`wineventlog_security` EventCode=4625 | bin _time span=5m | stats count by user", ""},
		{"`wineventlog_security` EventCode=4698 | xmlkv Message | search Command=\"*a*\"", ""},
		{"`wineventlog_security` EventCode=4698 | xmlkv Message | search Command=\"*a*\" | stats count by dest", ""},
		{"`linux_auditd` type=SYSCALL | stats count by host | where count > 3", ""},
		{"`cloudtrail` eventName=CreateUser errorCode=success", ""},
		{"`cloudtrail` eventName=CreateUser | stats count by src | where count > 5", ""},
		{"`azure_monitor_aad` operationName=\"Add member to role\" | stats count by user | where count > 5", ""},
		{"`o365_management_activity` Operation=Add* | stats dc(user) as n by src | where n > 5", ""},
		{"`okta` eventType=user.session.start | stats count by src | where count > 5", ""},
		{"`sysmon` EventCode=1 | bucket _time span=1h | stats count by dest _time | where count > 5", ""},
	} {
		r, err := Parse(rule(c.search), testMacros)
		if c.want != "" {
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: err = %v, want %q", c.search, err, c.want)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.search, err)
			continue
		}
		cases := Cases(r)
		pos := 0
		for _, cs := range cases {
			if cs.Expect {
				pos++
			}
		}
		if pos == 0 {
			t.Errorf("%s: no positive case: %s", c.search, NoEventsReason(r, cases))
		}
	}
}
