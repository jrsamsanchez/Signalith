// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"strings"
	"testing"
)

// Rules whose later stages compare fields, test what an if() or case()
// gives, or change a field in place get test events their filter and
// later stages agree on; rules splcheck cannot make an event for say
// why, and a search naming two event codes is refused.
func TestLaterStageCases(t *testing.T) {
	for _, c := range []struct{ search, want string }{
		{"`sysmon` EventCode=1 | eval x=lower(Image) | where x=lower(ParentImage)", ""},
		{"`sysmon` EventCode=1 | eval t=case(match(Image, \"a\"), 1) | where isnotnull(t)", ""},
		{"`sysmon` EventCode=1 | eval t=if(match(Image, \"a\"), 1, 0) | where t=1", ""},
		{"`sysmon` EventCode=1 | eval n=mvcount(split(CommandLine, \" \")) | where n > 3", ""},
		{"`sysmon` EventCode=1 | eval Image=replace(Image, \"a\", \"b\") | where Image=\"b\"", ""},
		{"`sysmon` EventCode=1 | eval x=replace(Image, \"a\", \"b\") | where x=\"b\"", ""},
		{"`sysmon` EventCode=1 | search Image=\"*\\\\cmd.exe\" NOT User=SYSTEM", ""},
		{"`sysmon` EventCode=1 | rex field=CommandLine mode=sed \"s/a/b/g\" | where CommandLine=\"b\"", ""},
		{"`sysmon` EventCode=1 | where len(CommandLine) > 100", "no events"},
		{"`sysmon` EventCode=1 | stats count by dest | search dest IN (a, b) OR dest=c", "no events"},
		{"`sysmon` EventCode=1 | iplocation dest | where Country=\"RU\"", "no events"},
		{"`wineventlog_security` EventCode=4688 EventCode=4689", "must name its event code once"},
	} {
		r, err := Parse(rule(c.search), testMacros)
		if c.want != "" && c.want != "no events" {
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
		if c.want == "no events" {
			if pos != 0 || !strings.HasPrefix(NoEventsReason(r, cases), "no test events") {
				t.Errorf("%s: %d positive cases, reason %q", c.search, pos, NoEventsReason(r, cases))
			}
			continue
		}
		if pos == 0 {
			t.Errorf("%s: no positive case: %s", c.search, NoEventsReason(r, cases))
		}
		for _, cs := range cases {
			doc, _ := Stored(cs)
			if kept := Eval(r.Where, View(doc)) && r.Keeps(doc); kept != cs.Expect {
				t.Errorf("%s: expect %v, kept %v: %v", c.search, cs.Expect, kept, cs.Data)
			}
		}
	}
}
