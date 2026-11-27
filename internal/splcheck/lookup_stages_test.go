// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"strings"
	"testing"
)

// A lookup's outputs may hold several values, or values with spaces
// Splunk keeps; later stages that read them that way are refused, and
// those that only test for them, count by them or show them are not.
func TestLookupLaterStages(t *testing.T) {
	lookups := testLookups(t,
		[2]string{pipesMeta, pipesCSV},
		[2]string{"name: exact\nlookup_type: csv\n", "pipe,tool,note\na,A,x\nb,B,\nb,C,y\n"},
		[2]string{"name: one\nlookup_type: csv\nmax_matches: 1\n", "pipe,tool,note\na,A,x\nb,B,\n"},
		[2]string{"name: padded\nlookup_type: csv\n", "pipe,tool\na, A \nb,B\n"},
		[2]string{"name: dflt\nlookup_type: csv\ndefault_match: none\n", "pipe,tool\na,A\n"},
	)
	for _, c := range []struct{ search, want string }{
		{`| lookup exact pipe AS pipe_name OUTPUT tool | where isnotnull(tool)`, ``},
		{`| lookup exact pipe AS pipe_name | where isnotnull(tool)`, ``},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | where tool="A"`, `lookup exact can give several values`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | search tool=A`, `lookup exact can give several values`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | where tool IN ("A", "B")`, `lookup exact can give several values`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | search tool IN (A, B)`, `lookup exact can give several values`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | stats values(tool) as tools by dest`, ``},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | stats count by tool`, ``},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | stats dc(tool) as n by dest`, `lookup exact can give several values`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | eval t=lower(tool)`, `lookup exact can give several values`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | eval tool=mvjoin(tool, ",")`, `lookup exact can give several values`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | table dest tool`, ``},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | fields - tool`, ``},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | where len(tool) > 1`, `lookup exact can give several values`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | where NOT isnull(tool)`, ``},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | rename tool as t`, `lookup exact can give several values`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | where (`, `unexpected end of query`},
		{`| lookup one pipe AS pipe_name OUTPUT tool note | where isnotnull(tool)`, ``},
		{`| lookup one pipe AS pipe_name OUTPUT tool | where isnotnull(tool)`, ``},
		{`| lookup padded pipe AS pipe_name OUTPUT tool | where tool="A"`, `Splunk keeps and Signalith does not`},
		{`| lookup padded pipe AS pipe_name OUTPUT tool | where isnotnull(tool)`, ``},
		{`| lookup dflt pipe AS pipe_name OUTPUTNEW tool | where isnotnull(tool)`, ``},
		{`| lookup dflt pipe AS pipe_name OUTPUT tool | where isnotnull(tool)`, ``},
		{`| lookup exact pipe AS pipe_name OUTPUT tool AS pipe_name | where isnotnull(pipe_name)`, `it also reads`},
		{`| lookup exact pipe AS dest OUTPUT tool | where isnotnull(tool)`, ``},
		{`| lookup exact pipe AS pipe_name OUTPUT tool AS count | where count > 1`, `an earlier stage sets`},
		{`| lookup exact pipe AS pipe_name, tool AS dest OUTPUT note | where isnotnull(note)`, ``},
		{`| lookup exact nope AS pipe_name OUTPUT tool | where isnotnull(tool)`, `lookup exact has no column nope`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | where isnotnull(tool) | lookup exact pipe AS tool OUTPUT note`, ``},
		{`| lookup nosuch pipe AS pipe_name OUTPUT tool`, `lookup nosuch, a table security_content does not ship`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool |`, ``},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | where tool=dest`, `lookup exact can give several values`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | eval x=if(tool="A", 1, 0) | where x=1`, `lookup exact can give several values`},
		{`| lookup exact pipe AS pipe_name OUTPUT tool | where match(tool, "A")`, `lookup exact can give several values`},
		{`| lookup pipes pipe AS pipe_name OUTPUT tool | stats values(tool) as t by dest`, ``},
		{`| lookup pipes pipe AS pipe_name OUTPUT tool | eval n=mvcount(tool)`, `lookup pipes can give several values`},
		{`| lookup pipes pipe AS pipe_name OUTPUT tool | table tool`, ``},
		{`| lookup pipes pipe AS pipe_name OUTPUT tool | where isnull(tool)`, ``},
		{`| lookup pipes pipe AS pipe_name OUTPUT tool | search tool=PsExec`, `lookup pipes can give several values`},
		{`| lookup pipes pipe AS pipe_name OUTPUT tool | stats count by dest`, ``},
	} {
		src := rule("`sysmon` EventCode=17 | stats count by dest pipe_name " + c.search)
		_, err := ParseWith(src, testMacros, ParseOptions{Lookups: lookups})
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.search, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want %q", c.search, err, c.want)
		}
	}
}
