package splcheck

import (
	"strings"
	"testing"
)

// casesOf parses a rule and returns the test events it must find.
func casesOf(t *testing.T, search string) (*Rule, []map[string]string) {
	t.Helper()
	return casesOfSrc(t, rule(search))
}

// casesOfSrc is casesOf of a whole detection.
func casesOfSrc(t *testing.T, src []byte) (*Rule, []map[string]string) {
	t.Helper()
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs := Cases(r)
	var out []map[string]string
	for _, c := range found(cs) {
		out = append(out, c.Data)
	}
	if len(out) == 0 {
		t.Fatalf("no test event is found: %s", NoEventsReason(r, cs))
	}
	if len(found(cs)) == len(cs) {
		t.Error("no test event the rule does not find")
	}
	return r, out
}

// TestCasesFromATie checks a later where that compares two fields gets
// test events where both have the same value.
func TestCasesFromATie(t *testing.T) {
	_, pos := casesOf(t, "| tstats count from datamodel=Endpoint.Processes where Processes.process_name=msbuild.exe by Processes.dest Processes.process Processes.process_path\n"+
		"| `drop_dm_object_name(Processes)`\n| where process=process_path\n| `test_rule_filter`")
	for _, d := range pos {
		if d["CommandLine"] != d["Image"] {
			t.Errorf("command line is not the program: %v", d)
		}
	}
}

// TestCasesFromASearchOfAWord checks a search's bare word is a value, not
// a field to tie: a where compares two fields, a search does not.
func TestCasesFromASearchOfAWord(t *testing.T) {
	src := append(rule("`azure_monitor_aad` operationName=\"Update user\" | rename properties.* as *\n"+
		"| eval propertyName = mvindex('targetResources{}.modifiedProperties{}.displayName',0)\n"+
		"| search propertyName = StrongAuthenticationMethod\n| stats count by user\n| `test_rule_filter`"),
		"data_source:\n  - Azure Active Directory Update user\n"...)
	_, pos := casesOfSrc(t, src)
	for _, d := range pos {
		if !strings.Contains(d["properties.targetResources"], `"displayName":"StrongAuthenticationMethod"`) {
			t.Errorf("event %v", d)
		}
	}
}

// TestCasesFromAnIfTest checks the test of an eval's if(), which a later
// where keeps the value of, is a test the event passes: here the program's
// command line holds its parent's.
func TestCasesFromAnIfTest(t *testing.T) {
	_, pos := casesOf(t, "| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe Processes.process=\"* /c *\" by Processes.dest Processes.process Processes.parent_process\n"+
		"| `drop_dm_object_name(Processes)`\n| eval result = if(like(process,\"%\".parent_process.\"%\"), \"Found\", \"Not Found\")\n"+
		"| where result = \"Found\"\n| `test_rule_filter`")
	for _, d := range pos {
		if !strings.Contains(d["CommandLine"], d["ParentCommandLine"]) {
			t.Errorf("the command line does not hold the parent's: %v", d)
		}
	}
}

// TestCasesFromPieces checks a count of a value's pieces and a test of one
// of them get a value with that many pieces.
func TestCasesFromPieces(t *testing.T) {
	_, pos := casesOf(t, "| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_name=\"*.exe\" by Filesystem.dest Filesystem.file_path\n"+
		"| `drop_dm_object_name(Filesystem)`\n| eval parts = split(file_path, \"\\\\\")\n| eval n = mvcount(parts)\n| eval drive = mvindex(parts, 0)\n"+
		"| where like(drive, \"%:\") AND n = 2 AND drive != \"C:\"\n| `test_rule_filter`")
	for _, d := range pos {
		p := strings.Split(d["TargetFilename"], `\`)
		if len(p) != 2 || !strings.HasSuffix(p[0], ":") || p[0] == "C:" {
			t.Errorf("file path %q", d["TargetFilename"])
		}
	}
	_, pos = casesOf(t, "| tstats count from datamodel=Endpoint.Processes where Processes.process_name=curl.exe Processes.process=\"* -o *\" by Processes.dest Processes.process\n"+
		"| `drop_dm_object_name(Processes)`\n| eval percent_count = mvcount(split(process, \"%\")) - 1\n| where percent_count >= 3\n| `test_rule_filter`")
	for _, d := range pos {
		if strings.Count(d["CommandLine"], "%") < 3 || !strings.Contains(d["CommandLine"], " -o ") {
			t.Errorf("command line %q", d["CommandLine"])
		}
	}
}

// TestCasesFromARexOfTheValue checks a rex group a later stage tests is
// added to the value the where clause makes, which keeps its own tests.
func TestCasesFromARexOfTheValue(t *testing.T) {
	_, pos := casesOf(t, "| tstats count from datamodel=Endpoint.Processes where Processes.process_name=icacls.exe Processes.process=\"*/grant*\" by Processes.dest Processes.process\n"+
		"| `drop_dm_object_name(Processes)`\n| rex field=process \":\\\\((?<permission>[^)]+)\\\\)\"\n"+
		"| eval has_read=if(match(permission, \"R\"), \"true\", \"false\")\n| where has_read=\"true\"\n| `test_rule_filter`")
	for _, d := range pos {
		if !strings.Contains(d["CommandLine"], "/grant") || !strings.Contains(d["CommandLine"], ":(R") {
			t.Errorf("command line %q", d["CommandLine"])
		}
	}
}

// TestCasesFromAuditdHost checks a later stats by host, which no auditd
// record names itself, groups by the host the record came from rather
// than a copy of a record field that is never set.
func TestCasesFromAuditdHost(t *testing.T) {
	r, _ := casesOfSrc(t, append(rule("`linux_auditd` (type=PATH OR type=CWD)\n| rex \"msg=audit\\([^)]*:(?<audit_id>\\d+)\\)\"\n"+
		"| stats values(type) as types values(name) as names values(nametype) as nametype values(cwd) as cwd_list values(_time) as event_times by audit_id, host\n"+
		"| eval current_working_directory = coalesce(mvindex(cwd_list, 0), \"N/A\")\n"+
		"| eval candidate_paths = mvmap(names, if(match(names, \"^/\"), names, current_working_directory + \"/\" + names))\n"+
		"| eval matched_paths = mvfilter(match(candidate_paths, \"/etc/sudoers.*\"))\n| eval match_count = mvcount(matched_paths)\n"+
		"| eval reconstructed_path = mvindex(matched_paths, 0)\n| eval e_time = mvindex(event_times, 0)\n"+
		"| where match_count > 0\n| rename host as dest\n"+
		"| stats count min(e_time) as firstTime max(e_time) as lastTime values(nametype) as nametype by current_working_directory reconstructed_path match_count dest audit_id\n"+
		"| `test_rule_filter`"), "data_source:\n  - Linux Auditd Path\n  - Linux Auditd Cwd\n"...))
	if strings.Contains(r.Post, "auditd_host") || !strings.Contains(r.Post, "dest=host") {
		t.Errorf("post %s", r.Post)
	}
}

// TestGroupSpanClass checks a group's span skips the ) of a class in it.
func TestGroupSpanClass(t *testing.T) {
	re := `:\((?<p>[^)]+)\)`
	if s, e := groupSpan(re, "p"); s < 0 || re[s:e] != `(?<p>[^)]+)` {
		t.Errorf("span %d %d", s, e)
	}
}

// TestNoEventsReasonNamesTheStage checks the reason names a stats's group
// field no event has.
func TestNoEventsReasonNamesTheStage(t *testing.T) {
	r, err := Parse(rule("| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest Processes.process\n"+
		"| `drop_dm_object_name(Processes)`\n| stats count by dest Group_Name\n| `test_rule_filter`"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := NoEventsReason(r, Cases(r)); !strings.Contains(got, "stats groups by Group_Name") {
		t.Errorf("reason %q", got)
	}
}
