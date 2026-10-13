package splcheck

import (
	"strings"
	"testing"
)

var testMacros = map[string]*Macro{
	"process_reg": {Name: "process_reg", Definition: `(Processes.process_name=reg.exe OR Processes.original_file_name=reg.exe)`},
}

func rule(search string) []byte {
	return []byte("name: Test rule\nid: 11111111-2222-3333-4444-555555555555\ntype: TTP\nstatus: production\nsearch: |\n" +
		indent(search) + "\n")
}

func indent(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return strings.Join(lines, "\n")
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		p, s string
		want bool
	}{
		{`*\reg.exe`, `C:\Windows\System32\REG.EXE`, true},
		{`*add*`, `reg add hklm`, true},
		{`reg.exe`, `xreg.exe`, false},
		{`a?c`, `abc`, false}, // ? is literal in Splunk
		{`a?c`, `a?c`, true},
		{`*`, ``, true},
		{`* C:\Windows\*`, `x C:\Windows\y`, true},
		{`* C:\Windows\*`, `C:\Windows\y`, false},
	} {
		if got := Glob(c.p, c.s); got != c.want {
			t.Errorf("Glob(%q, %q) = %v", c.p, c.s, got)
		}
	}
}

func TestParse(t *testing.T) {
	src := rule("| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes where\n" +
		"`process_reg` AND Processes.process IN (\"*add*\", \"*HKCR\\\\*\",)\n" +
		"```a comment with a ` in it```\n" +
		"NOT Processes.user=\"SYSTEM\" Processes.parent_process_name!=explorer.exe\n" +
		"by Processes.dest Processes.user\n| `drop_dm_object_name(Processes)`\n| `security_content_ctime(firstTime)`\n| `test_rule_filter`")
	r, err := Parse(src, testMacros)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != "Processes" {
		t.Fatalf("node %s", r.Node)
	}
	match := map[string]string{"process_name": "reg.exe", "process": `reg add HKCR\x`, "user": "alice", "parent_process_name": "cmd.exe"}
	if !Eval(r.Where, match) {
		t.Error("does not match its own event")
	}
	for f, v := range map[string]string{"user": "system", "parent_process_name": "EXPLORER.EXE", "process_name": "cmd.exe"} {
		ev := map[string]string{}
		for k, x := range match {
			ev[k] = x
		}
		ev[f] = v
		if Eval(r.Where, ev) {
			t.Errorf("%s=%s still matches", f, v)
		}
	}
	// != needs the field present, as in Splunk.
	delete(match, "parent_process_name")
	if Eval(r.Where, match) {
		t.Error("!= matched a missing field")
	}
}

func TestParseRefuses(t *testing.T) {
	for search, want := range map[string]string{
		"| tstats count from datamodel=Endpoint.Processes where Processes.process=* by Processes.dest | eval x=1": "later stage",
		"`sysmon` EventCode=10 | stats count":                                                                              "not a tstats",
		"| tstats count from datamodel=Endpoint.Processes where Processes.dest=x by Processes.dest":                        "no Signalith mapping",
		"| tstats count from datamodel=Endpoint.Processes where Filesystem.file_name=x by Processes.dest":                  "not a field of",
		"| tstats count from datamodel=Endpoint.Processes where `nope` by Processes.dest":                                  "not defined",
		"| tstats count from datamodel=Endpoint.Processes where Processes.process_name IN (\"a\" \"b\") by Processes.dest": "missing )",
		"| tstats count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=1 by All_Traffic.dest":      "not a tstats",
		"| tstats count from datamodel=Endpoint.Processes where Processes.process_id>4 by Processes.dest":                  "not supported",
	} {
		_, err := Parse(rule(search), testMacros)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", search, err, want)
		}
	}
}

func TestCasesAgreeWithTheRule(t *testing.T) {
	src := rule("| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_path IN (\"*\\\\Temp\\\\*\") Filesystem.file_name IN (\"*.exe\", \"*.ps1\") NOT Filesystem.process_name=msiexec.exe by Filesystem.dest")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := Cases(r)
	pos := 0
	for _, c := range cases {
		if c.Expect {
			pos++
			if !strings.Contains(strings.ToLower(c.Data["TargetFilename"]), `\temp\`) {
				t.Errorf("positive outside Temp: %v", c.Data)
			}
		}
	}
	if pos == 0 || pos == len(cases) {
		t.Fatalf("%d positives of %d", pos, len(cases))
	}
}
