package splcheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// found returns the cases the rule must find.
func found(cases []sigmacheck.Case) []sigmacheck.Case {
	var out []sigmacheck.Case
	for _, c := range cases {
		if c.Expect {
			out = append(out, c)
		}
	}
	return out
}

func TestCasesFromALaterWhere(t *testing.T) {
	// The where clause names net1.exe; the command line comes from the
	// search after the tstats.
	src := rule("| tstats count from datamodel=Endpoint.Processes where Processes.process_name=net1.exe by Processes.dest Processes.process\n" +
		"| `drop_dm_object_name(Processes)`\n| search process IN (\"*share* /delete*\", \"*share* /REMARK:*\")\n| `test_rule_filter`")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	pos := found(Cases(r))
	if len(pos) == 0 {
		t.Fatal("no test event is found")
	}
	for _, c := range pos {
		if !strings.Contains(strings.ToLower(c.Data["CommandLine"]), "share") {
			t.Errorf("found without the later where's command line: %v", c.Data)
		}
	}
}

func TestCasesFromALaterRexAndMatch(t *testing.T) {
	src := rule("| tstats count from datamodel=Endpoint.Processes where Processes.process_name=bash Processes.process=\"*|*\" by Processes.dest Processes.process\n" +
		"| `drop_dm_object_name(Processes)`\n| rex field=process \"base64\\s+(?<decode_flag>-{1,2}d\\w*)\"\n| where isnotnull(decode_flag)\n| `test_rule_filter`")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	pos := found(Cases(r))
	if len(pos) == 0 {
		t.Fatal("no test event is found")
	}
	for _, c := range pos {
		if !strings.Contains(c.Data["CommandLine"], "base64") {
			t.Errorf("found without base64 -d: %v", c.Data)
		}
	}
}

func TestCasesOutsideSystem32(t *testing.T) {
	// The rule names sfc.exe and leaves out the system folders, where a
	// test event's program is by default.
	src := rule("| tstats count from datamodel=Endpoint.Processes where Processes.process_name=sfc.exe Processes.process=\"* -k*\" NOT Processes.process_path IN (\"*:\\\\Windows\\\\System32\\\\*\", \"*:\\\\Windows\\\\SysWOW64\\\\*\") by Processes.dest")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	pos := found(Cases(r))
	if len(pos) == 0 {
		t.Fatal("no test event is found")
	}
	for _, c := range pos {
		if img := strings.ToLower(c.Data["Image"] + c.Data["NewProcessName"]); strings.Contains(img, `\system32\`) || !strings.HasSuffix(img, `\sfc.exe`) {
			t.Errorf("image %v", c.Data)
		}
	}
}

func TestCasesWithPatternsInEitherOrder(t *testing.T) {
	// A folder and a file name of one field: the folder comes first.
	src := rule("`sysmon` EventCode=11 (TargetFilename = \"*\\\\sqlite32.dll\" OR TargetFilename = \"*\\\\sqlite64.dll\") (TargetFilename = \"*\\\\temp\\\\*\") | stats count by dest file_path | `test_rule_filter`")
	r, err := Parse(src, testMacros)
	if err != nil {
		t.Fatal(err)
	}
	pos := found(Cases(r))
	if len(pos) == 0 {
		t.Fatal("no test event is found")
	}
	for _, c := range pos {
		f := strings.ToLower(c.Data["TargetFilename"])
		if !strings.Contains(f, `\temp\`) || !strings.HasSuffix(f, ".dll") {
			t.Errorf("file %s", c.Data["TargetFilename"])
		}
	}
}

func TestHintsSkipNegatedAndSedTests(t *testing.T) {
	r := &Rule{Post: "eval ScriptBlockText=script_block_text\n| rex mode=sed field=x \"s/a/b/g\"\n| where NOT match(ScriptBlockText, \"bad\")\n| where match(ScriptBlockText, \"(?i)virtualalloc\")"}
	hs := r.hints()
	if len(hs) != 1 {
		t.Fatalf("hints %#v", hs)
	}
	c := hs[0].(*Cmp)
	if c.Field != "script_block_text" || !c.Regex || c.Values[0] != "(?i)virtualalloc" {
		t.Errorf("hint %#v", c)
	}
}

func TestPermutations(t *testing.T) {
	ps := permutations(3)
	seen := map[string]bool{}
	for _, p := range ps {
		seen[fmt.Sprint(p)] = true
	}
	if len(ps) != 6 || len(seen) != 6 || fmt.Sprint(ps[0]) != "[0 1 2]" {
		t.Errorf("permutations %v", ps)
	}
}
