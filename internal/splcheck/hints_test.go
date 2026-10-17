package splcheck

import (
	"fmt"
	"regexp"
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

// A number a later where compares a rex's group with is a hint of the
// rex's field: the pattern with that number for the group.
func TestHintsOfARexGroupsNumber(t *testing.T) {
	r, err := Parse(rule("`wineventlog_security` EventCode=4723 TargetSid IN (\"*500*\", \"*512*\")\n"+
		"| rex field=TargetSid \"-(?<target_rid>\\d+)$\"\n| rex field=SubjectUserSid \"-(?<subject_rid>\\d+)$\"\n"+
		"| where tonumber(target_rid)=500 OR tonumber(target_rid) IN (512)\n| where tonumber(subject_rid) >= 1000\n| where subject_rid != target_rid\n"+
		"| stats count by dest TargetSid SubjectUserSid"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var vals []string
	for _, h := range r.hints() {
		if c := h.(*Cmp); c.Regex && !strings.Contains(c.Values[0], "<") {
			vals = append(vals, c.Field+" "+c.Values[0])
		}
	}
	if want := `object_sid -(?:500)$, object_sid -(?:512)$, user_sid -(?:1000)$`; strings.Join(vals, ", ") != want {
		t.Errorf("hints %v, want %s", vals, want)
	}
	pos := found(Cases(r))
	if len(pos) == 0 {
		t.Fatal("no test event is found")
	}
	for _, c := range pos {
		if !regexp.MustCompile(`-(500|512)$`).MatchString(c.Data["TargetSid"]) {
			t.Errorf("found with target %s", c.Data["TargetSid"])
		}
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
