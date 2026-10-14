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

func TestParseUppercaseAndNotNull(t *testing.T) {
	src := rule("| tstats count FROM datamodel=Endpoint.Registry\n  WHERE Registry.registry_path=\"*\\\\Winlogon*\" Registry.registry_value_name=AutoAdminLogon Registry.registry_value_data=0x00000001\n" +
		"  BY Registry.dest Registry.registry_value_data\n| `drop_dm_object_name(Registry)`\n| where isnotnull(registry_value_data)\n| `test_rule_filter`")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := map[string]string{"registry_path": `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon`, "registry_value_name": "AutoAdminLogon", "registry_value_data": "0x00000001"}
	if !Eval(r.Where, ev) {
		t.Error("does not match its own event")
	}
	// Splunk's Sysmon add-on reads "DWORD (0x00000001)" as 0x00000001.
	if v := View(map[string]any{"registry_value_data": "DWORD (0x00000001)"}); v["registry_value_data"] != "0x00000001" {
		t.Errorf("view = %v", v)
	}
	cases := Cases(r)
	found := false
	for _, c := range cases {
		found = found || c.Expect
	}
	if !found {
		t.Errorf("no test event matches: %+v", cases)
	}
}

func TestParsePowerShell(t *testing.T) {
	src := rule("`powershell` EventCode=4104 ScriptBlockText = \"*ShadowCopy*\" (ScriptBlockText = \"*Delete*\" OR ScriptBlockText = \"*Remove*\")\n" +
		"| fillnull | stats count min(_time) as firstTime BY dest signature\n| rename dest as host | `security_content_ctime(firstTime)` | `test_rule_filter`")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != "PowerShell" {
		t.Fatalf("node %s", r.Node)
	}
	if !Eval(r.Where, map[string]string{"script_block_text": "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject"}) {
		t.Error("does not match its own event")
	}
	if Eval(r.Where, map[string]string{"script_block_text": "Get-WmiObject Win32_ShadowCopy"}) {
		t.Error("matches without Delete or Remove")
	}
	found := false
	for _, c := range Cases(r) {
		found = found || c.Expect
	}
	if !found {
		t.Error("no test event matches")
	}
	for search, want := range map[string]string{
		"`powershell` ScriptBlockText=\"*x*\" | fillnull | stats count by dest":                               "must name its event code",
		"`powershell` EventCode=4103 ScriptBlockText=\"*x*\" | fillnull | stats count by dest":                "must be of event 4104",
		"`powershell` EventCode=4104 ScriptBlockText=\"*x*\" | stats count by dest":                           "later stage",
		"`powershell` EventCode=4104 Path=\"*x*\" | fillnull | stats count by dest":                           "no Signalith mapping",
		"`powershell` EventCode=4104 (ScriptBlockText=\"*x*\" OR EventID=1) | fillnull | stats count by dest": "only be named once",
	} {
		if _, err := Parse(rule(search), nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", search, err, want)
		}
	}
}
