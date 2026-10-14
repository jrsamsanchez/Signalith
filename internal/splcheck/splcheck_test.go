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
		"`sysmon` EventCode=10 | stats count":                                                                              "besides its event code",
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
	if !Eval(r.Where, map[string]string{"signature_id": "4104", "script_block_text": "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject"}) {
		t.Error("does not match its own event")
	}
	if Eval(r.Where, map[string]string{"signature_id": "4104", "script_block_text": "Get-WmiObject Win32_ShadowCopy"}) {
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
		"`powershell` EventCode=4103 ScriptBlockText=\"*x*\" | fillnull | stats count by dest":                "event 4103 is not supported",
		"`powershell` EventCode=4104 ScriptBlockText=\"*x*\" | eval x=1 | stats count by dest":                "later stage",
		"`powershell` EventCode=4104 Path=\"*x*\" | fillnull | stats count by dest":                           "no Signalith mapping",
		"`powershell` EventCode=4104 (ScriptBlockText=\"*x*\" OR EventID=1) | fillnull | stats count by dest": "once, at the top",
	} {
		if _, err := Parse(rule(search), nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", search, err, want)
		}
	}
}

// Splunk's search syntax evaluates OR before AND, so "a b OR c" is
// a AND (b OR c).
func TestOrBeforeAnd(t *testing.T) {
	e, err := ParseWhere(`Processes.process_name != "*temp.dat*" Processes.process = "*runrun*" OR Processes.process = "*temp.dat*"`, "Processes", nil)
	if err != nil {
		t.Fatal(err)
	}
	if Eval(e, map[string]string{"process_name": "temp.dat.exe", "process": "temp.dat.exe /x"}) {
		t.Error("the OR side ignores the != before it")
	}
	if !Eval(e, map[string]string{"process_name": "x.exe", "process": "x.exe temp.dat"}) {
		t.Error("does not match the second OR side")
	}
}

// An unquoted value reads \\ as one backslash, as a quoted one does.
func TestUnquotedBackslash(t *testing.T) {
	e, err := ParseWhere(`Processes.process=*\\users\\public\\* Processes.process_name="*\\\\*"`, "Processes", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !Eval(e, map[string]string{"process": `schtasks /create /tr C:\Users\Public\a.exe`, "process_name": `\\host\x`}) {
		t.Errorf("does not match single backslashes: %#v", e)
	}
}

func TestParseScheduledTask(t *testing.T) {
	src := rule("`wineventlog_security` EventCode=4698 TaskContent = \"*&lt;Hidden&gt;true&lt;/Hidden&gt;*\"\n| stats count by TaskName TaskContent dest")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != "TaskCreated" {
		t.Fatalf("node %s", r.Node)
	}
	if !Eval(r.Where, map[string]string{"signature_id": "4698", "task_content": "<Task><Hidden>true</Hidden></Task>"}) {
		t.Error("does not match the stored XML")
	}
	found := false
	for _, c := range Cases(r) {
		found = found || c.Expect
	}
	if !found {
		t.Error("no test event matches")
	}
}

func TestParseScheduledTaskXMLKV(t *testing.T) {
	src := rule("`wineventlog_security` EventCode=4698 | xmlkv Message | search Command IN (\"*rundll32*\")\n| stats count by dest Task_Name Command")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !Eval(r.Where, map[string]string{"signature_id": "4698", "task_command": `C:\Windows\System32\rundll32.exe`}) {
		t.Error("does not match its own event")
	}
	for search, want := range map[string]string{
		"`wineventlog_security` EventCode=4698 Command=\"*x*\" | stats count by dest":                      "no Signalith mapping",
		"`sysmon` EventCode=10 | xmlkv Message | search Command=\"*x*\" | stats count by dest":             "xmlkv on ProcessAccess",
		"`wineventlog_security` EventCode=4698 | xmlkv Message | search EventCode=1 | stats count by dest": "once, at the top",
	} {
		if _, err := Parse(rule(search), nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", search, err, want)
		}
	}
}

func TestParseObjectAccess(t *testing.T) {
	src := rule("`wineventlog_security` EventCode=4663 object_file_path=\"*\\\\WinSCP 2\\\\Configuration\\\\Security*\" NOT process_path IN (\"*\\\\WinSCP.exe\")\n| stats count by object_file_path process_path dest")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != "ObjectAccess" || !InModel(r.Node, "Registry") || !InModel(r.Node, "Filesystem") || InModel(r.Node, "Endpoint") {
		t.Fatalf("node %s", r.Node)
	}
	ev := map[string]string{"signature_id": "4663", "object_path": `\REGISTRY\USER\S-1-5-21-1\Software\Martin Prikryl\WinSCP 2\Configuration\Security`, "process_path": `C:\x\stealer.exe`}
	if !Eval(r.Where, ev) {
		t.Error("does not match its own event")
	}
	found := false
	for _, c := range Cases(r) {
		found = found || c.Expect
	}
	if !found {
		t.Error("no test event matches")
	}
}

func TestParseServiceInstalled(t *testing.T) {
	src := rule("`wineventlog_system` EventCode=7045 ImagePath = \"*.exe\" NOT (ImagePath IN (\"*:\\\\Windows\\\\*\", \"*%systemroot%\\\\*\"))\n| stats count by EventCode ImagePath ServiceName Computer | rename Computer as dest")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != "ServiceInstalled" || !InModel(r.Node, "Change") {
		t.Fatalf("node %s", r.Node)
	}
	if !Eval(r.Where, map[string]string{"signature_id": "7045", "service_path": `C:\Users\Public\svc.exe`}) ||
		Eval(r.Where, map[string]string{"signature_id": "7045", "service_path": `%SystemRoot%\system32\svc.exe`}) {
		t.Error("reads its events wrong")
	}
	pos := 0
	for _, c := range Cases(r) {
		if c.Expect {
			pos++
		}
		if c.Expect != Reads(r, c) {
			t.Errorf("case %+v: Reads disagrees", c)
		}
	}
	if pos == 0 {
		t.Error("no test event matches")
	}
}

func TestParseDirectoryShareAndKerberos(t *testing.T) {
	for src, node := range map[string]string{
		"`wineventlog_security` EventCode=5136 AttributeLDAPDisplayName=sIDHistory OperationType=\"%%14674\"\n| stats values(ObjectDN) as ObjectDN by _time, Computer":      "DirectoryChange",
		"`wineventlog_security` SubjectUserName=\"ANONYMOUS LOGON\" EventCode=5145 RelativeTargetName=lsarpc\n| stats count by dest, ShareName":                             "ShareAccess",
		"`wineventlog_security` EventCode=4732 TargetUserName=DnsAdmins\n| stats count by dest src_user":                                                                    "GroupMemberAdded",
		"`wineventlog_security` EventCode=4738 UserAccountControl=\"*%%2096*\"\n| rename TargetUserName as user\n| stats count by user":                                     "UserChanged",
		"`wineventlog_security` EventCode=4768 TicketEncryptionType=0x17 ServiceName!=*$\n| stats count by ServiceName src_ip dest":                                         "KerberosTGT",
		"`wineventlog_security` EventCode=4769 ServiceName!=\"*$\" (TicketOptions=0x40810000 OR TicketOptions=0x40800000) TicketEncryptionType=0x17\n| stats count by user": "KerberosService",
	} {
		r, err := Parse(rule(src), nil)
		if err != nil {
			t.Fatal(err)
		}
		if r.Node != node {
			t.Fatalf("node %s, want %s", r.Node, node)
		}
		pos := 0
		for _, c := range Cases(r) {
			if c.Expect {
				pos++
			}
			if c.Expect != Reads(r, c) {
				t.Errorf("%s case %+v: Reads disagrees", node, c)
			}
		}
		if pos == 0 {
			t.Errorf("%s: no test event matches", node)
		}
	}
}

func TestParseSysmonAccess(t *testing.T) {
	src := rule("`sysmon` EventCode=10 TargetImage=\"*\\\\lsass.exe\" GrantedAccess IN (\"0x1010\", \"0x1410\") NOT SourceImage=\"*\\\\MsMpEng.exe\"\n| stats count by dest SourceImage")
	r, err := Parse(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != "ProcessAccess" {
		t.Fatalf("node %s", r.Node)
	}
	ev := map[string]string{"signature_id": "10", "target_process_path": `C:\Windows\System32\lsass.exe`, "granted_access": "0x1410", "process_path": `C:\x\procdump.exe`}
	if !Eval(r.Where, ev) {
		t.Error("does not match its own event")
	}
	ev["signature_id"] = "8"
	if Eval(r.Where, ev) {
		t.Error("matches a remote thread event")
	}
	found := false
	for _, c := range Cases(r) {
		found = found || c.Expect
	}
	if !found {
		t.Error("no test event matches")
	}
	if _, err := Parse(rule("`sysmon` EventCode IN (7, 10) ImageLoaded=\"*x*\" | stats count by dest"), nil); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("mixed events: err = %v", err)
	}
}
