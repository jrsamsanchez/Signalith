// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"reflect"
	"testing"
)

func winSecurity(id string, data map[string]string) map[string]any {
	return Normalize("win.events", WinEventRecord(SecurityChannel, id, "DC1", now, data), now).Document()
}

func TestWindowsSecurityPositionalEvents(t *testing.T) {
	// A failed logon whose sub-status is unknown: the status explains it.
	expect(t, winSecurity("4625", map[string]string{"TargetUserName": "bob", "Status": "0xC0000234", "SubStatus": "0x0", "LogonType": "3"}),
		map[string]any{"datamodel": "Authentication", "action": "failure", "reason": "account locked out", "logon_type_name": "network"})

	// A new process whose command line is not audited: the process path.
	expect(t, winSecurity("4688", map[string]string{"NewProcessName": `C:\Windows\cmd.exe`, "ParentProcessName": `C:\Windows\explorer.exe`}),
		map[string]any{"datamodel": "Endpoint", "process": `C:\Windows\cmd.exe`, "process_name": "cmd.exe",
			"parent_process_name": "explorer.exe"})

	expect(t, winSecurity("4706", map[string]string{"DomainName": "partner.example", "DomainSid": "S-1-5-21-9",
		"TdoType": "2", "TdoDirection": "3", "TdoAttributes": "8", "SubjectUserName": "admin", "SubjectDomainName": "CORP"}),
		map[string]any{"datamodel": "Change", "action": "created", "object_category": "domain_trust", "object": "partner.example",
			"object_sid": "S-1-5-21-9", "trust_direction": "3", "user": "admin", "user_domain": "CORP"})

	expect(t, winSecurity("4794", map[string]string{"SubjectUserName": "admin", "Workstation": "DC1"}),
		map[string]any{"datamodel": "Change", "action": "modified", "object": "DSRM Administrator", "user": "admin", "src_host": "DC1"})

	// The named events: NTLM's success and a known failure, and a group
	// deleted or changed.
	expect(t, winSecurity("4776", map[string]string{"TargetUserName": "bob", "Status": "0x0"}),
		map[string]any{"action": "success"})
	expect(t, winSecurity("4776", map[string]string{"TargetUserName": "bob", "Status": "0xC000006A"}),
		map[string]any{"action": "failure", "reason": "bad password"})
	expect(t, winSecurity("4730", map[string]string{"TargetUserName": "Ops", "SubjectUserName": "admin"}),
		map[string]any{"datamodel": "Change", "action": "deleted", "object_category": "group"})
	expect(t, winSecurity("4737", map[string]string{"TargetUserName": "Ops", "SubjectUserName": "admin"}),
		map[string]any{"datamodel": "Change", "action": "modified"})
}

func winSysmon(id string, data map[string]string) map[string]any {
	return Normalize("win.sysmon", WinEventRecord("Microsoft-Windows-Sysmon/Operational", id, "WS1", now, data), now).Document()
}

func TestSysmonBranches(t *testing.T) {
	expect(t, winSysmon("3", map[string]string{"Image": `C:\x.exe`, "Initiated": "true", "DestinationIp": "192.0.2.1"}),
		map[string]any{"datamodel": "Network_Traffic", "direction": "outbound"})
	expect(t, winSysmon("3", map[string]string{"Image": `C:\x.exe`, "Initiated": "false"}),
		map[string]any{"direction": "inbound"})
	expect(t, winSysmon("27", map[string]string{"TargetFilename": `C:\t\evil.exe`, "Hashes": "MD5=AA,SHA256=ABCDEF"}),
		map[string]any{"datamodel": "Filesystem", "action": "blocked", "file_name": "evil.exe", "file_hash": "abcdef"})
	expect(t, winSysmon("13", map[string]string{"EventType": "SetValue", "TargetObject": "Run"}),
		map[string]any{"datamodel": "Registry", "registry_value_name": "Run"})
	for code, want := range map[string]string{"0": "NoError", "9003": "NXDomain", "123": "NXDomain", "9002": "ServFail",
		"9004": "NotImp", "9005": "Refused", "1460": "1460"} {
		if got := dnsStatus(code); got != want {
			t.Errorf("dnsStatus(%s) = %q, want %q", code, got, want)
		}
	}
	if got := parentPath("nobackslash"); got != "" {
		t.Errorf("parentPath = %q", got)
	}
}

func TestTaskElement(t *testing.T) {
	for _, c := range []struct{ task, want string }{
		{"<Exec><Command> C:\\a.exe </Command></Exec>", `C:\a.exe`},
		{"<Exec><Command>a &amp; b</Command>", "a & b"},
		{"<Exec></Exec>", ""},
		{"<Command>never closed", ""},
	} {
		if got := taskElement(c.task, "Command"); got != c.want {
			t.Errorf("taskElement(%q) = %q, want %q", c.task, got, c.want)
		}
	}
}

func TestWindowsEventNames(t *testing.T) {
	names, fields := WindowsEventNames(TaskSchedulerChannel, "", "141")
	if !reflect.DeepEqual(names, []string{"TaskName", "UserName"}) || len(fields) != 2 {
		t.Errorf("task scheduler 141 = %v %v", names, fields)
	}
	names, fields = WindowsEventNames(SystemChannel, "Application Popup", "26")
	if len(names) == 0 || len(names) != len(fields) {
		t.Errorf("application popup 26 = %v %v", names, fields)
	}
	for i, f := range fields {
		if want, _ := SystemDataField(names[i]); f != want {
			t.Errorf("%s stored as %s, want %s", names[i], f, want)
		}
	}
	if names, _ := WindowsEventNames(SystemChannel, "", "7045"); names != nil {
		t.Errorf("a service install is read by position: %v", names)
	}
	if names, _ := WindowsEventNames("Other", "", "1"); names != nil {
		t.Errorf("an unknown channel: %v", names)
	}
	if s := WindowsSecurityNames("4794"); len(s) != 5 || s[4] != "Workstation" {
		t.Errorf("WindowsSecurityNames(4794) = %v", s)
	}
	if s, ok := windowsSchemaFor(PowerShellChannel, "", "4104"); !ok || len(s) == 0 {
		t.Errorf("script block schema = %v %v", s, ok)
	}
	// No provider means the Service Control Manager.
	a, okA := systemEventFor("", "7036")
	b, okB := systemEventFor(ServiceControlManager, "7036")
	if okA != okB || !reflect.DeepEqual(a, b) {
		t.Errorf("systemEventFor without a provider = %v %v, want %v %v", a, okA, b, okB)
	}
}

// WinEventRecord writes a Defender event's data under its labels, and a
// System event's binary data.
func TestWinEventRecordShapes(t *testing.T) {
	r := WinEventRecord(DefenderChannel, "1116", "WS1", now, map[string]string{"Threat Name": "EICAR", "Unlabelled": "x"})
	msg, _ := r["Message"].(string)
	if want := "Microsoft Defender Antivirus event 1116:\n"; len(msg) < len(want) || msg[:len(want)] != want {
		t.Errorf("Defender message = %q", msg)
	}
	if !containsLine(msg, "Unlabelled: x") {
		t.Errorf("Defender message lacks the unlabelled value: %q", msg)
	}
	r = WinEventRecord(SystemChannel, "7036", "WS1", now, map[string]string{"param1": "Spooler", "Binary": "5300"})
	if r["Binary"] != "5300" || r["ProviderName"] != ServiceControlManager {
		t.Errorf("System record = %v", r)
	}
	r = WinEventRecord(SystemChannel, "1", "WS1", now, map[string]string{"Provider_Name": "Other", "b": "2", "a": "1"})
	if got := r["StringInserts"].([]any); !reflect.DeepEqual(got, []any{"1", "2"}) {
		t.Errorf("unknown event inserts = %v", got)
	}
}

func containsLine(s, line string) bool {
	for len(s) > 0 {
		i := 0
		for i < len(s) && s[i] != '\n' {
			i++
		}
		if s[:i] == line {
			return true
		}
		if i == len(s) {
			break
		}
		s = s[i+1:]
	}
	return false
}
