package ingest

import (
	"fmt"
	"strings"
	"testing"
)

// defenderRecord is a winevtlog record from the Defender channel.
func defenderRecord(id, msg string, ins ...string) map[string]any {
	r := map[string]any{
		"Channel": DefenderChannel, "Computer": "ws-fin-07.corp.example", "EventID": id,
		"ProviderName": "Microsoft-Windows-Windows Defender", "TimeCreated": "2026-10-11 09:14:02 +0000",
		"Message": msg,
	}
	if ins != nil {
		raw := make([]any, len(ins))
		for i, s := range ins {
			raw[i] = s
		}
		r["StringInserts"] = raw
	}
	return r
}

func defender(t *testing.T, id, msg string, ins ...string) (Event, map[string]any) {
	t.Helper()
	ev := Normalize("win.events", defenderRecord(id, msg, ins...), now)
	return ev, ev.Document()
}

const msg1116 = "Microsoft Defender Antivirus has detected malware or other potentially unwanted software.\r\n" +
	" For more information please see the following:\r\n" +
	"https://go.microsoft.com/fwlink/?linkid=37020&name=HackTool:Win32/Mimikatz.D&threatid=2147729891&enterprise=1\r\n" +
	" \tName: HackTool:Win32/Mimikatz.D\r\n" +
	" \tID: 2147729891\r\n" +
	" \tSeverity: High\r\n" +
	" \tCategory: Tool\r\n" +
	" \tPath: file:_C:\\Users\\alice.nguyen\\AppData\\Local\\Temp\\m.exe\r\n" +
	" \tDetection Origin: Local machine\r\n" +
	" \tDetection Type: Concrete\r\n" +
	" \tDetection Source: Real-Time Protection\r\n" +
	" \tUser: CORP\\alice.nguyen\r\n" +
	" \tProcess Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\n" +
	" \tSecurity intelligence Version: AV: 1.419.2361.0, AS: 1.419.2361.0, NIS: 1.419.2361.0\r\n" +
	" \tEngine Version: AM: 1.1.24090.11, NIS: 1.1.24090.11\r\n"

const msg1121 = "Microsoft Defender Exploit Guard has blocked an operation that is not allowed by your IT administrator.\n" +
	" \tID: D4F940AB-401B-4EFC-AADC-AD5F3C50688A\n" +
	" \tDetection time: 2026-10-11T15:31:12.204Z\n" +
	" \tUser: CORP\\pmorris\n" +
	" \tPath: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n" +
	" \tProcess Name: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\n" +
	" \tTarget Commandline: powershell.exe -nop -w hidden -enc SQBFAFgA\n"

func msg5007(oldValue, newValue string) string {
	return "Microsoft Defender Antivirus Configuration has changed. If this is an unexpected event you should review the settings as this may be the result of malware.\n" +
		" \tOld value: " + oldValue + "\n" +
		" \tNew value: " + newValue + "\n"
}

func TestDefenderThreat(t *testing.T) {
	ev, d := defender(t, "1116", msg1116)
	if ev.Model != "Malware" {
		t.Fatalf("model %s", ev.Model)
	}
	expect(t, d, map[string]any{
		"type": "threat", "action": "detected", "signature": "HackTool:Win32/Mimikatz.D", "signature_id": "1116",
		"threat_id": "2147729891", "category": "hacktool", "severity": "high", "vendor_severity": "High", "vendor_category": "Tool",
		"file_path": `C:\Users\alice.nguyen\AppData\Local\Temp\m.exe`, "file_name": "m.exe",
		"user": `CORP\alice.nguyen`, "process_name": "powershell.exe",
		"process_path":      `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"signature_version": "1.419.2361.0", "engine_version": "1.1.24090.11", "detection_source": "Real-Time Protection",
		"host": "ws-fin-07.corp.example", "dest": "ws-fin-07.corp.example",
		"vendor_product": "Microsoft Defender Antivirus", "sourcetype": "WinEventLog:Microsoft-Windows-Windows Defender/Operational",
	})
	if d["url"] != nil {
		t.Errorf("the FWLink line gave url %v", d["url"])
	}
	if !strings.Contains(d["message"].(string), "Mimikatz") {
		t.Error("message lost")
	}

	_, d = defender(t, "1118", msg1116+" \tAction: Remove\r\n \tError Code: 0x80508023\r\n \tError description: The process cannot access the file because it is being used by another process.\r\n")
	expect(t, d, map[string]any{"type": "threat", "action": "failed", "vendor_action": "Remove",
		"reason": "The process cannot access the file because it is being used by another process."})
}

func TestDefenderEveryEventID(t *testing.T) {
	threat := msg1116
	for _, c := range []struct {
		id, msg, typ, action, sig string
	}{
		{"1006", threat, "threat", "detected", "HackTool:Win32/Mimikatz.D"},
		{"1116", threat, "threat", "detected", "HackTool:Win32/Mimikatz.D"},
		{"1015", threat, "threat", "detected", "HackTool:Win32/Mimikatz.D"},
		{"1007", threat + "Action: Quarantine\n", "threat", "quarantined", "HackTool:Win32/Mimikatz.D"},
		{"1117", threat + "Action: Remove\n", "threat", "deleted", "HackTool:Win32/Mimikatz.D"},
		{"1008", threat, "threat", "failed", "HackTool:Win32/Mimikatz.D"},
		{"1118", threat, "threat", "failed", "HackTool:Win32/Mimikatz.D"},
		{"1119", threat, "threat", "failed", "HackTool:Win32/Mimikatz.D"},
		{"1009", threat, "threat", "restored", "HackTool:Win32/Mimikatz.D"},
		{"1121", msg1121, "rule", "blocked", "Office app started a child process"},
		{"1122", msg1121, "rule", "audited", "Office app started a child process"},
		{"1123", "Path: D:\\Shares\\Finance\\a.xlsx\n", "rule", "blocked", "Controlled folder access"},
		{"1124", "Path: D:\\Shares\\Finance\\a.xlsx\n", "rule", "audited", "Controlled folder access"},
		{"1127", "Path: D:\\Shares\\Finance\\a.xlsx\n", "rule", "blocked", "Controlled folder access"},
		{"1128", "Path: D:\\Shares\\Finance\\a.xlsx\n", "rule", "audited", "Controlled folder access"},
		{"1126", "Path: https://bad.example/x\n", "rule", "blocked", "Network protection"},
		{"1125", "Path: https://bad.example/x\n", "rule", "audited", "Network protection"},
		{"2000", "Current security intelligence Version: 1.419.2361.0\n", "health", "updated", "Antivirus definitions updated"},
		{"2002", "Current Engine Version: 1.1.24090.11\n", "health", "updated", "Antivirus engine updated"},
		{"2001", "Error description: The client could not connect to the update source.\n", "health", "update_failed", "Definitions update failed"},
		{"2003", "", "health", "update_failed", "Engine update failed"},
		{"2004", "", "health", "update_failed", "Definitions failed to load"},
		{"2006", "", "health", "update_failed", "Platform update failed"},
		{"3002", "", "health", "engine_failed", "Real-time protection failed"},
		{"5008", "", "health", "engine_failed", "Antivirus engine failed"},
		{"5000", "", "health", "enabled", "Real-time protection turned on"},
		{"5001", "", "health", "disabled", "Real-time protection turned off"},
		{"5009", "", "health", "enabled", "Malware scanning turned on"},
		{"5010", "", "health", "disabled", "Malware scanning turned off"},
		{"5011", "", "health", "enabled", "Virus scanning turned on"},
		{"5012", "", "health", "disabled", "Virus scanning turned off"},
		{"5004", "Feature Name: Behavior monitoring\n", "health", "modified", "Real-time protection setting changed"},
		{"5007", msg5007("", `HKLM\SOFTWARE\Microsoft\Windows Defender\Scan\AvgCPULoadFactor = 0x32`), "health", "modified", "Antivirus setting changed"},
		{"5013", `Value: HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1` + "\n", "health", "tamper_blocked", "Tamper protection blocked a change"},
		{"1150", "Platform version: 4.18.24090.11\n", "health", "status", "Antivirus is running"},
		{"1151", "Last AV security intelligence age: 0\n", "health", "status", "Antivirus health report"},
	} {
		ev, d := defender(t, c.id, c.msg)
		if ev.Model != "Malware" || d["type"] != c.typ || d["action"] != c.action || d["signature"] != c.sig || d["signature_id"] != c.id {
			t.Errorf("%s: model %s type %v action %v signature %v id %v", c.id, ev.Model, d["type"], d["action"], d["signature"], d["signature_id"])
		}
		if !ValidMalwareAction(c.typ, c.action) {
			t.Errorf("%s: %s is not a %s action", c.id, c.action, c.typ)
		}
		if _, ok := d["category"]; ok != (c.typ == "threat") {
			t.Errorf("%s: category %v on a %s event", c.id, d["category"], c.typ)
		}
	}
	// Spot checks of what the labels gave.
	_, d := defender(t, "1126", "Path: https://bad.example/x\n")
	expect(t, d, map[string]any{"url": "https://bad.example/x", "rule": "Network protection"})
	if d["file_path"] != nil {
		t.Errorf("network protection path in file_path")
	}
	_, d = defender(t, "1123", "Process Name: C:\\ProgramData\\SyncSvc\\sync.exe\nPath: D:\\Shares\\Finance\\Q3-forecast.xlsx\n")
	expect(t, d, map[string]any{"file_path": `D:\Shares\Finance\Q3-forecast.xlsx`, "file_name": "Q3-forecast.xlsx", "process_name": "sync.exe", "rule": "Controlled folder access"})
	_, d = defender(t, "2000", "Current security intelligence Version: 1.419.2361.0\nPrevious security intelligence Version: 1.419.2300.0\nCurrent Engine Version: 1.1.24090.11\n")
	expect(t, d, map[string]any{"signature_version": "1.419.2361.0", "engine_version": "1.1.24090.11"})
	_, d = defender(t, "2001", "Error description: The client could not connect to the update source.\n")
	expect(t, d, map[string]any{"reason": "The client could not connect to the update source."})
	_, d = defender(t, "1150", "Platform version: 4.18.24090.11\n")
	expect(t, d, map[string]any{"product_version": "4.18.24090.11"})
	_, d = defender(t, "5004", "Feature Name: Behavior monitoring\n")
	expect(t, d, map[string]any{"setting": "Behavior monitoring"})
	_, d = defender(t, "5013", "Value: HKLM\\X\\DisableRealtimeMonitoring = 0x1\n")
	expect(t, d, map[string]any{"setting": `HKLM\X\DisableRealtimeMonitoring = 0x1`})
}

func TestDefender1117Actions(t *testing.T) {
	for label, want := range map[string]string{"Quarantine": "quarantined", "Allow": "allowed", "User defined": "detected", "No action": "allowed", "Clean": "cleaned", "Block": "blocked"} {
		_, d := defender(t, "1117", msg1116+" \tAction: "+label+"\r\n")
		if d["action"] != want || d["vendor_action"] != label {
			t.Errorf("Action %s: action %v vendor_action %v", label, d["action"], d["vendor_action"])
		}
	}
	_, d := defender(t, "1117", msg1116+" \tAction Name: Quarantine\r\n")
	expect(t, d, map[string]any{"action": "quarantined", "vendor_action": "Quarantine"})
	_, d = defender(t, "1015", strings.ReplaceAll(msg1116, "HackTool:Win32/Mimikatz.D", "Exec:Win32/Odd.A"))
	if d["category"] != "behavior" {
		t.Errorf("1015 category %v", d["category"])
	}
}

func TestDefenderASR(t *testing.T) {
	_, d := defender(t, "1121", msg1121)
	expect(t, d, map[string]any{
		"type": "rule", "action": "blocked", "rule": "Office app started a child process", "signature": "Office app started a child process",
		"rule_id":   "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
		"file_path": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "file_name": "powershell.exe",
		"process_name": "WINWORD.EXE", "process": "powershell.exe -nop -w hidden -enc SQBFAFgA", "user": `CORP\pmorris`,
	})
	_, d = defender(t, "1121", strings.Replace(msg1121, "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "11111111-2222-3333-4444-555555555555", 1))
	expect(t, d, map[string]any{"rule": "Attack surface reduction rule", "rule_id": "11111111-2222-3333-4444-555555555555", "action": "blocked"})
	for guid, name := range defenderASR {
		_, d = defender(t, "1122", "ID: "+strings.ToUpper(guid)+"\n")
		if d["rule"] != name || d["action"] != "audited" {
			t.Errorf("%s: %v %v", guid, d["rule"], d["action"])
		}
	}
}

func TestDefenderExclusions(t *testing.T) {
	const base = `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\`
	for _, c := range []struct{ seg, value, typ string }{
		{"Paths", `C:\ProgramData\SyncSvc`, "path"},
		{"TemporaryPaths", `C:\Temp\x`, "path"},
		{"Extensions", `.ps1`, "extension"},
		{"Processes", `powershell.exe`, "process"},
		{"IpAddresses", `192.0.2.9`, "ip"},
	} {
		v := base + c.seg + `\` + c.value + " = 0x0"
		_, d := defender(t, "5007", msg5007("", v))
		expect(t, d, map[string]any{"type": "health", "action": "exclusion_added", "exclusion": c.value, "exclusion_type": c.typ,
			"signature": "Antivirus exclusion added", "setting": v})
		_, d = defender(t, "5007", msg5007(v, ""))
		expect(t, d, map[string]any{"type": "health", "action": "exclusion_removed", "exclusion": c.value, "exclusion_type": c.typ,
			"signature": "Antivirus exclusion removed"})
	}
	// "Old value:" with nothing after it, as Defender writes it.
	_, d := defender(t, "5007", "Microsoft Defender Antivirus Configuration has changed.\n \tOld value:\n \tNew value: "+base+`Paths\C:\ProgramData\SyncSvc = 0x0`+"\n")
	expect(t, d, map[string]any{"action": "exclusion_added", "exclusion": `C:\ProgramData\SyncSvc`, "exclusion_type": "path"})
	for _, k := range []string{"DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableOnAccessProtection", "DisableScriptScanning", "DisableAntiSpyware", "DisableAntiVirus"} {
		_, d := defender(t, "5007", msg5007("", `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\`+k+" = 0x1"))
		expect(t, d, map[string]any{"action": "disabled", "signature": "Antivirus protection turned off by a setting"})
	}
	_, d = defender(t, "5007", msg5007("", `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x0`))
	expect(t, d, map[string]any{"action": "modified"})

	// Tamper protection: 4 or 0 is off, 5 is on.
	for v, want := range map[string]string{"0x4": "disabled", "0x0": "disabled", "0x5": "modified", "0x40": "modified"} {
		_, d = defender(t, "5007", msg5007(`HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = 0x5`,
			`HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = `+v))
		expect(t, d, map[string]any{"action": want})
	}

	// Group Policy switching its exclusion lists on or off is no exclusion.
	for _, v := range []string{
		`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Paths = 0x1`,
		`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Extensions = 0x0`,
		base + `Paths\ = 0x0`,
		base + `Unknown\C:\x = 0x0`,
	} {
		_, d = defender(t, "5007", msg5007("", v))
		expect(t, d, map[string]any{"action": "modified", "exclusion": nil, "exclusion_type": nil})
	}
}

func TestDefenderHealthReport(t *testing.T) {
	_, d := defender(t, "1151", "Endpoint Protection client health report (time in UTC):\n \tPlatform version: 4.18.24090.11\n \tLast AV security intelligence age: 3\n")
	expect(t, d, map[string]any{"action": "status", "signature": "Antivirus health report", "signature_age_days": int64(3), "product_version": "4.18.24090.11"})
	_, d = defender(t, "1151", "Last AV signature age: 9\n")
	expect(t, d, map[string]any{"action": "outdated", "signature": "Antivirus definitions out of date", "signature_age_days": int64(9)})
	_, d = defender(t, "1151", "Last AV security intelligence age: soon\n")
	expect(t, d, map[string]any{"action": "status", "signature_age_days": nil})
}

func TestDefenderOldLabels(t *testing.T) {
	msg := strings.Replace(msg1116, "Security intelligence Version", "Signature Version", 1)
	_, d := defender(t, "1116", msg)
	expect(t, d, map[string]any{"signature_version": "1.419.2361.0"})
	_, d = defender(t, "2000", "Current Signature Version: 1.419.2400.0\n")
	expect(t, d, map[string]any{"signature_version": "1.419.2400.0"})
}

func TestDefenderResources(t *testing.T) {
	for path, want := range map[string]map[string]any{
		`file:_C:\a\b.exe; file:_C:\c\d.exe`:                                         {"file_path": `C:\a\b.exe`, "file_name": "b.exe"},
		`containerfile:_C:\a\b.zip`:                                                  {"file_path": `C:\a\b.zip`, "file_name": "b.zip"},
		`webfile:_C:\Users\a\x.exe|https://dl.example/x.exe|pid:4120,ProcessStart:1`: {"file_path": `C:\Users\a\x.exe`, "url": "https://dl.example/x.exe", "process_id": int64(4120)},
		`process:_pid:2116,ProcessStart:133000`:                                      {"process_id": int64(2116), "file_path": nil},
		`behavior:_process: C:\x.exe, pid:77:1`:                                      {"process_id": int64(77)},
		`amsi:_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`:            {"process_name": "powershell.exe"},
		`regkey:_HKLM\SOFTWARE\Run\\x`:                                               {"setting": `HKLM\SOFTWARE\Run\\x`},
		`\\file-01\public\Payroll_Update.exe`:                                        {"file_path": `\\file-01\public\Payroll_Update.exe`, "file_name": "Payroll_Update.exe"},
	} {
		_, d := defender(t, "1116", "Name: Trojan:Win32/X\nPath: "+path+"\n")
		expect(t, d, want)
	}
}

func TestDefenderInsertsFallback(t *testing.T) {
	ins := make([]string, 42)
	for i := range ins {
		ins[i] = fmt.Sprint("x", i)
	}
	ins[6], ins[7], ins[9], ins[11] = "2147729891", "HackTool:Win32/Mimikatz.D", "High", "Tool"
	ins[17], ins[18], ins[19] = "Real-Time Protection", `C:\Windows\explorer.exe`, `CORP\alice.nguyen`
	ins[21], ins[30], ins[33] = `file:_C:\Users\a\m.exe`, "Remove", "Access is denied."
	ins[40], ins[41] = "AV: 1.419.2361.0, AS: 1.419.2361.0, NIS: 1.419.2361.0", "AM: 1.1.24090.11, NIS: 1.1.24090.11"
	ev, d := defender(t, "1118", "", ins...)
	if ev.Model != "Malware" {
		t.Fatal(ev.Model)
	}
	expect(t, d, map[string]any{"type": "threat", "action": "failed", "signature": "HackTool:Win32/Mimikatz.D", "threat_id": "2147729891",
		"severity": "high", "category": "hacktool", "detection_source": "Real-Time Protection", "process_name": "explorer.exe",
		"user": `CORP\alice.nguyen`, "file_path": `C:\Users\a\m.exe`, "vendor_action": "Remove", "reason": "Access is denied.",
		"signature_version": "1.419.2361.0", "engine_version": "1.1.24090.11"})

	// Not the expected layout: the inserts are not read.
	bad := append([]string(nil), ins...)
	bad[6] = "abc"
	_, d = defender(t, "1116", "", bad...)
	expect(t, d, map[string]any{"signature": "Unknown threat", "threat_id": nil, "category": "other"})
	_, d = defender(t, "1116", "", ins[:41]...)
	expect(t, d, map[string]any{"signature": "Unknown threat"})
	// Only for 1116 to 1119.
	_, d = defender(t, "1006", "", ins...)
	expect(t, d, map[string]any{"signature": "Unknown threat"})
}

func TestDefenderUnknownIDIsOther(t *testing.T) {
	ev, d := defender(t, "1013", "Microsoft Defender Antivirus has removed history of malware.\n User: CORP\\a\n")
	if ev.Model != "Other" {
		t.Errorf("model %s", ev.Model)
	}
	expect(t, d, map[string]any{"vendor_product": "Microsoft Defender Antivirus", "signature_id": "1013", "type": nil, "action": nil, "host": "ws-fin-07.corp.example"})
	if !strings.Contains(d["message"].(string), "removed history") {
		t.Error("message lost")
	}
}

func TestDefenderMessageCannotNameFields(t *testing.T) {
	ev, d := defender(t, "5001", "datamodel: Risk\nsignalith_sample: x\ntype: health\naction: enabled\nsignature: fake\nhost: other\n")
	if ev.Model != "Malware" {
		t.Fatal(ev.Model)
	}
	expect(t, d, map[string]any{"datamodel": "Malware", "signalith_sample": nil, "type": "health", "action": "disabled",
		"signature": "Real-time protection turned off", "host": "ws-fin-07.corp.example"})
	_, d = defender(t, "1116", "Name: X\ndatamodel: Risk\ntype: rule\nsignalith_sample: s\nAction: none\n")
	expect(t, d, map[string]any{"datamodel": "Malware", "signalith_sample": nil, "type": "threat", "action": "detected"})
}

func TestDefenderMessageLimits(t *testing.T) {
	var b strings.Builder
	for i := range 150 {
		fmt.Fprintf(&b, "Filler %d: x\n", i)
	}
	_, d := defender(t, "1116", "Name: Early.A\n"+b.String()+"User: CORP\\late\n")
	expect(t, d, map[string]any{"signature": "Early.A", "user": nil})

	// Labels past the first 16 KB are not read.
	_, d = defender(t, "1116", strings.Repeat("x", 17<<10)+"\nName: Late.A\n")
	expect(t, d, map[string]any{"signature": "Unknown threat"})

	// Long labels are ignored; a long value is capped.
	_, d = defender(t, "1116", strings.Repeat("n", 49)+": a\nName: "+strings.Repeat("v", 10<<10)+"\n")
	if s, _ := d["signature"].(string); len(s) != MaxValueLen {
		t.Errorf("signature of %d bytes", len(s))
	}
	// The first occurrence of a label wins.
	_, d = defender(t, "1116", "Name: First.A\nName: Second.A\n")
	expect(t, d, map[string]any{"signature": "First.A"})
}
