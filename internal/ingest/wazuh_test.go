package ingest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Wazuh alert fixtures, written to the shape of alerts.json lines as the
// Wazuh documentation shows them (one alert per line on disk).
var wazuhFixtures = map[string]string{
	"sshd_success": `{"timestamp":"2026-10-11T09:15:02.123+0000","rule":{"level":3,"description":"sshd: authentication success.","id":"5715",
		"mitre":{"id":["T1078","T1021"],"tactic":["Defense Evasion","Persistence","Privilege Escalation","Initial Access","Lateral Movement"],"technique":["Valid Accounts","Remote Services"]},
		"firedtimes":1,"mail":false,"groups":["syslog","sshd","authentication_success"],"pci_dss":["10.2.5"],"gdpr":["IV_32.2"]},
		"agent":{"id":"001","name":"web-01","ip":"10.0.0.21"},"manager":{"name":"wazuh-manager"},"id":"1760174102.123456",
		"full_log":"Oct 11 09:15:02 web-01 sshd[2211]: Accepted publickey for deploy from 198.51.100.7 port 50122 ssh2: RSA SHA256:4f1c",
		"predecoder":{"program_name":"sshd","timestamp":"Oct 11 09:15:02","hostname":"web-01"},"decoder":{"parent":"sshd","name":"sshd"},
		"data":{"srcip":"198.51.100.7","srcport":"50122","dstuser":"deploy"},"location":"/var/log/auth.log"}`,

	"sshd_failed": `{"timestamp":"2026-10-11T09:16:40.502+0000","rule":{"level":5,"description":"sshd: authentication failed.","id":"5760",
		"mitre":{"id":["T1110.001","T1021.004"],"tactic":["Credential Access","Lateral Movement"]},"firedtimes":3,"mail":false,
		"groups":["syslog","sshd","authentication_failed"]},"agent":{"id":"001","name":"web-01","ip":"10.0.0.21"},"manager":{"name":"wazuh-manager"},
		"id":"1760174200.4711","full_log":"Oct 11 09:16:40 web-01 sshd[2290]: Failed password for root from 203.0.113.9 port 40022 ssh2",
		"predecoder":{"program_name":"sshd","timestamp":"Oct 11 09:16:40","hostname":"web-01"},"decoder":{"parent":"sshd","name":"sshd"},
		"data":{"srcip":"203.0.113.9","srcport":"40022","dstuser":"root"},"location":"/var/log/auth.log"}`,

	"sshd_bruteforce": `{"timestamp":"2026-10-11T09:17:01.000+0000","rule":{"level":10,"description":"sshd: brute force trying to get access to the system. Authentication failed.","id":"5763",
		"frequency":8,"mitre":{"id":["T1110"],"tactic":["Credential Access"]},"groups":["syslog","sshd","authentication_failures"]},
		"agent":{"id":"001","name":"web-01","ip":"10.0.0.21"},"manager":{"name":"wazuh-manager"},"id":"1760174221.5000",
		"decoder":{"parent":"sshd","name":"sshd"},"data":{"srcip":"203.0.113.9","srcport":"40100","dstuser":"admin"},"location":"/var/log/auth.log"}`,

	"pam_session": `{"timestamp":"2026-10-11T09:20:00.000+0000","rule":{"level":3,"description":"PAM: Login session opened.","id":"5501",
		"groups":["pam","syslog","authentication_success"]},"agent":{"id":"003","name":"jump-01","ip":"10.0.0.5"},"manager":{"name":"wazuh-manager"},
		"id":"1760174400.900","predecoder":{"program_name":"su"},"decoder":{"parent":"pam","name":"pam"},
		"data":{"srcuser":"alice","dstuser":"root","uid":"0"},"location":"journald"}`,

	"sudo": `{"timestamp":"2026-10-11T09:21:00.000+0000","rule":{"level":3,"description":"Successful sudo to ROOT executed.","id":"5402",
		"mitre":{"id":["T1548.003"],"tactic":["Privilege Escalation","Defense Evasion"]},"groups":["syslog","sudo"]},
		"agent":{"id":"003","name":"jump-01","ip":"10.0.0.5"},"manager":{"name":"wazuh-manager"},"id":"1760174460.1001",
		"decoder":{"name":"sudo"},"data":{"srcuser":"alice","dstuser":"root","tty":"pts/0","pwd":"/home/alice","command":"/bin/bash"},"location":"/var/log/auth.log"}`,

	"fim_modified": `{"timestamp":"2026-10-11T09:30:12.345+0000","rule":{"level":7,"description":"Integrity checksum changed.","id":"550",
		"mitre":{"id":["T1565.001"],"tactic":["Impact"]},"groups":["ossec","syscheck","syscheck_entry_modified","syscheck_file"]},
		"agent":{"id":"002","name":"db-01","ip":"10.0.0.31"},"manager":{"name":"wazuh-manager"},"id":"1760175012.2000",
		"full_log":"File '/etc/passwd' modified\nMode: whodata\nChanged attributes: size,mtime,md5,sha1,sha256\n",
		"syscheck":{"path":"/etc/passwd","mode":"whodata","size_before":"2410","size_after":"2471","perm_after":"rw-r--r--","uid_after":"0","gid_after":"0",
			"md5_after":"6c3a3a9a6d0e2c1f0b6a4e7f1c2d3e4f","sha1_after":"0d5f0c2a3b4c5d6e7f8091a2b3c4d5e6f7081920",
			"sha256_after":"9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08","uname_after":"root","gname_after":"root",
			"inode_after":131090,"changed_attributes":["size","mtime","md5","sha1","sha256"],"event":"modified",
			"audit":{"user":{"id":"1000","name":"alice"},"process":{"id":"4321","name":"/usr/bin/vim.basic","ppid":"4100"},"login_user":{"id":"1000","name":"alice"}}},
		"decoder":{"name":"syscheck_integrity_changed"},"location":"syscheck"}`,

	"fim_added": `{"timestamp":"2026-10-11T09:31:00.000+0000","rule":{"level":5,"description":"File added to the system.","id":"554",
		"groups":["ossec","syscheck","syscheck_entry_added","syscheck_file"]},"agent":{"id":"002","name":"db-01","ip":"10.0.0.31"},
		"manager":{"name":"wazuh-manager"},"id":"1760175060.2100",
		"syscheck":{"path":"/var/www/html/shell.php","mode":"realtime","size_after":1337,"sha256_after":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"uname_after":"www-data","event":"added"},"decoder":{"name":"syscheck_new_entry"},"location":"syscheck"}`,

	"fim_deleted_windows": `{"timestamp":"2026-10-11T09:32:00.000+0000","rule":{"level":7,"description":"File deleted.","id":"553",
		"groups":["ossec","syscheck","syscheck_entry_deleted","syscheck_file"]},"agent":{"id":"004","name":"WS-07","ip":"10.0.1.7"},
		"manager":{"name":"wazuh-manager"},"id":"1760175120.2200",
		"syscheck":{"path":"c:\\windows\\system32\\drivers\\etc\\hosts","mode":"scheduled","event":"deleted"},"decoder":{"name":"syscheck_deleted"},"location":"syscheck"}`,

	"fim_registry": `{"timestamp":"2026-10-11T09:33:00.000+0000","rule":{"level":5,"description":"Registry Value Integrity Checksum Changed","id":"750",
		"groups":["ossec","syscheck","syscheck_entry_modified","syscheck_registry"]},"agent":{"id":"004","name":"WS-07","ip":"10.0.1.7"},
		"manager":{"name":"wazuh-manager"},"id":"1760175180.2300",
		"syscheck":{"path":"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\updater","value_name":"ImagePath","value_type":"REG_EXPAND_SZ",
			"arch":"[x64]","mode":"scheduled","event":"modified"},"decoder":{"name":"syscheck_registry_value_modified"},"location":"syscheck"}`,

	"sca_failed": `{"timestamp":"2026-10-11T10:00:00.000+0000","rule":{"level":7,"description":"CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0: Ensure SSH root login is disabled.","id":"19007",
		"groups":["sca"]},"agent":{"id":"001","name":"web-01","ip":"10.0.0.21"},"manager":{"name":"wazuh-manager"},"id":"1760176800.3000",
		"data":{"sca":{"type":"check","scan_id":"1760176700","policy":"CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0","policy_id":"cis_ubuntu22-04",
			"check":{"id":"28654","title":"Ensure SSH root login is disabled.","description":"The PermitRootLogin parameter specifies if the root user can log in using SSH.",
				"rationale":"Disallowing root logins over SSH requires administrators to authenticate with their own account.",
				"remediation":"Set PermitRootLogin no in /etc/ssh/sshd_config.","compliance":{"cis":"5.2.8","nist_sp_800-53":"AC-6(2)","pci_dss_v4.0":["7.2.1","7.2.2"]},
				"command":"sshd -T","result":"failed"}}},"decoder":{"name":"sca"},"location":"sca"}`,

	"sca_not_applicable": `{"timestamp":"2026-10-11T10:00:01.000+0000","rule":{"level":3,"description":"CIS Benchmark: Ensure auditd is installed.","id":"19008",
		"groups":["sca"]},"agent":{"id":"001","name":"web-01"},"manager":{"name":"wazuh-manager"},"id":"1760176801.3001",
		"data":{"sca":{"type":"check","policy":"CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0","check":{"id":28700,"title":"Ensure auditd is installed.",
			"status":"Not applicable","reason":"Could not open file '/etc/audit/auditd.conf'"}}},"location":"sca"}`,

	"sca_summary": `{"timestamp":"2026-10-11T10:00:05.000+0000","rule":{"level":7,"description":"SCA summary: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0: Score less than 50% (42)","id":"19004",
		"groups":["sca"]},"agent":{"id":"001","name":"web-01"},"manager":{"name":"wazuh-manager"},"id":"1760176805.3100",
		"data":{"sca":{"type":"summary","policy":"CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0","passed":"80","failed":"110","score":"42"}},"location":"sca"}`,

	"win_4625": `{"timestamp":"2026-10-11T09:40:02.000+0000","rule":{"level":5,"description":"Logon failure - Unknown user or bad password.","id":"60122",
		"mitre":{"id":["T1531"],"tactic":["Impact"]},"groups":["windows","windows_security","win_authentication_failed","authentication_failed"]},
		"agent":{"id":"004","name":"WS-07","ip":"10.0.1.7"},"manager":{"name":"wazuh-manager"},"id":"1760175602.4000","decoder":{"name":"windows_eventchannel"},
		"data":{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4625","level":"0","channel":"Security",
			"computer":"WS-07.corp.local","systemTime":"2026-10-11T09:40:01.9876543Z","message":"\"An account failed to log on.\""},
			"eventdata":{"subjectUserSid":"S-1-0-0","targetUserName":"administrator","targetDomainName":"CORP","status":"0xc000006d","subStatus":"0xc000006a",
				"logonType":"3","logonProcessName":"NtLmSsp ","authenticationPackageName":"NTLM","workstationName":"KALI","ipAddress":"203.0.113.9","ipPort":"51234"}}},
		"location":"EventChannel"}`,

	"win_4688": `{"timestamp":"2026-10-11T09:41:00.000+0000","rule":{"level":3,"description":"A new process has been created.","id":"67027",
		"groups":["windows","windows_security"]},"agent":{"id":"004","name":"WS-07","ip":"10.0.1.7"},"manager":{"name":"wazuh-manager"},"id":"1760175660.4100",
		"data":{"win":{"system":{"eventID":"4688","channel":"Security","computer":"WS-07.corp.local"},
			"eventdata":{"subjectUserName":"bob","subjectDomainName":"CORP","newProcessId":"0x1a2c","newProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
				"commandLine":"powershell -enc AAA","parentProcessName":"C:\\Windows\\explorer.exe"}}},"location":"EventChannel"}`,

	"sysmon_1": `{"timestamp":"2026-10-11T09:42:00.000+0000","rule":{"level":4,"description":"Sysmon - Suspicious Process - cmd.exe","id":"92031",
		"mitre":{"id":["T1059.003"],"tactic":["Execution"]},"groups":["sysmon","sysmon_process-anomalies","windows"]},
		"agent":{"id":"004","name":"WS-07","ip":"10.0.1.7"},"manager":{"name":"wazuh-manager"},"id":"1760175720.4200",
		"data":{"win":{"system":{"eventID":"1","channel":"Microsoft-Windows-Sysmon/Operational","computer":"WS-07.corp.local"},
			"eventdata":{"image":"C:\\Windows\\System32\\cmd.exe","commandLine":"cmd.exe /c whoami","processId":"4242","user":"CORP\\bob",
				"hashes":"SHA256=ABCDEF0123,MD5=99AA","parentImage":"C:\\Windows\\explorer.exe","parentCommandLine":"C:\\Windows\\Explorer.EXE"}}},
		"location":"EventChannel"}`,

	"sysmon_3": `{"timestamp":"2026-10-11T09:42:30.000+0000","rule":{"level":4,"description":"Sysmon - Network connection by powershell.exe","id":"92101",
		"groups":["sysmon","sysmon_eid3_detections","windows"]},"agent":{"id":"004","name":"WS-07","ip":"10.0.1.7"},"manager":{"name":"wazuh-manager"},
		"id":"1760175750.4250","data":{"win":{"system":{"eventID":"3","channel":"Microsoft-Windows-Sysmon/Operational","computer":"WS-07.corp.local"},
			"eventdata":{"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","user":"CORP\\bob","protocol":"tcp",
				"sourceIp":"10.0.1.7","sourcePort":"50311","destinationIp":"198.51.100.80","destinationHostname":"evil.example","destinationPort":"443"}}},
		"location":"EventChannel"}`,

	"win_other": `{"timestamp":"2026-10-11T09:43:00.000+0000","rule":{"level":12,"description":"The audit log was cleared.","id":"63103",
		"groups":["windows","windows_security"]},"agent":{"id":"004","name":"WS-07"},"manager":{"name":"wazuh-manager"},"id":"1760175780.4300",
		"data":{"win":{"system":{"eventID":"1102","channel":"Security","computer":"WS-07.corp.local"},"eventdata":{"subjectUserName":"bob"}}},"location":"EventChannel"}`,

	"web_attack": `{"timestamp":"2026-10-11T09:50:00.000+0000","rule":{"level":7,"description":"SQL injection attempt.","id":"31103",
		"mitre":{"id":["T1190"],"tactic":["Initial Access"]},"groups":["web","accesslog","attack","sql_injection"]},
		"agent":{"id":"001","name":"web-01","ip":"10.0.0.21"},"manager":{"name":"wazuh-manager"},"id":"1760176200.5000",
		"full_log":"203.0.113.50 - - [11/Oct/2026:09:50:00 +0000] \"GET /index.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1\" 200 512",
		"decoder":{"name":"web-accesslog"},"data":{"srcip":"203.0.113.50","protocol":"GET","url":"/index.php?id=1%27%20OR%20%271%27=%271","id":"200"},
		"location":"/var/log/nginx/access.log"}`,

	"rootcheck_critical": `{"timestamp":"2026-10-11T09:55:00.000+0000","rule":{"level":"13","description":"Host-based anomaly detection event (rootcheck).","id":"510",
		"groups":"ossec,rootcheck"},"agent":{"id":"002","name":"db-01"},"manager":{"name":"wazuh-manager"},"id":"1760176500.6000",
		"full_log":"Trojaned version of file '/bin/ls' detected.","decoder":{"name":"rootcheck"},"location":"rootcheck"}`,
}

func wazuhEvent(t *testing.T, name string) Event {
	t.Helper()
	line, ok := wazuhFixtures[name]
	if !ok {
		t.Fatalf("no fixture %s", name)
	}
	// On disk each alert is one line.
	line = strings.Join(strings.Fields(strings.ReplaceAll(line, "\n\t\t", " ")), " ")
	if !json.Valid([]byte(line)) {
		t.Fatalf("fixture %s is not valid JSON", name)
	}
	return Normalize(WazuhTag, map[string]any{"date": 1760175000.5, "log": line}, now)
}

func TestWazuhMapping(t *testing.T) {
	for _, tc := range []struct {
		name  string
		model string
		want  map[string]any
	}{
		{"sshd_success", "Authentication", map[string]any{
			"action": "success", "app": "sshd", "user": "deploy", "src": "198.51.100.7", "src_port": int64(50122), "dest": "web-01",
			"signature_id": "5715", "signature": "sshd: authentication success.", "@timestamp": "2026-10-11T09:15:02.123Z",
		}},
		{"sshd_failed", "Authentication", map[string]any{"action": "failure", "user": "root", "src": "203.0.113.9", "app": "sshd"}},
		{"sshd_bruteforce", "Authentication", map[string]any{"action": "failure", "user": "admin", "wazuh_rule_level": int64(10)}},
		{"pam_session", "Authentication", map[string]any{"action": "success", "app": "pam", "user": "root", "src_user": "alice", "dest": "jump-01"}},
		{"sudo", "Alerts", map[string]any{"app": "wazuh", "user": "root", "severity": "informational", "severity_id": int64(3), "type": "syslog, sudo"}},
		{"fim_modified", "Filesystem", map[string]any{
			"action": "modified", "file_path": "/etc/passwd", "file_name": "passwd", "file_size": int64(2471), "user": "alice",
			"file_hash":    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			"process_name": "vim.basic", "process_path": "/usr/bin/vim.basic", "process_id": int64(4321), "dest": "db-01", "host": "db-01",
			"signature_id": "550",
		}},
		{"fim_added", "Filesystem", map[string]any{"action": "created", "file_name": "shell.php", "file_size": int64(1337), "user": "www-data"}},
		{"fim_deleted_windows", "Filesystem", map[string]any{"action": "deleted", "file_name": "hosts", "file_path": `c:\windows\system32\drivers\etc\hosts`}},
		{"fim_registry", "Registry", map[string]any{
			"action": "modified", "registry_key_name": "updater", "registry_value_name": "ImagePath",
			"registry_path": `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\updater\ImagePath`,
		}},
		{"sca_failed", "Configuration_Check", map[string]any{
			"check_id": "28654", "check": "Ensure SSH root login is disabled.", "result": "fail", "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0",
			"reference": "cis: 5.2.8; nist_sp_800-53: AC-6(2); pci_dss_v4.0: 7.2.1,7.2.2", "dest": "web-01",
		}},
		{"sca_not_applicable", "Configuration_Check", map[string]any{
			"check_id": "28700", "result": "n/a", "detail": "Could not open file '/etc/audit/auditd.conf'",
		}},
		{"sca_summary", "Alerts", map[string]any{"severity": "medium", "type": "sca"}},
		{"win_4625", "Authentication", map[string]any{
			"action": "failure", "app": "win:local", "user": "administrator", "user_domain": "CORP", "src": "203.0.113.9", "src_port": int64(51234),
			"logon_type": int64(3), "reason": "bad password", "src_host": "KALI", "authentication_method": "NTLM",
			"wazuh_win_event_id": "4625", "signature_id": "60122", "host": "WS-07", "dest": "WS-07", "sourcetype": "wazuh:alerts",
		}},
		{"win_4688", "Endpoint", map[string]any{"process_name": "powershell.exe", "process": "powershell -enc AAA", "process_id": int64(0x1a2c), "user": "bob", "parent_process_name": "explorer.exe"}},
		{"sysmon_1", "Endpoint", map[string]any{"process_name": "cmd.exe", "process": "cmd.exe /c whoami", "process_id": int64(4242), "process_sha256": "abcdef0123", "user": `CORP\bob`}},
		{"sysmon_3", "Network_Traffic", map[string]any{
			"src": "10.0.1.7", "src_port": int64(50311), "dest": "198.51.100.80", "dest_port": int64(443), "dest_host": "evil.example",
			"transport": "tcp", "process_name": "powershell.exe", "host": "WS-07",
		}},
		{"win_other", "Alerts", map[string]any{"severity": "high", "severity_id": int64(12), "user": "bob"}},
		{"web_attack", "Alerts", map[string]any{
			"app": "wazuh", "id": "1760176200.5000", "description": "SQL injection attempt.", "severity": "medium", "severity_id": int64(7),
			"type": "web, accesslog, attack, sql_injection", "src": "203.0.113.50", "dest": "web-01",
		}},
		{"rootcheck_critical", "Alerts", map[string]any{"severity": "critical", "severity_id": int64(13), "type": "ossec,rootcheck"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := wazuhEvent(t, tc.name)
			if ev.Model != tc.model {
				t.Fatalf("model = %s, want %s", ev.Model, tc.model)
			}
			d := ev.Document()
			expect(t, d, tc.want)
			expect(t, d, map[string]any{"vendor_product": "Wazuh", "sourcetype": "wazuh:alerts", "wazuh_manager": "wazuh-manager"})
			if msg, _ := d["message"].(string); !strings.HasPrefix(msg, `{"timestamp":`) || !json.Valid([]byte(msg)) {
				t.Errorf("message is not the alert JSON: %.80s", msg)
			}
			if d["wazuh_agent_id"] == nil || d["wazuh_rule_level"] == nil || d["wazuh_rule_groups"] == nil {
				t.Errorf("wazuh fields missing: %v", d)
			}
			for k := range d {
				if !KnownField(k) {
					t.Errorf("field %s is not a known field", k)
				}
			}
		})
	}
}

func TestWazuhKeepsRuleDetails(t *testing.T) {
	d := wazuhEvent(t, "sshd_success").Document()
	if !reflect.DeepEqual(d["mitre"], []string{"T1078", "T1021"}) || !reflect.DeepEqual(d["wazuh_rule_groups"], []string{"syslog", "sshd", "authentication_success"}) {
		t.Errorf("mitre = %v, groups = %v", d["mitre"], d["wazuh_rule_groups"])
	}
	if tac, _ := d["mitre_tactic"].([]string); len(tac) != 5 {
		t.Errorf("mitre_tactic = %v", d["mitre_tactic"])
	}
	expect(t, d, map[string]any{
		"wazuh_agent_id": "001", "wazuh_agent_ip": "10.0.0.21", "wazuh_agent_name": "web-01", "wazuh_decoder": "sshd",
		"wazuh_location": "/var/log/auth.log", "wazuh_rule_level": int64(3),
	})
	// The Fluent Bit "date" is only a fallback for an alert's own time.
	ev := Normalize(WazuhTag, map[string]any{"date": 1760175000.5, "log": `{"rule":{"id":"1"},"agent":{"name":"a"}}`}, now)
	if ev.Model != "Alerts" || ev.Time.Unix() != 1760175000 {
		t.Errorf("model %s, time %v", ev.Model, ev.Time)
	}
}

func TestWazuhRecordShapes(t *testing.T) {
	line := strings.Join(strings.Fields(wazuhFixtures["sshd_failed"]), " ")
	// Already decoded by a Fluent Bit json parser, under any tag.
	ev := Normalize("app", decode(t, line), now)
	if ev.Model != "Authentication" || ev.Fields["sourcetype"] != WazuhSourcetype || ev.Fields["src_port"] != int64(40022) {
		t.Errorf("decoded record: %s %v", ev.Model, ev.Fields)
	}
	// A line under the Wazuh tag that is not an alert stays searchable.
	for _, s := range []string{"ossec: started", `{"rule":"x","agent":{}}`, `{"rule":{},"agent":{}} trailing`, "{" + strings.Repeat(`"a":{`, 40)} {
		ev = Normalize(WazuhTag, map[string]any{"log": s}, now)
		if ev.Model != "Other" || ev.Fields["sourcetype"] != WazuhSourcetype || ev.Fields["message"] != s {
			t.Errorf("%.30q: %s %v", s, ev.Model, ev.Fields)
		}
	}
	// Too long to be one record.
	big := `{"rule":{"id":"1"},"agent":{"name":"a"},"full_log":"` + strings.Repeat("x", MaxRecordBytes) + `"}`
	if ev = Normalize(WazuhTag, map[string]any{"log": big}, now); ev.Model != "Other" {
		t.Errorf("oversized alert mapped to %s", ev.Model)
	}
	// Other tags are not affected.
	if ev = Normalize("linux.auth", map[string]any{"log": "Oct 11 09:15:02 web-01 sshd[1]: Accepted password for a from 192.0.2.1 port 1 ssh2"}, now); ev.Fields["sourcetype"] != "linux:auth" {
		t.Errorf("linux.auth: %v", ev.Fields)
	}
}

func TestWazuhOddTypes(t *testing.T) {
	for _, s := range []string{
		`{"rule":{"level":"high","groups":[1,null,{"a":1},"x"],"mitre":{"id":"T1"},"id":5715,"description":["x"]},"agent":{"name":42,"id":null}}`,
		`{"rule":{"level":1e300},"agent":{},"syscheck":"x"}`,
		`{"rule":{"level":-4},"agent":{},"syscheck":{"path":7,"size_after":"12.5","audit":"x","event":["added"]}}`,
		`{"rule":{"level":16},"agent":{},"data":{"sca":{"type":"check","check":["x"]}}}`,
		`{"rule":{"level":2},"agent":{},"data":{"sca":{"type":"check","check":{"compliance":{"cis":{"x":1}},"id":{"a":1}}}}}`,
		`{"rule":{"groups":["authentication_success"]},"agent":{},"data":"x"}`,
		`{"rule":{},"agent":{},"data":{"win":{"system":"x"}}}`,
		`{"rule":{},"agent":{},"data":{"win":{"system":{"eventID":4625,"channel":"Security"},"eventdata":["x"]}}}`,
		`{"rule":{},"agent":{},"data":{"win":{"system":{"eventID":"1","channel":"Microsoft-Windows-Sysmon/Operational"},"eventdata":{"":"x","image":5}}}}`,
		`{"rule":{},"agent":{},"timestamp":12}`,
	} {
		ev, ok := ParseWazuhText(s)
		if !ok {
			t.Errorf("%s: not read as an alert", s)
			continue
		}
		_ = ev.Document()
	}
	ev, _ := ParseWazuhText(`{"rule":{"level":"high","groups":[1,null,{"a":1},"x"],"mitre":{"id":"T1"},"id":5715},"agent":{"name":42}}`)
	expect(t, ev.Fields, map[string]any{"signature_id": "5715", "host": "42", "type": "1, x"})
	if !reflect.DeepEqual(ev.Fields["mitre"], []string{"T1"}) {
		t.Errorf("mitre = %v", ev.Fields["mitre"])
	}
	if _, ok := ev.Fields["severity"]; ok {
		t.Errorf("severity from a level that is not a number: %v", ev.Fields["severity"])
	}
	ev, _ = ParseWazuhText(`{"rule":{"level":16},"agent":{}}`)
	if ev.Fields["severity"] != "critical" {
		t.Errorf("level 16: %v", ev.Fields["severity"])
	}
}

func TestParseWazuhText(t *testing.T) {
	line := strings.Join(strings.Fields(wazuhFixtures["web_attack"]), " ")
	for _, s := range []string{line, "ossec: " + line, "wazuh-manager ossec: " + line + "\n"} {
		ev, ok := ParseWazuhText(s)
		if !ok || ev.Model != "Alerts" || ev.Fields["message"] != line {
			t.Errorf("%.40q: ok %v model %s", s, ok, ev.Model)
		}
	}
	for _, s := range []string{
		"", "plain text", `{"rule":{},"other":{}}`, strings.Repeat("x", maxWazuhPrefix+1) + line,
		line[:len(line)-20], `{"agent":{},"rule":{}}{"agent":{},"rule":{}}`, "[" + line + "]",
	} {
		if _, ok := ParseWazuhText(s); ok {
			t.Errorf("%.60q read as an alert", s)
		}
	}
}

func TestWazuhAntivirusToMalware(t *testing.T) {
	for name, c := range map[string]struct {
		alert, product, action, sig, path string
	}{
		"clamav": {`{"timestamp":"2026-10-13T09:00:00.000+0000","rule":{"level":8,"id":"52502","description":"ClamAV: Virus detected","groups":["clamd","freshclam","virus"]},` +
			`"agent":{"id":"002","name":"web-02"},"decoder":{"name":"clamd"},"full_log":"Oct 13 09:00:00 web-02 clamd[812]: /tmp/eicar.com: Win.Test.EICAR_HDB-1 FOUND"}`,
			"ClamAV", "detected", "Win.Test.EICAR_HDB-1", "/tmp/eicar.com"},
		"virustotal": {`{"rule":{"level":12,"id":"87105","description":"VirusTotal: Alert","groups":["virustotal"]},"agent":{"id":"003","name":"ws-1"},` +
			`"data":{"virustotal":{"malicious":"1","positives":"52","total":"70","permalink":"https://www.virustotal.com/x","source":{"file":"/home/a/x.elf","md5":"44D88612FEA8A8F36DE82E1278ABB02F","sha1":"3395856ce81f2b7382dee72602f798b642f14140"}}}}`,
			"Wazuh", "detected", "VirusTotal: 52 of 70 engines", "/home/a/x.elf"},
		"rootcheck trojan": {`{"rule":{"level":7,"id":"510","description":"Host-based anomaly detection event (rootcheck).","groups":["ossec","rootcheck"]},"agent":{"id":"004","name":"db-1"},` +
			`"data":{"title":"Trojaned version of file detected.","file":"/bin/passwd"},"full_log":"Trojaned version of file '/bin/passwd' detected."}`,
			"Wazuh", "detected", "Trojaned version of file detected.", "/bin/passwd"},
	} {
		var a map[string]any
		if err := json.Unmarshal([]byte(c.alert), &a); err != nil {
			t.Fatal(err)
		}
		ev := ParseWazuhAlert(a, "")
		f := ev.Fields
		if ev.Model != MalwareModel || f["vendor_product"] != c.product || f["action"] != c.action || f["signature"] != c.sig ||
			f["file_path"] != c.path || f["type"] != MalwareThreat || f["dest"] == "" || f["description"] == "" {
			t.Errorf("%s: %s %+v", name, ev.Model, f)
		}
	}

	// Other rootcheck findings carry no threat and stay Alerts.
	var a map[string]any
	_ = json.Unmarshal([]byte(`{"rule":{"level":7,"id":"510","description":"rootcheck","groups":["rootcheck"]},"agent":{"name":"db-1"},"data":{"title":"Process hidden from /bin/ps"}}`), &a)
	if ev := ParseWazuhAlert(a, ""); ev.Model != "Alerts" {
		t.Errorf("rootcheck without a threat = %s", ev.Model)
	}
}
