package sigmacheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Windows channels the test events come from.
const (
	SysmonChannel        = "Microsoft-Windows-Sysmon/Operational"
	SecurityChannel      = "Security"
	SystemChannel        = ingest.SystemChannel
	ApplicationChannel   = ingest.ApplicationChannel
	CodeIntegrityChannel = ingest.CodeIntegrityChannel
	PowerShellChannel    = ingest.PowerShellChannel
	DefenderChannel      = ingest.DefenderChannel
	// LinuxSysmonChannel is Sysmon for Linux, whose events have Sysmon's
	// event IDs and fields.
	LinuxSysmonChannel = ingest.LinuxSysmonChannel
	// AuditdChannel is Linux audit records, whose event ID is the record
	// type (EXECVE) and whose data are its fields by auditd's names.
	AuditdChannel = ingest.AuditdChannel
)

// TestFile holds a shipped rule's test events.
type TestFile struct {
	// Rule is the Sigma rule's id.
	Rule  string `json:"rule"`
	Cases []Case `json:"cases"`
}

// Case is one Windows event and whether the rule must match it.
type Case struct {
	Expect bool `json:"expect"`
	// Source is "synthesized" (made from the rule), "sigmahq" (a real
	// event from SigmaHQ's regression data) or "attack_data" (a real event
	// from Splunk's attack recordings).
	Source  string            `json:"source"`
	Channel string            `json:"channel"`
	EventID string            `json:"event_id"`
	Data    map[string]string `json:"data"`
}

// Security 4688 data names and the Sigma process_creation fields they
// carry. User is left out: 4688 names the account without its domain.
var security4688 = map[string]string{
	"NewProcessName":    "Image",
	"CommandLine":       "CommandLine",
	"ParentProcessName": "ParentImage",
}

// SigmaView returns the case's event as Sigma field names, or false when
// the event's channel has no Sigma view here.
func (c Case) SigmaView() (map[string]string, bool) {
	switch {
	case c.Channel == AuditdChannel:
		// A recorded line's fields, or the fields a line is built from.
		fields := c.Data
		if raw, ok := c.Data["_raw"]; ok {
			rec, ok := ingest.ReadAuditd(raw)
			if !ok {
				return nil, false
			}
			fields = rec.Fields
		}
		out := map[string]string{"type": c.EventID}
		for k, v := range fields {
			out[k] = v
		}
		return out, true
	case strings.EqualFold(c.Channel, SysmonChannel), strings.EqualFold(c.Channel, LinuxSysmonChannel),
		strings.EqualFold(c.Channel, PowerShellChannel) && c.EventID == "4104":
		out := map[string]string{"EventID": c.EventID}
		for k, v := range c.Data {
			out[k] = v
		}
		return out, true
	case strings.EqualFold(c.Channel, DefenderChannel):
		// Defender rules name the event's data as its message labels
		// it (Path, ProcessName, NewValue).
		out := map[string]string{"EventID": c.EventID}
		for k, v := range c.Data {
			out[k] = v
		}
		return out, true
	case c.Channel == ApplicationChannel || c.Channel == CodeIntegrityChannel || ingest.IsNamedChannel(c.Channel):
		// Application and Code Integrity log rules name the provider and
		// the event's data values (Data); Firewall and BITS log rules
		// their events' data by name.
		out := map[string]string{"EventID": c.EventID}
		for k, v := range c.Data {
			out[k] = v
		}
		return out, true
	case c.Channel == SystemChannel:
		// The provider is part of the event's System section, which Sigma
		// rules name as Provider_Name; the parser takes an event without
		// one as the Service Control Manager's.
		out := map[string]string{"EventID": c.EventID}
		for k, v := range c.Data {
			out[k] = v
		}
		if out["Provider_Name"] == "" {
			out["Provider_Name"] = ingest.ServiceControlManager
		}
		return out, true
	case c.Channel == SecurityChannel && c.EventID == "4688":
		out := map[string]string{"EventID": c.EventID}
		for raw, sig := range security4688 {
			if v, ok := c.Data[raw]; ok {
				out[sig] = v
			}
		}
		return out, true
	case c.Channel == SecurityChannel && slices.Contains(SecurityEvents, c.EventID):
		// Security log rules (service: security) name the event's own
		// data.
		out := map[string]string{"EventID": c.EventID}
		for k, v := range c.Data {
			out[k] = v
		}
		return out, true
	}
	return nil, false
}

// Record is a case's event as the agent sends it, with its Fluent Bit tag:
// a journal record for Sysmon for Linux, else a Windows event record.
func (c Case) Record(host string, t time.Time) (string, map[string]any) {
	if strings.EqualFold(c.Channel, LinuxSysmonChannel) {
		return "linux.journal", ingest.LinuxSysmonRecord(c.EventID, host, t, c.Data)
	}
	if c.Channel == AuditdChannel {
		return "linux.audit", ingest.AuditdRecordFor(ingest.AuditdLine(c.EventID, t, c.Data), host)
	}
	return "win.events", ingest.WinEventRecord(c.Channel, c.EventID, host, t, c.Data)
}

// Stored is a case's event after the real parser.
func (c Case) Stored(host string, t time.Time) ingest.Event {
	tag, rec := c.Record(host, t)
	return ingest.Normalize(tag, rec, t)
}

// Logsource event IDs: the Sysmon event (or, for the System log, the
// Windows event) a Sigma log source category is.
var sysmonEvents = map[string]string{
	"process_creation":     "1",
	"network_connection":   "3",
	"driver_load":          "6",
	"image_load":           "7",
	"create_remote_thread": "8",
	"process_access":       "10",
	"file_event":           "11",
	"registry_add":         "12",
	"registry_delete":      "12",
	"registry_event":       "13",
	"registry_set":         "13",
	"create_stream_hash":   "15",
	"pipe_created":         "17",
	"raw_access_thread":    "9",
	"dns_query":            "22",
	"file_delete":          "26",
	"ps_script":            "4104",
	// Windows System log rules (service: system) are about services
	// installed, or name the other System events they are about (a
	// service changing state, by default).
	"system":       "7045",
	"system_event": "7036",
	// Application log rules (service: application) name their events;
	// an application crash is the first.
	"application": "1000",
	// Code Integrity log rules name their events; an unsigned driver
	// loaded is the first.
	"code_integrity": "3001",
	// Rules about the logs the parser reads by name name their events:
	// a firewall rule added, a BITS transfer started, an app package
	// deployed and a WMI operation failed are the first.
	"firewall_as":           "2004",
	"bits_client":           "16403",
	"appxdeployment_server": "400",
	"wmi":                   "5858",
	// Sysmon's own events (service: sysmon): a configuration change,
	// or a file block.
	"sysmon_event":                         "16",
	"sysmon_file_block":                    "27",
	"terminalservices_localsessionmanager": "21",
	"shell_core":                           "28115",
	"smbclient_security":                   "31017",
	"security_mitigations":                 "12",
	// Defender log rules (service: windefend) name their events; a
	// threat detected is the first.
	"windefend": "1116",
}

// SecurityEvents are the Security log events Security log rules
// (service: security) are checked for; such a rule's category is
// SecurityCategory of its one event, or of the events of one of
// SecurityGroups.
var SecurityEvents = []string{"4624", "4625", "4648", "4656", "4657", "4661", "4662", "4663", "4697", "4698", "4706", "4719",
	"4720", "4732", "4738", "4794", "4768", "4769", "5136", "5145", "5156", "5157", "4728", "4729", "4730", "1102", "4699",
	"4701", "4702", "5140"}

// SecurityGroups are Security events with the same data that a rule may
// name together: a handle to an object requested (4656) and the access
// made with it (4663), and a scheduled task deleted (4699) or disabled
// (4701). Test events are made as the last one first.
var SecurityGroups = [][]string{{"4656", "4663"}, {"4699", "4701"}}

// SecurityCategory is the category of a Security log rule about its
// events (sorted), as Bases, Cases and Channel know it; it is known (by
// SysmonEventID) for one of SecurityEvents or a group of SecurityGroups.
func SecurityCategory(eventIDs ...string) string { return "security_" + strings.Join(eventIDs, "_") }

// SysmonServiceCategory is the category of a rule about Sysmon's own
// events (service: sysmon): its file blocks (27, 28, 29), or others.
func SysmonServiceCategory(eventIDs ...string) string {
	if len(eventIDs) > 0 && !slices.ContainsFunc(eventIDs, func(id string) bool { return id != "27" && id != "28" && id != "29" }) {
		return "sysmon_file_block"
	}
	return "sysmon_event"
}

// SystemCategory is the category of a System log rule (service: system)
// about its events: services installed (7045), or other events.
func SystemCategory(eventIDs ...string) string {
	if len(eventIDs) > 0 && !slices.Contains(eventIDs, "7045") {
		return "system_event"
	}
	return "system"
}

func init() {
	// Other System events have no typical data: each rule names its
	// event's.
	Bases["system_event"] = map[string]string{}
	Bases["application"] = map[string]string{}
	Bases["code_integrity"] = map[string]string{}
	for service := range ingest.NamedChannelServices {
		Bases[ingest.NamedChannelCategory(service)] = map[string]string{}
	}
	Bases["sysmon_event"] = map[string]string{}
	Bases["sysmon_file_block"] = Bases["file_event"]
	// A task disabled has the data of a task deleted.
	Bases[SecurityCategory("4701")] = Bases[SecurityCategory("4699")]
	for _, id := range SecurityEvents {
		sysmonEvents[SecurityCategory(id)] = id
	}
	for _, g := range SecurityGroups {
		c := SecurityCategory(g...)
		sysmonEvents[c] = g[len(g)-1]
		Bases[c] = Bases[SecurityCategory(g[len(g)-1])]
	}
}

// Channel returns the Windows channel a log source category's events come
// from.
func Channel(category string) string {
	switch category {
	case "ps_script":
		return PowerShellChannel
	case "system", "system_event":
		return SystemChannel
	case "application":
		return ApplicationChannel
	case "code_integrity":
		return CodeIntegrityChannel
	case "windefend":
		return DefenderChannel
	}
	for service, channel := range ingest.NamedChannelServices {
		if category == ingest.NamedChannelCategory(service) {
			return channel
		}
	}
	if strings.HasPrefix(category, "security_") {
		return SecurityChannel
	}
	return SysmonChannel
}

// Bases are the fields a typical event of each log source has, for
// Synthesize: neutral values that the rule's own values override.
var Bases = map[string]map[string]string{
	"process_creation": {
		"User":              `CORP\tester`,
		"ProcessId":         "4242",
		"ParentProcessId":   "4100",
		"ParentImage":       `D:\apps\launcher\launcher.exe`,
		"ParentCommandLine": `"D:\apps\launcher\launcher.exe" --run`,
		"CurrentDirectory":  `D:\apps\work\`,
		"IntegrityLevel":    "Medium",
	},
	"network_connection": {
		"User":            `CORP\tester`,
		"ProcessId":       "4242",
		"Protocol":        "tcp",
		"Initiated":       "true",
		"SourceIp":        "192.0.2.10",
		"SourcePort":      "50123",
		"DestinationIp":   "198.51.100.20",
		"DestinationPort": "8443",
	},
	"driver_load": {
		"ImageLoaded":     `D:\drivers\vendor\device.sys`,
		"Hashes":          "SHA256=" + strings.Repeat("ab", 32),
		"Signed":          "true",
		"Signature":       "Example Hardware Vendor",
		"SignatureStatus": "Valid",
	},
	"image_load": {
		"Image":           `D:\apps\launcher\launcher.exe`,
		"ProcessId":       "4242",
		"User":            `CORP\tester`,
		"ImageLoaded":     `D:\apps\launcher\plugin.dll`,
		"Signed":          "true",
		"Signature":       "Example Software Vendor",
		"SignatureStatus": "Valid",
	},
	"create_remote_thread": {
		"SourceImage":     `D:\apps\launcher\launcher.exe`,
		"SourceProcessId": "4242",
		"SourceUser":      `CORP\tester`,
		"TargetImage":     `D:\apps\worker\worker.exe`,
		"TargetProcessId": "4300",
		"StartAddress":    "0x00007FF6A1B21000",
		"StartModule":     `D:\apps\worker\worker.exe`,
		"StartFunction":   "-",
	},
	"process_access": {
		"SourceImage":     `D:\apps\launcher\launcher.exe`,
		"SourceProcessId": "4242",
		"SourceUser":      `CORP\tester`,
		"TargetImage":     `D:\apps\worker\worker.exe`,
		"TargetProcessId": "4300",
		"GrantedAccess":   "0x1000",
		"CallTrace":       `D:\apps\launcher\launcher.exe+1a2b|D:\apps\launcher\core.dll+3c4d`,
	},
	"file_event": {
		"Image":          `D:\apps\launcher\launcher.exe`,
		"ProcessId":      "4242",
		"User":           `CORP\tester`,
		"TargetFilename": `D:\apps\work\output.txt`,
	},
	"file_delete": {
		"Image":          `D:\apps\launcher\launcher.exe`,
		"ProcessId":      "4242",
		"User":           `CORP\tester`,
		"TargetFilename": `D:\apps\work\old-output.txt`,
	},
	"registry_add": {
		"EventType":    "CreateKey",
		"Image":        `D:\apps\launcher\launcher.exe`,
		"ProcessId":    "4242",
		"User":         `CORP\tester`,
		"TargetObject": `HKU\S-1-5-21-1000\SOFTWARE\ExampleVendor\Launcher`,
	},
	"registry_delete": {
		"EventType":    "DeleteKey",
		"Image":        `D:\apps\launcher\launcher.exe`,
		"ProcessId":    "4242",
		"User":         `CORP\tester`,
		"TargetObject": `HKU\S-1-5-21-1000\SOFTWARE\ExampleVendor\Launcher`,
	},
	"registry_set": {
		"EventType":    "SetValue",
		"Image":        `D:\apps\launcher\launcher.exe`,
		"ProcessId":    "4242",
		"User":         `CORP\tester`,
		"TargetObject": `HKU\S-1-5-21-1000\SOFTWARE\ExampleVendor\Launcher\LastRun`,
		"Details":      "DWORD (0x00000001)",
	},
	"ps_script": {
		"MessageNumber":   "1",
		"MessageTotal":    "1",
		"ScriptBlockText": "Get-ChildItem -Path D:\\apps\\work | Select-Object Name",
		"ScriptBlockId":   "6f1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10",
		"Path":            `D:\apps\scripts\report.ps1`,
	},
	"security_4624": {
		"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS1$", "SubjectDomainName": "CORP", "SubjectLogonId": "0x3e7",
		"TargetUserSid": "S-1-5-21-1000-1104", "TargetUserName": "tester", "TargetDomainName": "CORP", "TargetLogonId": "0x1a2b3c",
		"LogonType": "3", "LogonProcessName": "NtLmSsp", "AuthenticationPackageName": "NTLM", "WorkstationName": "WS2",
		"LmPackageName": "NTLM V2", "KeyLength": "0", "ProcessId": "0x0", "IpAddress": "192.0.2.10", "IpPort": "50123",
	},
	"security_4625": {
		"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS1$", "SubjectDomainName": "CORP", "SubjectLogonId": "0x3e7",
		"TargetUserSid": "S-1-0-0", "TargetUserName": "tester", "TargetDomainName": "CORP", "Status": "0xc000006d",
		"FailureReason": "%%2313", "SubStatus": "0xc000006a", "LogonType": "3", "LogonProcessName": "NtLmSsp",
		"AuthenticationPackageName": "NTLM", "WorkstationName": "WS2", "KeyLength": "0", "ProcessId": "0x0",
		"IpAddress": "192.0.2.10", "IpPort": "50123",
	},
	"security_4648": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"LogonGuid": "{00000000-0000-0000-0000-000000000000}", "TargetUserName": "svc_report", "TargetDomainName": "CORP",
		"TargetLogonGuid": "{00000000-0000-0000-0000-000000000000}", "TargetServerName": "fs1.corp.example.com",
		"TargetInfo": "fs1.corp.example.com", "ProcessId": "0x1092", "ProcessName": `D:\apps\launcher\launcher.exe`,
		"IpAddress": "-", "IpPort": "-",
	},
	"security_4656": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"ObjectServer": "Security", "ObjectType": "File", "ObjectName": `D:\apps\work\output.txt`, "HandleId": "0x0",
		"TransactionId": "{00000000-0000-0000-0000-000000000000}", "AccessList": "%%4416", "AccessReason": "-", "AccessMask": "0x1",
		"PrivilegeList": "-", "RestrictedSidCount": "0", "ProcessId": "0x1092", "ProcessName": `D:\apps\launcher\launcher.exe`,
	},
	"security_4657": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"ObjectName": `\REGISTRY\MACHINE\SOFTWARE\ExampleVendor\Launcher`, "ObjectValueName": "Theme", "HandleId": "0x1f0",
		"OperationType": "%%1905", "OldValueType": "%%1873", "OldValue": "light", "NewValueType": "%%1873", "NewValue": "dark",
		"ProcessId": "0x1092", "ProcessName": `D:\apps\launcher\launcher.exe`,
	},
	"security_4661": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"ObjectServer": "Security Account Manager", "ObjectType": "SAM_ALIAS", "ObjectName": "S-1-5-21-1000-1201", "HandleId": "0x0",
		"TransactionId": "{00000000-0000-0000-0000-000000000000}", "AccessList": "%%5400", "AccessMask": "0x4", "PrivilegeList": "-",
		"Properties": "-", "RestrictedSidCount": "0", "ProcessId": "0x2b4", "ProcessName": `C:\Windows\System32\lsass.exe`,
	},
	"security_4662": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"ObjectServer": "DS", "ObjectType": "bf967a86-0de6-11d0-a285-00aa003049e2", "ObjectName": "CN=WS2,OU=Computers,DC=corp,DC=example,DC=com",
		"OperationType": "Object Access", "HandleId": "0x0", "AccessList": "%%7684", "AccessMask": "0x10",
		"Properties": "%%7684 {77b5b886-944a-11d1-aebd-0000f80367c1}",
	},
	"security_4768": {
		"TargetUserName": "tester", "TargetDomainName": "CORP", "TargetSid": "S-1-5-21-1000-1104", "ServiceName": "krbtgt",
		"ServiceSid": "S-1-5-21-1000-502", "TicketOptions": "0x40810010", "Status": "0x0", "TicketEncryptionType": "0x12",
		"PreAuthType": "2", "IpAddress": "::ffff:192.0.2.10", "IpPort": "50123",
	},
	"security_4769": {
		"TargetUserName": "tester@CORP.EXAMPLE.COM", "TargetDomainName": "CORP.EXAMPLE.COM", "ServiceName": "svc_report",
		"ServiceSid": "S-1-5-21-1000-1301", "TicketOptions": "0x40810000", "TicketEncryptionType": "0x12",
		"IpAddress": "::ffff:192.0.2.10", "IpPort": "50123", "Status": "0x0",
	},
	"security_4663": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"ObjectServer": "Security", "ObjectType": "File", "ObjectName": `D:\apps\work\output.txt`, "HandleId": "0x1f4",
		"AccessList": "%%4416", "AccessMask": "0x1", "ProcessId": "0x1092", "ProcessName": `D:\apps\launcher\launcher.exe`,
	},
	"security_5156": {
		"ProcessID": "4242", "Application": `\device\harddiskvolume2\apps\launcher\launcher.exe`, "Direction": "%%14593",
		"SourceAddress": "192.0.2.10", "SourcePort": "50123", "DestAddress": "198.51.100.20", "DestPort": "8443", "Protocol": "6",
		"FilterRTID": "70412", "LayerName": "%%14611", "LayerRTID": "48",
	},
	"security_5157": {
		"ProcessID": "4242", "Application": `\device\harddiskvolume2\apps\launcher\launcher.exe`, "Direction": "%%14593",
		"SourceAddress": "192.0.2.10", "SourcePort": "50123", "DestAddress": "198.51.100.20", "DestPort": "8443", "Protocol": "6",
		"FilterRTID": "70413", "LayerName": "%%14611", "LayerRTID": "48",
	},
	"security_4706": {
		"DomainName": "partner.example.net", "DomainSid": "S-1-5-21-2000", "TdoType": "2", "TdoDirection": "3", "TdoAttributes": "8",
		"SidFilteringEnabled": "%%1796", "SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester",
		"SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
	},
	"security_4719": {
		"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WS1$", "SubjectDomainName": "CORP", "SubjectLogonId": "0x3e7",
		"CategoryId": "%%8274", "SubcategoryId": "%%12801", "SubcategoryGuid": "{0CCE921D-69AE-11D9-BED3-505054503030}",
		"AuditPolicyChanges": "%%8449",
	},
	"security_4720": {
		"TargetUserName": "jdoe", "TargetDomainName": "CORP", "TargetSid": "S-1-5-21-1000-1201",
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"PrivilegeList": "-", "SamAccountName": "jdoe", "DisplayName": "%%1793", "UserPrincipalName": "-", "PrimaryGroupId": "513",
		"AllowedToDelegateTo": "-", "OldUacValue": "0x0", "NewUacValue": "0x15", "UserAccountControl": "%%2080 %%2082 %%2084",
		"SidHistory": "-",
	},
	"security_4732": {
		"MemberName": "-", "MemberSid": "S-1-5-21-1000-1201", "TargetUserName": "Remote Desktop Users", "TargetDomainName": "Builtin",
		"TargetSid": "S-1-5-32-555", "SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester",
		"SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
	},
	"security_4738": {
		"Dummy": "-", "TargetUserName": "jdoe", "TargetDomainName": "CORP", "TargetSid": "S-1-5-21-1000-1201",
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"PrivilegeList": "-", "SamAccountName": "-", "DisplayName": "-", "UserPrincipalName": "-", "PrimaryGroupId": "-",
		"AllowedToDelegateTo": "-", "OldUacValue": "0x10", "NewUacValue": "0x210", "UserAccountControl": "%%2089", "SidHistory": "-",
	},
	"security_4794": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"Workstation": "DC1",
	},
	"security_4697": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"ServiceName": "ExampleUpdater", "ServiceFileName": `"D:\apps\updater\updater.exe" --service`,
		"ServiceType": "0x10", "ServiceStartType": "2", "ServiceAccount": "LocalSystem",
	},
	"security_4698": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"TaskName":    `\ExampleUpdater`,
		"TaskContent": `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2"><Actions Context="Author"><Exec><Command>D:\apps\updater\updater.exe</Command></Exec></Actions></Task>`,
	},
	"security_5136": {
		"OpCorrelationID": "{2a5d8e4f-9b10-4b8e-9c71-6f1b4c2e0d3a}", "AppCorrelationID": "-",
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"DSName": "corp.example.com", "DSType": "%%14676", "ObjectDN": "CN=Example User,OU=Staff,DC=corp,DC=example,DC=com",
		"ObjectGUID": "{6f1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10}", "ObjectClass": "user", "AttributeLDAPDisplayName": "description",
		"AttributeSyntaxOID": "2.5.5.12", "AttributeValue": "Example description", "OperationType": "%%14674",
	},
	"security_5145": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"ObjectType": "File", "IpAddress": "192.0.2.10", "IpPort": "50123", "ShareName": `\\*\Projects`,
		"ShareLocalPath": `\??\D:\Projects`, "RelativeTargetName": `reports\summary.txt`, "AccessMask": "0x1", "AccessList": "%%4416",
	},
	"system": {
		"ServiceName": "ExampleUpdater",
		"ImagePath":   `"D:\apps\updater\updater.exe" --service`,
		"ServiceType": "user mode service",
		"StartType":   "auto start",
		"AccountName": "LocalSystem",
	},
	"security_4728": {
		"MemberName": "CN=Example User,OU=Staff,DC=corp,DC=example,DC=com", "MemberSid": "S-1-5-21-1000-1201",
		"TargetUserName": "Report Readers", "TargetDomainName": "CORP", "TargetSid": "S-1-5-21-1000-1301",
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
	},
	"security_4729": {
		"MemberName": "CN=Example User,OU=Staff,DC=corp,DC=example,DC=com", "MemberSid": "S-1-5-21-1000-1201",
		"TargetUserName": "Report Readers", "TargetDomainName": "CORP", "TargetSid": "S-1-5-21-1000-1301",
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
	},
	"security_4730": {
		"TargetUserName": "Report Readers", "TargetDomainName": "CORP", "TargetSid": "S-1-5-21-1000-1301",
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c", "PrivilegeList": "-",
	},
	"security_1102": {"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c", "Provider_Name": "Microsoft-Windows-Eventlog"},
	"security_4699": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"TaskName":    `\ExampleUpdater`,
		"TaskContent": `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2"><Actions Context="Author"><Exec><Command>D:\apps\updater\updater.exe</Command></Exec></Actions></Task>`,
	},
	"security_4702": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"TaskName":       `\ExampleUpdater`,
		"TaskContentNew": `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2"><Actions Context="Author"><Exec><Command>D:\apps\updater\updater.exe</Command></Exec></Actions></Task>`,
	},
	"security_5140": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"ObjectType": "File", "IpAddress": "192.0.2.10", "IpPort": "50123", "ShareName": `\\*\Projects`,
		"ShareLocalPath": `\??\D:\Projects`, "AccessMask": "0x1", "AccessList": "%%4416",
	},
	"windefend": {
		"ThreatName":    "Trojan:Win32/Example",
		"SeverityName":  "Severe",
		"CategoryName":  "Trojan",
		"Path":          `file:_C:\Users\tester\Downloads\invoice.exe`,
		"SourceName":    "Real-Time Protection",
		"ProcessName":   `C:\Windows\explorer.exe`,
		"DetectionUser": `CORP\tester`,
	},
	"raw_access_thread": {
		"Image":     `D:\apps\backup\backup.exe`,
		"ProcessId": "4242",
		"User":      `CORP\tester`,
		"Device":    `\Device\HarddiskVolume3`,
	},
	"pipe_created": {
		"Image":     `D:\apps\launcher\launcher.exe`,
		"ProcessId": "4242",
		"User":      `CORP\tester`,
		"EventType": "CreatePipe",
		"PipeName":  `\launcher_ipc`,
	},
	"create_stream_hash": {
		"Image":          `D:\apps\launcher\launcher.exe`,
		"ProcessId":      "4242",
		"User":           `CORP\tester`,
		"TargetFilename": `C:\Users\tester\Downloads\setup.exe:Zone.Identifier`,
		"Hash":           "SHA256=2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE",
		"Contents":       "[ZoneTransfer]  ZoneId=3",
	},
	"dns_query": {
		"Image":        `D:\apps\launcher\launcher.exe`,
		"ProcessId":    "4242",
		"User":         `CORP\tester`,
		"QueryName":    "updates.example.com",
		"QueryStatus":  "0",
		"QueryResults": "::ffff:192.0.2.30;",
	},
}

// LinuxBases are Bases for Linux rules, as Sysmon for Linux writes them.
var LinuxBases = map[string]map[string]string{
	"process_creation": {
		"User":              "tester",
		"ProcessId":         "4242",
		"ParentProcessId":   "4100",
		"ParentImage":       "/opt/apps/launcher/launcher",
		"ParentCommandLine": "/opt/apps/launcher/launcher --run",
		"CurrentDirectory":  "/opt/apps/work",
	},
	"network_connection": {
		"User":            "tester",
		"ProcessId":       "4242",
		"Protocol":        "tcp",
		"Initiated":       "true",
		"SourceIp":        "192.0.2.10",
		"SourcePort":      "50123",
		"DestinationIp":   "198.51.100.20",
		"DestinationPort": "8443",
	},
	// An audit record's fields are the rule's own.
	"auditd": {},
	"file_event": {
		"Image":          "/opt/apps/launcher/launcher",
		"ProcessId":      "4242",
		"User":           "tester",
		"TargetFilename": "/opt/apps/work/output.txt",
	},
}

func init() {
	// registry_event covers keys and values; a set value is the typical
	// event.
	Bases["registry_event"] = Bases["registry_set"]
}

// sysmonAlso are the other Sysmon events a log source category covers.
var sysmonAlso = map[string][]string{
	"registry_event": {"12", "14"},
	"file_delete":    {"23"},
}

// SysmonEventIDs returns every Sysmon event ID a log source category
// covers, the one test events are made as first.
func SysmonEventIDs(category string) []string {
	id, ok := sysmonEvents[category]
	if !ok {
		return nil
	}
	return append([]string{id}, sysmonAlso[category]...)
}

// SysmonEventID returns the Sysmon event ID of a log source category.
func SysmonEventID(category string) (string, bool) {
	id, ok := sysmonEvents[category]
	return id, ok
}

// Cases turns synthesized events into test cases: each as a Sysmon event,
// and process creations whose fields Security 4688 also carries as a
// 4688 event too.
func Cases(category string, syn *Synthesis, fields []string) []Case {
	return CasesOn(Channel(category), category, syn, fields)
}

// LinuxCases are Cases for a Linux rule: each as a Sysmon for Linux event.
func LinuxCases(category string, syn *Synthesis, fields []string) []Case {
	return CasesOn(LinuxSysmonChannel, category, syn, fields)
}

// AuditdCases are Cases for a Linux audit rule (service: auditd): each
// event as an audit record of the type the rule names (EXECVE when it
// names a program's arguments and no type, else SYSCALL). A program's
// arguments come in order from a0, so ones the rule leaves out are
// filled in, and argc counts them.
func AuditdCases(_ string, syn *Synthesis, fields []string) []Case {
	var out []Case
	add := func(expect bool, ev map[string]string) {
		data := map[string]string{}
		typ := ""
		top := -1
		for k, v := range ev {
			if k == "type" {
				typ = strings.ToUpper(v)
				continue
			}
			data[k] = v
			if n, ok := auditArg(k); ok && n > top {
				top = n
			}
		}
		if typ == "" {
			if !expect && slices.Contains(fields, "type") {
				// A near miss without the type: every record has one.
				return
			}
			typ = "SYSCALL"
			if top >= 0 {
				typ = "EXECVE"
			}
		}
		if typ == "EXECVE" && top >= 0 {
			for i := 0; i <= top; i++ {
				if _, ok := data[fmt.Sprintf("a%d", i)]; !ok {
					data[fmt.Sprintf("a%d", i)] = "arg"
				}
			}
			if _, ok := data["argc"]; !ok {
				data["argc"] = fmt.Sprint(top + 1)
			}
		}
		out = append(out, Case{Expect: expect, Source: "synthesized", Channel: AuditdChannel, EventID: typ, Data: data})
	}
	for _, ev := range syn.Positive {
		add(true, ev)
	}
	for _, ev := range syn.Negative {
		add(false, ev)
	}
	return out
}

// auditArg reads an EXECVE argument field's index (a0 is 0).
func auditArg(k string) (int, bool) {
	if len(k) < 2 || k[0] != 'a' {
		return 0, false
	}
	n := 0
	for _, r := range k[1:] {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// CasesOn is Cases with the channel the events are written to.
func CasesOn(channel, category string, syn *Synthesis, fields []string) []Case {
	id, ok := sysmonEvents[category]
	if !ok {
		return nil
	}
	also4688 := category == "process_creation" && channel == SysmonChannel
	for _, f := range fields {
		found := false
		for _, sig := range security4688 {
			if sig == f {
				found = true
			}
		}
		if !found {
			also4688 = false
		}
	}
	var out []Case
	add := func(expect bool, ev map[string]string) {
		eid := id
		if _, ok := ev["EventID"]; !ok && !expect && slices.Contains(fields, "EventID") {
			// A near miss without the event ID: every event has one.
			return
		}
		if _, ok := ev["Provider_Name"]; !ok && !expect && (channel == SystemChannel || channel == ApplicationChannel) && slices.Contains(fields, "Provider_Name") {
			// Nor without its provider.
			return
		}
		if v, ok := ev["EventID"]; ok {
			// A rule that names event IDs: the event is one of them, or
			// another event of the channel.
			eid = v
			ev = maps.Clone(ev)
			delete(ev, "EventID")
		}
		if n, err := strconv.Atoi(eid); err == nil && n < 1000 && channel == SecurityChannel {
			// A Windows 2000 or XP event, which never reaches Signalith
			// (Rule.EventIDs).
			return
		}
		out = append(out, Case{Expect: expect, Source: "synthesized", Channel: channel, EventID: eid, Data: ev})
		if also4688 {
			data := map[string]string{"SubjectUserName": "tester", "SubjectDomainName": "CORP"}
			for raw, sig := range security4688 {
				if v, ok := ev[sig]; ok {
					data[raw] = v
				}
			}
			out = append(out, Case{Expect: expect, Source: "synthesized", Channel: SecurityChannel, EventID: "4688", Data: data})
		}
	}
	for _, ev := range syn.Positive {
		add(true, ev)
	}
	for _, ev := range syn.Negative {
		add(false, ev)
	}
	return out
}

// Verify checks a converted detection filter against a rule's test
// events. Each event must be read the same way by the Sigma rule (Match)
// and, after the real Windows parser, by the filter (search.MatchDoc), and
// land in the detection's data model. It returns every disagreement.
func Verify(rule *Rule, datamodel string, filter query.Expr, tf *TestFile) []error {
	var errs []error
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i, c := range tf.Cases {
		where := fmt.Sprintf("case %d (%s %s %s, expect %v)", i, c.Source, c.Channel, c.EventID, c.Expect)
		view, ok := c.SigmaView()
		if !ok {
			errs = append(errs, fmt.Errorf("%s: no Sigma view of this channel", where))
			continue
		}
		if m, err := rule.Match(view); err != nil {
			errs = append(errs, fmt.Errorf("%s: Sigma: %v", where, err))
			continue
		} else if m != c.Expect {
			errs = append(errs, fmt.Errorf("%s: the Sigma rule says %v for %s", where, m, String(view)))
			continue
		}
		ev := c.Stored("test-host", now)
		if datamodel != "" && !strings.EqualFold(ev.Model, datamodel) {
			// An event of another data model never reaches the detection:
			// right for an event it must not match.
			if c.Expect {
				errs = append(errs, fmt.Errorf("%s: the parser put the event in %s, not %s", where, ev.Model, datamodel))
			}
			continue
		}
		m, err := search.MatchDoc(filter, ev.Document())
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", where, err))
			continue
		}
		if m != c.Expect {
			errs = append(errs, fmt.Errorf("%s: the detection says %v for %s", where, m, String(c.Data)))
		}
	}
	return errs
}

// EncodeTestFile writes a test file as JSON with one case per line, which
// keeps the files small and their diffs readable.
func EncodeTestFile(tf *TestFile) ([]byte, error) {
	var b bytes.Buffer
	rule, err := json.Marshal(tf.Rule)
	if err != nil {
		return nil, err
	}
	b.WriteString(`{"rule": ` + string(rule) + `, "cases": [`)
	for i, c := range tf.Cases {
		line, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("\n  ")
		b.Write(line)
	}
	b.WriteString("\n]}\n")
	return b.Bytes(), nil
}

// DecodeTestFile reads a test file.
func DecodeTestFile(data []byte) (*TestFile, error) {
	var tf TestFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return nil, err
	}
	return &tf, nil
}
