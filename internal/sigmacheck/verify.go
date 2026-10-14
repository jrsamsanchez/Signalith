package sigmacheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Windows channels the test events come from.
const (
	SysmonChannel     = "Microsoft-Windows-Sysmon/Operational"
	SecurityChannel   = "Security"
	SystemChannel     = ingest.SystemChannel
	PowerShellChannel = ingest.PowerShellChannel
	// LinuxSysmonChannel is Sysmon for Linux, whose events have Sysmon's
	// event IDs and fields.
	LinuxSysmonChannel = ingest.LinuxSysmonChannel
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
	case strings.EqualFold(c.Channel, SysmonChannel), strings.EqualFold(c.Channel, LinuxSysmonChannel),
		strings.EqualFold(c.Channel, PowerShellChannel) && c.EventID == "4104":
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
	"dns_query":            "22",
	"file_delete":          "26",
	"ps_script":            "4104",
	// Windows System log rules (service: system) are about services
	// installed.
	"system": "7045",
}

// SecurityEvents are the Security log events Security log rules
// (service: security) are checked for; such a rule's category is
// SecurityCategory of its one event.
var SecurityEvents = []string{"4624", "4625", "4663", "4697", "4698"}

// SecurityCategory is the category of a Security log rule about one
// event, as Bases, Cases and Channel know it.
func SecurityCategory(eventID string) string { return "security_" + eventID }

func init() {
	for _, id := range SecurityEvents {
		sysmonEvents[SecurityCategory(id)] = id
	}
}

// Channel returns the Windows channel a log source category's events come
// from.
func Channel(category string) string {
	switch category {
	case "ps_script":
		return PowerShellChannel
	case "system":
		return SystemChannel
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
	"security_4663": {
		"SubjectUserSid": "S-1-5-21-1000-1104", "SubjectUserName": "tester", "SubjectDomainName": "CORP", "SubjectLogonId": "0x1a2b3c",
		"ObjectServer": "Security", "ObjectType": "File", "ObjectName": `D:\apps\work\output.txt`, "HandleId": "0x1f4",
		"AccessList": "%%4416", "AccessMask": "0x1", "ProcessId": "0x1092", "ProcessName": `D:\apps\launcher\launcher.exe`,
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
	"system": {
		"ServiceName": "ExampleUpdater",
		"ImagePath":   `"D:\apps\updater\updater.exe" --service`,
		"ServiceType": "user mode service",
		"StartType":   "auto start",
		"AccountName": "LocalSystem",
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
		if _, ok := ev["Provider_Name"]; !ok && !expect && channel == SystemChannel && slices.Contains(fields, "Provider_Name") {
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
