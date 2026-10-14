package ingest

import (
	"encoding/xml"
	"sort"
	"strconv"
	"strings"
	"time"
)

// WinEventRecord builds the record Fluent Bit's winevtlog input sends for
// a Windows event with the given named data values: StringInserts in
// schema order for the Security, System and PowerShell events the parser
// reads, and for Sysmon a rendered message of "Name: Value" lines. A
// Provider_Name value is the event's provider rather than its data; a
// System event without one is the Service Control Manager's. Tests,
// sample data and the detection content checks use it to put events
// through the real parser.
func WinEventRecord(channel, eventID, computer string, t time.Time, data map[string]string) map[string]any {
	provider, named := data["Provider_Name"]
	if !named && channel == SystemChannel {
		provider = ServiceControlManager
	}
	names := make([]string, 0, len(data))
	for k := range data {
		if k != "Provider_Name" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	var inserts []any
	if schema, ok := windowsSchemaFor(channel, eventID); ok {
		for _, n := range schema {
			inserts = append(inserts, data[n])
		}
	} else {
		for _, n := range names {
			inserts = append(inserts, data[n])
		}
	}
	var msg strings.Builder
	if strings.EqualFold(channel, "Microsoft-Windows-Sysmon/Operational") {
		msg.WriteString("Sysmon event " + eventID + ":\n")
		for _, n := range names {
			msg.WriteString(n + ": " + data[n] + "\n")
		}
	} else {
		msg.WriteString("Windows event " + eventID)
	}
	return map[string]any{
		"Channel":       channel,
		"Computer":      computer,
		"EventID":       eventID,
		"ProviderName":  provider,
		"TimeCreated":   t.UTC().Format(time.RFC3339Nano),
		"Message":       msg.String(),
		"StringInserts": inserts,
	}
}

// LinuxSysmonChannel is Sysmon for Linux's channel, as its events name it.
const LinuxSysmonChannel = "Linux-Sysmon/Operational"

// LinuxSysmonRecord builds the systemd journal record Fluent Bit sends for
// a Sysmon for Linux event with the given named data values: the event's
// XML as the sysmon program's message. Its tag is linux.journal.
func LinuxSysmonRecord(eventID, computer string, t time.Time, data map[string]string) map[string]any {
	names := make([]string, 0, len(data))
	for k := range data {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(`<Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/><EventID>`)
	xmlText(&b, eventID)
	b.WriteString(`</EventID><TimeCreated SystemTime="` + t.UTC().Format(time.RFC3339Nano) + `"/><Channel>` + LinuxSysmonChannel + `</Channel><Computer>`)
	xmlText(&b, computer)
	b.WriteString(`</Computer></System><EventData>`)
	for _, n := range names {
		b.WriteString(`<Data Name="`)
		xmlText(&b, n)
		b.WriteString(`">`)
		xmlText(&b, data[n])
		b.WriteString(`</Data>`)
	}
	b.WriteString(`</EventData></Event>`)
	return map[string]any{
		"SYSLOG_IDENTIFIER":    "sysmon",
		"_HOSTNAME":            computer,
		"_PID":                 "1000",
		"MESSAGE":              b.String(),
		"__REALTIME_TIMESTAMP": strconv.FormatInt(t.UnixMicro(), 10),
	}
}

func xmlText(b *strings.Builder, s string) {
	_ = xml.EscapeText(b, []byte(s))
}
