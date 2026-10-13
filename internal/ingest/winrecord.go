package ingest

import (
	"sort"
	"strings"
	"time"
)

// WinEventRecord builds the record Fluent Bit's winevtlog input sends for
// a Windows event with the given named data values: StringInserts in
// schema order for the Security events the parser reads, and for Sysmon
// a rendered message of "Name: Value" lines. Tests, sample data and the
// detection content checks use it to put events through the real parser.
func WinEventRecord(channel, eventID, computer string, t time.Time, data map[string]string) map[string]any {
	names := make([]string, 0, len(data))
	for k := range data {
		names = append(names, k)
	}
	sort.Strings(names)
	var inserts []any
	if schema, ok := windowsSchema[eventID]; ok && channel == "Security" {
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
		"TimeCreated":   t.UTC().Format(time.RFC3339Nano),
		"Message":       msg.String(),
		"StringInserts": inserts,
	}
}
