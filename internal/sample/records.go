package sample

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/syslog"
)

// These helpers build the same records a Fluent Bit agent or a syslog
// device would send, then run them through the real ingest parsers
// (ingest.Normalize, syslog.Parse) so sample events are normalised into
// the same data models and fields as live data. Every event is stamped
// with the sample marker before it is returned.

const winTimeLayout = "2006-01-02 15:04:05 -0700"

// builder collects events and stamps each with the load's marker.
type builder struct {
	id     string // the sample load ID (marker value)
	now    time.Time
	events []ingest.Event
}

func (b *builder) emit(ev ingest.Event) {
	if ev.Fields == nil {
		ev.Fields = map[string]any{}
	}
	ev.Fields[ingest.SampleField] = b.id
	b.events = append(b.events, ev)
}

// win adds a Windows Security event. inserts are the StringInserts in
// schema order; missing trailing values may be "".
func (b *builder) win(h Host, eventID string, t time.Time, msg string, inserts ...string) {
	rec := map[string]any{
		"Channel":       "Security",
		"Computer":      h.Name,
		"EventID":       json.Number(eventID),
		"TimeCreated":   t.Format(winTimeLayout),
		"Message":       msg,
		"StringInserts": toAny(inserts),
	}
	b.emit(ingest.Normalize("win.events", rec, t))
}

// sysmon adds a Sysmon event (channel Microsoft-Windows-Sysmon/Operational)
// whose "Key: Value" message the parser reads. kv keeps insertion order via
// the slice of pairs.
func (b *builder) sysmon(h Host, eventID string, t time.Time, kv [][2]string) {
	var sb strings.Builder
	for _, p := range kv {
		fmt.Fprintf(&sb, "%s: %s\n", p[0], p[1])
	}
	rec := map[string]any{
		"Channel":     "Microsoft-Windows-Sysmon/Operational",
		"Computer":    h.Name,
		"EventID":     json.Number(eventID),
		"TimeCreated": t.Format(winTimeLayout),
		"Message":     sb.String(),
	}
	b.emit(ingest.Normalize("win.events", rec, t))
}

// syslogLine adds a Linux syslog line (auth.log / secure style) through the
// agent's linux.auth path, with an exact ISO 8601 timestamp.
func (b *builder) syslogLine(h Host, prog, pid, msg string, t time.Time) {
	line := fmt.Sprintf("%s %s %s[%s]: %s", t.UTC().Format(time.RFC3339), h.Name, prog, pid, msg)
	rec := map[string]any{"log": line}
	ev := ingest.Normalize("linux.auth", rec, t)
	b.emit(ev)
}

// cef adds a firewall / proxy event as a CEF syslog message through the
// syslog receiver, so it lands in Network_Traffic like a real appliance.
// device is the appliance IP the message appears to come from.
func (b *builder) cef(device string, t time.Time, name, sigID, severity string, ext map[string]string) {
	var sb strings.Builder
	// rt in epoch millis gives an exact event time.
	fmt.Fprintf(&sb, "rt=%d", t.UnixMilli())
	// Sorted so the line (and so the generated event) is deterministic.
	keys := make([]string, 0, len(ext))
	for k := range ext {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&sb, " %s=%s", k, ext[k])
	}
	header := fmt.Sprintf("CEF:0|Example|Firewall|2.1|%s|%s|%s|", sigID, name, severity)
	line := fmt.Sprintf("<134>%s %s SampleFW: %s%s", t.UTC().Format(time.RFC3339), device, header, sb.String())
	m := syslog.Parse([]byte(line), t)
	ev := m.Event(mustAddr(device), t, 0)
	b.emit(ev)
}

// defender adds a Microsoft Defender Antivirus event from the Defender
// channel, the way the Windows agent collects it. msg is the rendered
// message the parser reads ("Label: value" lines); inserts are the event
// data values, which the parser reads only when the message names nothing.
func (b *builder) defender(h Host, eventID string, t time.Time, msg string, inserts ...string) {
	rec := map[string]any{
		"Channel":     ingest.DefenderChannel,
		"Computer":    h.Name,
		"EventID":     json.Number(eventID),
		"TimeCreated": t.Format(winTimeLayout),
		"Message":     msg,
	}
	if len(inserts) > 0 {
		rec["StringInserts"] = toAny(inserts)
	}
	b.emit(ingest.Normalize("win.events", rec, t))
}

// clamav adds a ClamAV log line the way the Linux agent tails it from
// /var/log/clamav: file is the log file (clamav.log or freshclam.log),
// line is the text as ClamAV writes it, with its local-time prefix.
func (b *builder) clamav(h Host, file, line string, t time.Time) {
	rec := map[string]any{
		"log":      line,
		"file":     file,
		"hostname": h.Name,
		"date":     float64(t.Unix()),
	}
	b.emit(ingest.Normalize("linux.clamav", rec, t))
}

// cefAV adds a CEF event from an antivirus console through the syslog
// receiver, like cef but with any vendor and product in the header.
// Extension values are escaped as CEF requires (backslash and equals).
func (b *builder) cefAV(device string, t time.Time, vendor, product, version, sigID, name, severity string, ext map[string]string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "rt=%d", t.UnixMilli())
	keys := make([]string, 0, len(ext))
	for k := range ext {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	esc := strings.NewReplacer(`\`, `\\`, "=", `\=`)
	for _, k := range keys {
		fmt.Fprintf(&sb, " %s=%s", k, esc.Replace(ext[k]))
	}
	header := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%s|", vendor, product, version, sigID, name, severity)
	line := fmt.Sprintf("<134>%s %s SampleAV: %s%s", t.UTC().Format(time.RFC3339), device, header, sb.String())
	m := syslog.Parse([]byte(line), t)
	b.emit(m.Event(mustAddr(device), t, 0))
}

// generic adds an event that no agent parser maps (DNS lookups, and the
// like); it lands in Other, searchable by its fields. tag is a Fluent Bit
// tag the generic parser falls through on.
func (b *builder) generic(t time.Time, sourcetype string, fields map[string]any) {
	ev := ingest.Event{Time: t, Model: "Other", Fields: map[string]any{}}
	for k, v := range fields {
		ev.Fields[k] = v
	}
	ev.Fields["sourcetype"] = sourcetype
	if _, ok := ev.Fields["message"]; !ok {
		raw, _ := json.Marshal(fields)
		ev.Fields["message"] = string(raw)
	}
	b.emit(ev)
}

// signalith adds an event Signalith writes about itself (intake
// signalith), such as a silent sensor's.
func (b *builder) signalith(t time.Time, sourcetype string, fields map[string]any) {
	ev := ingest.Event{Time: t, Model: "Other", Fields: map[string]any{}, Origin: ingest.Origin{Intake: ingest.IntakeSignalith}}
	for k, v := range fields {
		ev.Fields[k] = v
	}
	ev.Fields["sourcetype"] = sourcetype
	b.emit(ev)
}

// sensorHost is the network sensor the sample's Zeek and Suricata events
// come from, as Fluent Bit's sysinfo filter names it.
const sensorHost = "nsm-01"

// zeek adds one Zeek log line (log is the log type: conn, dns, http, ...)
// the way the sensor's Fluent Bit tails it from Zeek's JSON logs: rec gets
// Zeek's epoch "ts", is written as one JSON line, and goes through the real
// Zeek parser. The event keeps the parser's document ID.
func (b *builder) zeek(log string, t time.Time, rec map[string]any) {
	line := sensorLine(rec, "ts", float64(t.UnixMicro())/1e6)
	ev := ingest.Normalize(ingest.ZeekTag+"."+log, map[string]any{"log": line, "hostname": sensorHost}, t)
	// A notice about one address (an Address_Scan) is local when the
	// scanner is: the parser counts private ranges as local, and the
	// sample's company range stands in for one of them.
	if src, _ := ev.Fields["src"].(string); log == "notice" && ev.Fields["local_host"] == nil && Internal(src) {
		ev.Fields["local_host"] = src
	}
	b.emit(ev)
}

// eveTimeLayout is the timestamp layout of Suricata's eve.json.
const eveTimeLayout = "2006-01-02T15:04:05.000000-0700"

// eve adds one Suricata EVE event, read from eve.json by the sensor's
// Fluent Bit and parsed by the real Suricata parser. rec gets the EVE
// timestamp and the sensor's host name.
func (b *builder) eve(t time.Time, rec map[string]any) {
	rec["host"] = sensorHost
	line := sensorLine(rec, "timestamp", t.UTC().Format(eveTimeLayout))
	b.emit(ingest.Normalize(ingest.SuricataTag+".eve", map[string]any{"log": line, "hostname": sensorHost}, t))
}

// sensorStatus adds one status line of the sensor's status.sh, read by
// the sensor's Fluent Bit and parsed by the real status line parser.
func (b *builder) sensorStatus(t time.Time, rec map[string]any) {
	rec["kind"], rec["v"], rec["host"], rec["role"] = "signalith-sensor-status", 1, sensorHost, "sensor"
	line := sensorLine(rec, "time", t.UTC().Format(time.RFC3339))
	ev := ingest.Normalize(ingest.SensorStatusTag, map[string]any{"log": line, "hostname": sensorHost}, t)
	// As a sensor's token sends it: network-sensor-unhealthy believes
	// only those.
	ev.Origin = ingest.Origin{Intake: ingest.IntakeAgent, Purpose: "sensor"}
	b.emit(ev)
}

// sensorLine writes rec as one JSON line with its time first, as Zeek and
// Suricata do. The other keys follow in sorted order (json.Marshal sorts
// map keys), so a line, and so its document ID, is deterministic.
func sensorLine(rec map[string]any, timeKey string, t any) string {
	head, _ := json.Marshal(map[string]any{timeKey: t})
	delete(rec, timeKey)
	body, _ := json.Marshal(rec)
	if string(body) == "{}" {
		return string(head)
	}
	return string(head[:len(head)-1]) + "," + string(body[1:])
}

func toAny(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}
