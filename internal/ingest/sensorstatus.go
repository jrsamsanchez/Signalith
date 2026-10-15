package ingest

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// A sensor the sensor install script built (deploy/sensor/install.sh)
// writes a status line every 5 minutes (/usr/lib/signalith-sensor/
// status.sh), which its agent sends under the tag sensor.status: versions,
// whether Zeek and Suricata run, the rules' age, the capture port and its
// packet drops, and free disk. Each line is stored as an event, and its
// values go to the agent's row on the Endpoints page (Result.Sensor).

// SensorStatusTag is the tag of the sensor status line, and
// SensorStatusVendor the vendor_product of its events.
const (
	SensorStatusTag    = "sensor.status"
	SensorStatusVendor = "Signalith sensor"
	sensorStatusKind   = "signalith-sensor-status"
	// maxSensorWarnings caps the warnings kept from one line, and
	// maxSensorWord the length of a version, name or state.
	maxSensorWarnings = 16
	maxSensorWord     = 64
)

// SensorStatus is what a sensor's newest status line says, as the agent
// inventory keeps it for the Endpoints and Health pages.
type SensorStatus struct {
	// At is the line's own time.
	At       time.Time   `json:"at"`
	Role     string      `json:"role,omitempty"`
	Version  string      `json:"version,omitempty"`
	Layout   string      `json:"layout,omitempty"`
	Zeek     *SensorTool `json:"zeek,omitempty"`
	Suricata *SensorTool `json:"suricata,omitempty"`
	// FluentBit is the agent's version.
	FluentBit string `json:"fluentbit,omitempty"`
	// RulesUpdated is when the Suricata rules were last updated (RFC
	// 3339), RulesUpdate how the last try went (ok, failed, never).
	RulesUpdated string `json:"rules_updated,omitempty"`
	RulesCount   int64  `json:"rules_count,omitempty"`
	RulesUpdate  string `json:"rules_update,omitempty"`
	// Interface is the capture port, Link its state (up, down).
	Interface string `json:"interface,omitempty"`
	Link      string `json:"link,omitempty"`
	Packets   int64  `json:"packets,omitempty"`
	Dropped   int64  `json:"dropped,omitempty"`
	// DropPercent is the share of packets dropped since the line before.
	DropPercent     float64 `json:"drop_percent"`
	DiskFreePercent float64 `json:"disk_free_percent"`
	DiskFreeBytes   int64   `json:"disk_free_bytes,omitempty"`
	DiskEncrypted   bool    `json:"disk_encrypted"`
	TimeSynced      bool    `json:"time_synced"`
	// Warnings are the IDs of what the line found wrong (capture_ip,
	// capture_link, no_traffic, drops, rules_old, rules_failed,
	// zeek_stopped, suricata_stopped, disk_low, time_not_synced).
	Warnings []string `json:"warnings,omitempty"`
}

// SensorTool is one of the sensor's programs.
type SensorTool struct {
	Version string `json:"version,omitempty"`
	Running bool   `json:"running"`
}

// parseSensorStatus maps a status line, sent in "log", to an event that
// carries its values in Sensor too. Anything else under the tag is kept
// as a generic event.
func parseSensorStatus(r map[string]any) Event {
	line, _ := r["log"].(string)
	rec, ok := decodeSensorLine(line)
	if !ok || wstr(rec["kind"]) != sensorStatusKind {
		ev := parseGeneric(r)
		ev.Fields["sourcetype"] = "sensor:status"
		ev.Fields["vendor_product"] = SensorStatusVendor
		return ev
	}
	raw := strings.TrimSpace(line)
	s := &SensorStatus{
		Role:         word(rec["role"]),
		Version:      word(rec["sensor_version"]),
		Layout:       word(rec["layout"]),
		FluentBit:    word(wget(rec, "fluentbit", "version")),
		RulesUpdated: word(wget(rec, "rules", "updated")),
		RulesUpdate:  word(wget(rec, "rules", "update")),
		Interface:    word(wget(rec, "interface", "name")),
		Link:         word(wget(rec, "interface", "link")),
	}
	if t, err := time.Parse(time.RFC3339, wstr(rec["time"])); err == nil {
		s.At = t.UTC()
	}
	for _, tool := range []struct {
		key string
		dst **SensorTool
	}{{"zeek", &s.Zeek}, {"suricata", &s.Suricata}} {
		if t, ok := rec[tool.key].(map[string]any); ok {
			*tool.dst = &SensorTool{Version: word(t["version"]), Running: t["running"] == true}
		}
	}
	s.RulesCount, _ = intOf(wget(rec, "rules", "count"))
	s.Packets, _ = intOf(wget(rec, "interface", "rx_packets"))
	s.Dropped, _ = intOf(wget(rec, "interface", "rx_dropped"))
	s.DiskFreeBytes, _ = intOf(wget(rec, "disk", "free_bytes"))
	s.DropPercent = percent(wget(rec, "interface", "drop_percent"))
	s.DiskFreePercent = percent(wget(rec, "disk", "free_percent"))
	s.DiskEncrypted = wget(rec, "disk", "encrypted") == true
	s.TimeSynced = rec["time_synced"] == true
	if l, ok := rec["warnings"].([]any); ok {
		for _, w := range l {
			if w := word(w); w != "" && len(s.Warnings) < maxSensorWarnings {
				s.Warnings = append(s.Warnings, w)
			}
		}
	}

	host := word(rec["host"])
	if h := strings.TrimSpace(wstr(r["hostname"])); h != "" && len(h) <= 255 {
		host = h
	}
	f := map[string]any{
		"sourcetype":     "sensor:status",
		"vendor_product": SensorStatusVendor,
		"signature":      "Sensor status",
		"message":        s.Summary(host),
	}
	if host != "" {
		f["host"], f["dvc"] = host, host
	}
	setStr(f, "sensor_role", s.Role)
	setStr(f, "sensor_version", s.Version)
	setStr(f, "fluentbit_version", s.FluentBit)
	if s.Zeek != nil {
		setStr(f, "zeek_version", s.Zeek.Version)
		f["sensor_zeek_running"] = yesNo(s.Zeek.Running)
	}
	if s.Suricata != nil {
		setStr(f, "suricata_version", s.Suricata.Version)
		f["sensor_suricata_running"] = yesNo(s.Suricata.Running)
		setStr(f, "rules_updated", s.RulesUpdated)
		setStr(f, "rules_update", s.RulesUpdate)
		if n, ok := intOf(wget(rec, "rules", "count")); ok {
			f["rules_count"] = n
		}
	}
	setStr(f, "sensor_interface", s.Interface)
	setStr(f, "sensor_link", s.Link)
	if _, ok := intOf(wget(rec, "interface", "rx_packets")); ok {
		f["packets_received"] = s.Packets
	}
	if _, ok := intOf(wget(rec, "interface", "rx_dropped")); ok {
		f["packets_dropped"] = s.Dropped
	}
	f["drop_percent"] = s.DropPercent
	f["disk_free_percent"] = s.DiskFreePercent
	if _, ok := intOf(wget(rec, "disk", "free_bytes")); ok {
		f["disk_free_bytes"] = s.DiskFreeBytes
	}
	f["sensor_disk_encrypted"] = yesNo(s.DiskEncrypted)
	f["sensor_time_synced"] = yesNo(s.TimeSynced)
	if len(s.Warnings) > 0 {
		f["sensor_warnings"] = s.Warnings
	}

	return Event{Time: s.At, Model: "Other", Fields: f, ID: sensorDocID("sensor:status", raw), Sensor: s}
}

// Summary is the status line in one sentence, the event's message:
// "nsm-01: Zeek 8.0.4 running, Suricata 8.0.1 running, rules 1 day old,
// ens192 up, 0.1% dropped, 63% disk free".
func (s *SensorStatus) Summary(host string) string {
	var parts []string
	for _, t := range []struct {
		name string
		tool *SensorTool
	}{{"Zeek", s.Zeek}, {"Suricata", s.Suricata}} {
		if t.tool == nil {
			continue
		}
		state := "stopped"
		if t.tool.Running {
			state = "running"
		}
		parts = append(parts, strings.TrimSpace(t.name+" "+t.tool.Version)+" "+state)
	}
	if s.Suricata != nil {
		switch {
		case s.RulesUpdate == "failed":
			parts = append(parts, "rules update failed")
		case s.RulesUpdated != "":
			if t, err := time.Parse(time.RFC3339, s.RulesUpdated); err == nil && !s.At.IsZero() {
				parts = append(parts, "rules "+age(s.At.Sub(t))+" old")
			} else {
				parts = append(parts, "rules from "+s.RulesUpdated)
			}
		default:
			parts = append(parts, "no rules yet")
		}
	}
	if s.Interface != "" {
		parts = append(parts, strings.TrimSpace(s.Interface+" "+s.Link))
	}
	parts = append(parts, fmt.Sprintf("%g%% dropped", s.DropPercent), fmt.Sprintf("%g%% disk free", s.DiskFreePercent))
	msg := strings.Join(parts, ", ")
	if host != "" {
		msg = host + ": " + msg
	}
	return msg
}

// age writes a duration as whole days, or hours under a day.
func age(d time.Duration) string {
	switch h := int(d.Hours()); {
	case h < 1:
		return "less than an hour"
	case h < 24:
		return plural(h, "hour")
	default:
		return plural(h/24, "day")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// word returns a short text value of the status line: no control
// characters, at most maxSensorWord bytes.
func word(v any) string {
	s := strings.TrimSpace(wstr(v))
	if len(s) > maxSensorWord || strings.ContainsFunc(s, func(c rune) bool { return c < ' ' || c == 0x7f }) {
		return ""
	}
	return s
}

// percent returns a share from 0 to 100, rounded to a hundredth.
func percent(v any) float64 {
	p, ok := floatOf(v)
	if !ok || p < 0 {
		return 0
	}
	return math.Round(math.Min(p, 100)*100) / 100
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
