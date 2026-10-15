package syslog

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// ESET PROTECT exports its logs to syslog as JSON (the default), LEEF or
// plain syslog. A JSON detection reads
//
//	{"event_type":"Threat_Event","ipv4":"192.0.2.27","hostname":"ws-fin-07","threat_name":"Win32/Agent.ABC",...}
//
// with the same keys as LEEF, so both go through the ESET rule of the
// vendor table. Some servers send stray bytes (a mangled byte order mark)
// before the JSON. Other ESET events keep the plain syslog mapping.

// esetMaxText is how much of a message is read as JSON.
const esetMaxText = 64 << 10

// esetThreat reports whether text is an ESET PROTECT JSON detection, and
// gives its record.
func esetThreat(text string, rec *avRecord) bool {
	t := strings.TrimLeft(text, ". \t\ufeff\ufffd")
	if len(t) > esetMaxText || !strings.HasPrefix(t, "{") || !strings.Contains(t[:min(len(t), 256)], `"event_type"`) {
		return false
	}
	d := json.NewDecoder(strings.NewReader(t))
	d.UseNumber()
	var m map[string]any
	if d.Decode(&m) != nil {
		return false
	}
	if et, _ := m["event_type"].(string); !strings.EqualFold(et, "Threat_Event") {
		return false
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	*rec = avRecord{vendor: "ESET", product: "PROTECT", eventID: "Threat_Event"}
	for _, k := range keys {
		var v string
		switch x := m[k].(type) {
		case string:
			v = x
		case bool:
			v = strconv.FormatBool(x)
		case json.Number:
			v = x.String()
		default:
			continue
		}
		if k == "severity" {
			rec.severity = v
			continue
		}
		if len(rec.params) < maxAVParams {
			rec.params = append(rec.params, Param{Name: k, Value: v})
		}
	}
	return true
}

// kasperskyThreat reports whether a message is a Kaspersky Endpoint
// Security event sent straight to syslog, with its details in structured
// data such as [event@23668 et="GNRL_EV_VIRUS_FOUND" hdn="WS-1" hip="192.0.2.27"]
// and its text as "Label: value" lines, and gives its record and fields.
func kasperskyThreat(m *Message, rec *avRecord, f map[string]any) bool {
	for _, el := range m.Data {
		if !strings.HasPrefix(el.ID, "event@23668") {
			continue
		}
		var et, name string
		for _, p := range el.Params {
			switch p.Name {
			case "et":
				et = p.Value
			case "etdn":
				name = p.Value
			case "hdn":
				f["dest_host"] = p.Value
			case "hip":
				f["dest"] = p.Value
			}
		}
		if _, ok := kasperskyEvents[strings.ToUpper(strings.TrimSpace(et))]; !ok {
			return false
		}
		*rec = avRecord{vendor: "Kaspersky", product: "Kaspersky Endpoint Security", eventID: et, name: name,
			// The text's line breaks are the characters \r\n; its
			// backslashes are single.
			params: []Param{{Name: "msg", Value: strings.ReplaceAll(m.Text, `\r\n`, "\n")}}}
		return true
	}
	return false
}
