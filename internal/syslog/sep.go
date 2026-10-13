package syslog

import (
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// Symantec Endpoint Protection Manager sends its logs as syslog from the
// program SymantecServer, one event per line: the event name, then
// "Key: value" pairs separated by commas, as in
//
//	Virus found,IP Address: 192.0.2.27,Computer name: ws-fin-07,...,Risk name: Trojan.Gen.2,...
//
// Values may contain commas, so a pair starts only at a comma followed by
// something that looks like a key.

const (
	sepMaxText     = 16 << 10
	sepMaxSegments = 80
	sepMaxKey      = 40
)

// isSEP reports whether a message comes from Symantec Endpoint Protection
// Manager.
func isSEP(app, text string) bool {
	return strings.EqualFold(app, "SymantecServer") || strings.HasPrefix(text, "SymantecServer: ")
}

// sepKeyLen returns the length of a key at the start of s, "Risk name" in
// "Risk name: x", or 0: up to 40 bytes that start with an upper-case
// letter and hold only letters, digits, spaces, '(', ')' or '/', followed
// by ": ".
func sepKeyLen(s string) int {
	if s == "" || s[0] < 'A' || s[0] > 'Z' {
		return 0
	}
	for i := 1; i < len(s) && i <= sepMaxKey; i++ {
		c := s[i]
		switch {
		case c == ':':
			if i+1 < len(s) && s[i+1] == ' ' {
				return i
			}
			return 0
		case isAlnum(c), c == ' ', c == '(', c == ')', c == '/':
		default:
			return 0
		}
	}
	return 0
}

// splitSEP returns the event name and the pairs of a SEP line.
func splitSEP(text string) (string, []Param) {
	text = truncate(text, sepMaxText)
	var bounds []int // where each ",Key: " starts
	for i := 0; i < len(text) && len(bounds) < sepMaxSegments-1; i++ {
		if text[i] == ',' && sepKeyLen(text[i+1:]) > 0 {
			bounds = append(bounds, i)
		}
	}
	if len(bounds) == 0 {
		return strings.TrimSpace(text), nil
	}
	name := strings.TrimSpace(text[:bounds[0]])
	pairs := make([]Param, 0, len(bounds))
	for n, b := range bounds {
		end := len(text)
		if n+1 < len(bounds) {
			end = bounds[n+1]
		}
		seg := text[b+1 : end]
		k := sepKeyLen(seg)
		pairs = append(pairs, Param{Name: seg[:k], Value: strings.TrimSpace(seg[k+2:])})
	}
	return name, pairs
}

// parseSEP maps a SEP risk event onto the Malware data model. It reports
// false for other SEP events, which keep the plain syslog mapping.
func parseSEP(text string) (map[string]any, bool) {
	text = strings.TrimPrefix(text, "SymantecServer: ")
	name, pairs := splitSEP(text)
	switch name {
	case "Virus found", "Security risk found", "Potential risk found":
	default:
		return nil, false
	}
	kv := map[string]string{}
	for _, p := range pairs {
		if _, seen := kv[p.Name]; !seen {
			kv[p.Name] = p.Value
		}
	}
	f := map[string]any{
		"sourcetype":     "symantec:sep",
		"vendor_product": "Symantec Endpoint Protection",
		"type":           ingest.MalwareThreat,
	}
	ingest.SetValue(f, "dest_ip", kv["IP Address"])
	ingest.SetValue(f, "dest", truncate(kv["Computer name"], maxHostLen))
	ingest.SetValue(f, "detection_source", kv["Source"])
	ingest.SetFilePath(f, kv["File path"])
	ingest.SetValue(f, "vendor_action", kv["Actual action"])
	ingest.SetValue(f, "user", kv["User Name"])
	ingest.SetFileHash(f, kv["Application hash"])
	if n, err := strconv.ParseInt(strings.TrimSpace(kv["File size (bytes)"]), 10, 64); err == nil && n >= 0 {
		f["file_size"] = n
	}
	ingest.SetValue(f, "vendor_category", kv["Category type"])
	sig := ingest.CapValue(kv["Risk name"])
	if sig == "" {
		sig = ingest.UnknownThreat
	}
	f["signature"] = sig
	f["action"] = ingest.MalwareAction(kv["Actual action"])
	vc, _ := f["vendor_category"].(string)
	f["category"] = ingest.MalwareCategory(sig, vc)
	return f, true
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
