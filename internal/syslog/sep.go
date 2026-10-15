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

// sepPairAt returns where the key of a pair starting at s begins: 0, or 1
// when SEPM quoted the whole pair ("Event Description: a, b"); -1 when s
// does not start a pair.
func sepPairAt(s string) int {
	if sepKeyLen(s) > 0 {
		return 0
	}
	if len(s) > 1 && s[0] == '"' && sepKeyLen(s[1:]) > 0 {
		return 1
	}
	return -1
}

// splitSEP returns the event name and the pairs of a SEP line.
func splitSEP(text string) (string, []Param) {
	text = truncate(text, sepMaxText)
	var bounds []int // where each ",Key: " starts
	for i := 0; i < len(text) && len(bounds) < sepMaxSegments-1; i++ {
		if text[i] == ',' && sepPairAt(text[i+1:]) >= 0 {
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
		quoted := sepPairAt(seg) == 1
		if quoted {
			seg = seg[1:]
		}
		k := sepKeyLen(seg)
		v := strings.TrimSpace(seg[k+2:])
		if quoted {
			// "Key: value", and anything after the closing quote.
			if i := strings.LastIndexByte(v, '"'); i >= 0 {
				v = strings.TrimSpace(v[:i])
			}
		} else if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1] // File path: "C:\a,b\x.xla"
		}
		pairs = append(pairs, Param{Name: seg[:k], Value: v})
	}
	return name, pairs
}

// parseSEP maps a SEP risk event, or a client's failed definitions update,
// onto the Malware data model. It reports false for other SEP events,
// which keep the plain syslog mapping.
func parseSEP(text string) (map[string]any, bool) {
	text = strings.TrimPrefix(text, "SymantecServer: ")
	name, pairs := splitSEP(text)
	kv := map[string]string{}
	for _, p := range pairs {
		if _, seen := kv[p.Name]; !seen {
			kv[p.Name] = p.Value
		}
	}
	switch name {
	case "Virus found", "Security risk found", "Potential risk found":
	default:
		return sepSystem(name, kv)
	}
	f := map[string]any{
		"sourcetype":     "symantec:sep",
		"vendor_product": "Symantec Endpoint Protection",
		"type":           ingest.MalwareThreat,
	}
	ingest.SetValue(f, "dest_ip", kv["IP Address"])
	ingest.SetValue(f, "dest", truncate(kv["Computer name"], maxHostLen))
	ingest.SetValue(f, "detection_source", kv["Source"])
	path := kv["File path"]
	if _, ok := kv["File path"]; !ok {
		// Older SEPM versions write the path with no key, after the
		// occurrences: "Occurrences: 1,C:\x\a.exe,Description,...".
		if _, rest, ok := strings.Cut(kv["Occurrences"], ","); ok {
			path, _, _ = strings.Cut(rest, ",")
			path = strings.Trim(path, `" `)
		}
	}
	ingest.SetFilePath(f, path)
	ingest.SetValue(f, "vendor_action", kv["Actual action"])
	// Older versions say "User" where newer ones say "User Name".
	ingest.SetValue(f, "user", first(kv["User Name"], kv["User"]))
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

// sepSystem reads a client's system log line, "host,Category: 2,LiveUpdate
// Manager,Event Description: ...", and maps a failed content update onto a
// Malware health event about that host.
func sepSystem(host string, kv map[string]string) (map[string]any, bool) {
	if _, ok := kv["Category"]; !ok {
		return nil, false
	}
	desc := kv["Event Description"]
	d := strings.ToLower(desc)
	if !strings.Contains(d, "update") || !containsAny(d, "fail", "unable") {
		return nil, false
	}
	f := map[string]any{
		"sourcetype":     "symantec:sep",
		"vendor_product": "Symantec Endpoint Protection",
		"type":           ingest.MalwareHealth,
		"action":         "update_failed",
		"signature":      "Definitions update failed",
	}
	ingest.SetValue(f, "dest", truncate(host, maxHostLen))
	ingest.SetValue(f, "reason", desc)
	return f, true
}
