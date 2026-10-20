// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package syslog

import (
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// CEF is one ArcSight Common Event Format record:
// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
type CEF struct {
	Version       string
	Vendor        string
	Product       string
	DeviceVersion string
	SignatureID   string
	Name          string
	Severity      string
	// Extension holds the key=value pairs in the order they appeared,
	// with escapes resolved.
	Extension []Param
}

// parseCEF reads a CEF record. Header fields escape '|' and '\' with a
// backslash; it reports false when the seven header fields are not all
// there.
func parseCEF(s string) (*CEF, bool) {
	if !strings.HasPrefix(s, "CEF:") {
		return nil, false
	}
	body := s[len("CEF:"):]
	var hdr [7]string
	n, start := 0, 0
	for i := 0; i < len(body) && n < len(hdr); i++ {
		switch body[i] {
		case '\\':
			i++
		case '|':
			hdr[n] = unescapeHeader(body[start:i])
			n++
			start = i + 1
		}
	}
	if n < len(hdr) {
		return nil, false
	}
	version := strings.TrimSpace(hdr[0])
	if version == "" || strings.Trim(version, "0123456789") != "" {
		return nil, false
	}
	return &CEF{
		Version:       version,
		Vendor:        strings.TrimSpace(hdr[1]),
		Product:       strings.TrimSpace(hdr[2]),
		DeviceVersion: strings.TrimSpace(hdr[3]),
		SignatureID:   strings.TrimSpace(hdr[4]),
		Name:          strings.TrimSpace(hdr[5]),
		Severity:      strings.TrimSpace(hdr[6]),
		Extension:     parseExtension(body[start:]),
	}, true
}

func unescapeHeader(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '\\') {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.'
}

// parseExtension splits "key=value key2=value with spaces" into pairs. A
// key starts after a space and ends at an unescaped '='; a value runs to the
// space before the next key, so values may contain spaces, and '=' inside a
// value (escaped as \= or, leniently, unescaped in the middle of a word as
// in URLs) does not start a new key.
func parseExtension(s string) []Param {
	type key struct{ start, value int } // key text is s[start:value-1]
	var keys []key
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
			continue
		case '=':
		default:
			continue
		}
		j := i
		for j > 0 && isKeyChar(s[j-1]) {
			j--
		}
		if j == i || (j > 0 && s[j-1] != ' ') {
			continue
		}
		keys = append(keys, key{start: j, value: i + 1})
	}
	out := make([]Param, 0, len(keys))
	for n, k := range keys {
		end := len(s)
		if n+1 < len(keys) {
			end = keys[n+1].start
		}
		out = append(out, Param{
			Name:  s[k.start : k.value-1],
			Value: unescapeValue(strings.TrimSpace(s[k.value:end])),
		})
	}
	return out
}

func unescapeValue(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '=', '\\', '|':
				b.WriteByte(s[i+1])
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			case 'r':
				b.WriteByte('\r')
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// cefField says where a well-known CEF key goes.
type cefField struct {
	name    string
	numeric bool
}

// cefFields maps CEF keys (short and full names) to CIM field names.
var cefFields = map[string]cefField{
	"src": {name: "src"}, "sourceAddress": {name: "src"},
	"dst": {name: "dest"}, "destinationAddress": {name: "dest"},
	"spt": {name: "src_port", numeric: true}, "sourcePort": {name: "src_port", numeric: true},
	"dpt": {name: "dest_port", numeric: true}, "destinationPort": {name: "dest_port", numeric: true},
	"shost": {name: "src_host"}, "sourceHostName": {name: "src_host"},
	"dhost": {name: "dest_host"}, "destinationHostName": {name: "dest_host"},
	"smac": {name: "src_mac"}, "sourceMacAddress": {name: "src_mac"},
	"dmac": {name: "dest_mac"}, "destinationMacAddress": {name: "dest_mac"},
	"suser": {name: "src_user"}, "sourceUserName": {name: "src_user"},
	"duser": {name: "dest_user"}, "destinationUserName": {name: "dest_user"},
	"sntdom": {name: "src_nt_domain"}, "sourceNtDomain": {name: "src_nt_domain"},
	"dntdom": {name: "dest_nt_domain"}, "destinationNtDomain": {name: "dest_nt_domain"},
	"sourceTranslatedAddress":      {name: "src_translated_ip"},
	"destinationTranslatedAddress": {name: "dest_translated_ip"},
	"sourceTranslatedPort":         {name: "src_translated_port", numeric: true},
	"destinationTranslatedPort":    {name: "dest_translated_port", numeric: true},
	"deviceInboundInterface":       {name: "src_interface"},
	"deviceOutboundInterface":      {name: "dest_interface"},
	"app":                          {name: "app"}, "applicationProtocol": {name: "app"},
	"in": {name: "bytes_in", numeric: true}, "bytesIn": {name: "bytes_in", numeric: true},
	"out": {name: "bytes_out", numeric: true}, "bytesOut": {name: "bytes_out", numeric: true},
	"request": {name: "url"}, "requestUrl": {name: "url"},
	"requestMethod":            {name: "http_method"},
	"requestClientApplication": {name: "http_user_agent"},
	"requestContext":           {name: "http_referrer"},
	"fname":                    {name: "file_name"}, "fileName": {name: "file_name"},
	"filePath": {name: "file_path"},
	"fileHash": {name: "file_hash"},
	"fsize":    {name: "file_size", numeric: true}, "fileSize": {name: "file_size", numeric: true},
	"dproc": {name: "process_name"}, "destinationProcessName": {name: "process_name"},
	"dpid": {name: "process_id", numeric: true}, "destinationProcessId": {name: "process_id", numeric: true},
	"cat": {name: "category"}, "deviceEventCategory": {name: "category"},
	"reason":  {name: "reason"},
	"dvchost": {name: "dvc_host"}, "deviceHostName": {name: "dvc_host"},
}

var cefActions = map[string]string{
	"accept": "allowed", "accepted": "allowed", "allow": "allowed", "allowed": "allowed",
	"permit": "allowed", "permitted": "allowed", "pass": "allowed", "passed": "allowed",
	"deny": "blocked", "denied": "blocked", "drop": "blocked", "dropped": "blocked",
	"block": "blocked", "blocked": "blocked", "reject": "blocked", "rejected": "blocked",
	"prevent": "blocked", "prevented": "blocked", "reset": "blocked",
	"close": "teardown", "closed": "teardown", "teardown": "teardown",
}

var ipProtocols = map[string]string{"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "58": "icmpv6", "132": "sctp"}

// cefFieldsFor maps a CEF record onto CIM fields. Well-known keys get CIM
// names; other keys are kept as cef_<key>, at most extra of them. It also
// returns the event time from rt, end or start, when one parses; now gives
// times without a year the right one.
func cefFieldsFor(c *CEF, f map[string]any, extra *int, now time.Time) time.Time {
	f["sourcetype"] = "cef"
	f["vendor_product"] = vendorProduct(c.Vendor, c.Product)
	f["signature"] = c.Name
	f["signature_id"] = c.SignatureID
	f["cef_version"] = c.Version
	f["cef_vendor"] = c.Vendor
	f["cef_product"] = c.Product
	f["cef_device_version"] = c.DeviceVersion
	if sev, id := cefSeverity(c.Severity); sev != "" {
		f["severity"] = sev
		if id != nil {
			f["severity_id"] = id
		}
	}
	var t time.Time
	times := map[string]string{}
	for _, p := range c.Extension {
		v := p.Value
		if v == "" {
			continue
		}
		switch p.Name {
		case "act", "deviceAction":
			f["vendor_action"] = v
			if a, ok := cefActions[strings.ToLower(v)]; ok {
				f["action"] = a
			} else {
				f["action"] = strings.ToLower(v)
			}
			continue
		case "proto", "transportProtocol":
			v = strings.ToLower(v)
			if name, ok := ipProtocols[v]; ok {
				v = name
			}
			f["transport"] = v
			continue
		case "deviceDirection":
			switch v {
			case "0":
				f["direction"] = "inbound"
			case "1":
				f["direction"] = "outbound"
			}
			continue
		case "rt", "deviceReceiptTime", "end", "endTime", "start", "startTime":
			times[p.Name] = v
		}
		if cf, ok := cefFields[p.Name]; ok {
			if !cf.numeric {
				f[cf.name] = v
				continue
			}
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				f[cf.name] = n
				continue
			}
		}
		addExtra(f, "cef_", p.Name, v, extra)
	}
	switch {
	case f["dest_user"] != nil:
		f["user"] = f["dest_user"]
	case f["src_user"] != nil:
		f["user"] = f["src_user"]
	}
	in, hasIn := f["bytes_in"].(int64)
	out, hasOut := f["bytes_out"].(int64)
	if hasIn || hasOut {
		f["bytes"] = in + out
	}
	for _, k := range []string{"rt", "deviceReceiptTime", "end", "endTime", "start", "startTime"} {
		if v, ok := times[k]; ok {
			if t2, ok := cefTime(v, now); ok {
				t = t2
				break
			}
		}
	}
	return t
}

// addExtra stores a vendor-specific field under prefix plus a cleaned-up
// lower-case key, unless the message already added max extra fields.
func addExtra(f map[string]any, prefix, key, value string, extra *int) {
	name := fieldName(key)
	if name == "" || *extra >= maxExtraFields {
		return
	}
	name = prefix + name
	if _, dup := f[name]; !dup {
		*extra++
	}
	f[name] = value
}

// fieldName turns a vendor key into a safe field name: lower case letters,
// digits and underscores, at most 64 characters.
func fieldName(key string) string {
	clean := len(key) <= 64 && key != "" && key[0] != '_' && key[len(key)-1] != '_'
	for i := 0; clean && i < len(key); i++ {
		c := key[i]
		clean = c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
	}
	if clean {
		return key
	}
	var b strings.Builder
	for i := 0; i < len(key) && b.Len() < 64; i++ {
		c := key[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 'a' - 'A')
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func vendorProduct(vendor, product string) string {
	if vendor == "" || strings.HasPrefix(strings.ToLower(product), strings.ToLower(vendor)) {
		return product
	}
	return strings.TrimSpace(vendor + " " + product)
}

// cefSeverity maps CEF severity (0-10, or Low, Medium, High, Very-High)
// to CIM severity, ArcSight style: 0-3 low, 4-6 medium, 7-8 high, 9-10
// critical. The number is returned as severity_id.
func cefSeverity(s string) (string, any) {
	if n, err := strconv.Atoi(s); err == nil {
		switch {
		case n < 0:
			return "unknown", int64(n)
		case n <= 3:
			return "low", int64(n)
		case n <= 6:
			return "medium", int64(n)
		case n <= 8:
			return "high", int64(n)
		default:
			return "critical", int64(n)
		}
	}
	switch l := strings.ToLower(s); l {
	case "very-high", "very high", "veryhigh":
		return "critical", nil
	default:
		return l, nil
	}
}

var (
	cefTimeLayouts = []string{"Jan 2 2006 15:04:05.000", "Jan 2 2006 15:04:05"}
	// cefYearless are the spec's forms without a year.
	cefYearless = []string{"Jan 2 15:04:05.000", "Jan 2 15:04:05"}
)

// cefTime reads a CEF timestamp: milliseconds (or seconds) since 1970,
// "MMM dd [yyyy] HH:mm:ss[.SSS] [zone]" or ISO 8601. The zone may be UTC,
// GMT, Z or an offset such as +0200 or -07:00; other zone names are
// ambiguous and ignored, and the time is taken as local, like syslog
// headers. Times without a year get the one ingest.GuessYear picks.
func cefTime(v string, now time.Time) (time.Time, bool) {
	v = strings.Join(strings.Fields(v), " ")
	if v == "" {
		return time.Time{}, false
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if len(v) >= 12 {
			return time.UnixMilli(n).UTC(), true
		}
		return time.Unix(n, 0).UTC(), true
	}
	if isDigit(v[0]) {
		if t, n, _, ok := parseISO(v); ok && n == len(v) {
			return t, true
		}
		return time.Time{}, false
	}
	loc := time.Local
	if i := strings.LastIndexByte(v, ' '); i > 0 {
		zone := v[i+1:]
		if zone == "UTC" || zone == "GMT" || zone == "Z" {
			loc = time.UTC
			v = v[:i]
		} else if off, ok := zoneOffset(zone); ok {
			loc = time.FixedZone("", off)
			v = v[:i]
		} else if strings.Trim(zone, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" {
			v = v[:i]
		}
	}
	for _, l := range cefTimeLayouts {
		if t, err := time.ParseInLocation(l, v, loc); err == nil {
			return t.UTC(), true
		}
	}
	for _, l := range cefYearless {
		if t, err := time.ParseInLocation(l, v, loc); err == nil {
			return ingest.GuessYear(t, now), true
		}
	}
	return time.Time{}, false
}

// zoneOffset reads "+0200", "-07:00" and the like as seconds east of UTC.
func zoneOffset(z string) (int, bool) {
	if len(z) < 5 || (z[0] != '+' && z[0] != '-') {
		return 0, false
	}
	digits := strings.Replace(z[1:], ":", "", 1)
	if len(digits) != 4 || !allDigits(digits) {
		return 0, false
	}
	h, _ := strconv.Atoi(digits[:2])
	m, _ := strconv.Atoi(digits[2:])
	if h > 23 || m > 59 {
		return 0, false
	}
	off := h*3600 + m*60
	if z[0] == '-' {
		off = -off
	}
	return off, true
}
