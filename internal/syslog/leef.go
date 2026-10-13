package syslog

import (
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// LEEF is one IBM Log Event Extended Format record, the format QRadar
// uses and some products (ESET PROTECT among them) send:
//
//	LEEF:1.0|Vendor|Product|Version|EventID|key=value<tab>key=value
//	LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|key=value...
type LEEF struct {
	Version       string
	Vendor        string
	Product       string
	DeviceVersion string
	EventID       string
	// Attributes holds the key=value pairs in the order they appeared, at
	// most maxLEEFAttributes of them.
	Attributes []Param
}

const (
	// maxLEEFAttributes caps the pairs read from one record.
	maxLEEFAttributes = 256
	// maxLEEFHeader caps each header field.
	maxLEEFHeader = 256
	// maxLEEFKey is the longest attribute key read.
	maxLEEFKey = 64
)

// parseLEEF reads a LEEF record. It reports false when the text is not
// LEEF: no LEEF: prefix, a version other than 1 or 2, or a header field
// missing.
func parseLEEF(s string) (*LEEF, bool) {
	if !strings.HasPrefix(s, "LEEF:") {
		return nil, false
	}
	body := s[len("LEEF:"):]
	// The header fields end at a '|' that is not escaped as \|, as in CEF.
	var hdr [5]string
	n, start := 0, 0
	for i := 0; i < len(body) && n < len(hdr); i++ {
		switch body[i] {
		case '\\':
			i++
		case '|':
			hdr[n] = truncate(strings.TrimSpace(unescapeHeader(truncate(body[start:i], 2*maxLEEFHeader))), maxLEEFHeader)
			n++
			start = i + 1
		}
	}
	if n < len(hdr) {
		return nil, false
	}
	rest := body[start:]
	l := &LEEF{Version: hdr[0], Vendor: hdr[1], Product: hdr[2], DeviceVersion: hdr[3], EventID: hdr[4]}
	delim := "\t"
	switch l.Version {
	case "1", "1.0":
		if !strings.Contains(rest, "\t") {
			// Some senders separate the pairs with spaces, as in CEF.
			for _, p := range parseExtension(rest) {
				if len(l.Attributes) == maxLEEFAttributes {
					break
				}
				if validLEEFKey(p.Name) {
					l.Attributes = append(l.Attributes, p)
				}
			}
			return l, true
		}
	case "2", "2.0":
		if d, after, ok := leefDelimiter(rest); ok {
			delim, rest = d, after
		}
	default:
		return nil, false
	}
	l.Attributes = splitLEEF(rest, delim)
	return l, true
}

// leefDelimiter reads the delimiter field of a LEEF 2.0 record: empty
// (tab), one character, or its code as x09 or 0x7C. It reports false when
// the text does not start with one, so the pairs start right away.
func leefDelimiter(s string) (delim, rest string, ok bool) {
	j := strings.IndexByte(s[:min(len(s), 7)], '|')
	if j < 0 {
		return "", s, false
	}
	field, rest := s[:j], s[j+1:]
	var r rune
	switch {
	case field == "":
		return "\t", rest, true
	case utf8.RuneCountInString(field) == 1:
		r, _ = utf8.DecodeRuneInString(field)
	default:
		hex := strings.TrimPrefix(strings.TrimPrefix(field, "0"), "x")
		if !strings.HasPrefix(field, "x") && !strings.HasPrefix(field, "0x") || len(hex) < 1 || len(hex) > 4 {
			return "", s, false
		}
		n, err := strconv.ParseUint(hex, 16, 32)
		if err != nil {
			return "", s, false
		}
		r = rune(n)
	}
	// A delimiter that would split keys or values apart is no delimiter.
	if r == '=' || r == utf8.RuneError || !utf8.ValidRune(r) || unicode.IsLetter(r) || unicode.IsDigit(r) {
		return "\t", rest, true
	}
	return string(r), rest, true
}

// splitLEEF splits pairs on delim, then each at its first '='. Pairs whose
// key is not 1 to 64 key characters are skipped.
func splitLEEF(s, delim string) []Param {
	var out []Param
	for s != "" && len(out) < maxLEEFAttributes {
		var pair string
		if i := strings.Index(s, delim); i >= 0 {
			pair, s = s[:i], s[i+len(delim):]
		} else {
			pair, s = s, ""
		}
		k, v, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		if !ok || !validLEEFKey(k) {
			continue
		}
		out = append(out, Param{Name: k, Value: strings.TrimSpace(v)})
	}
	return out
}

func validLEEFKey(k string) bool {
	if k == "" || len(k) > maxLEEFKey {
		return false
	}
	for i := 0; i < len(k); i++ {
		if !isKeyChar(k[i]) {
			return false
		}
	}
	return true
}

// leefFields maps LEEF's predefined keys to CIM field names; other keys
// are looked up in cefFields, then kept as leef_<key>.
var leefFields = map[string]cefField{
	"src":            {name: "src"},
	"dst":            {name: "dest"},
	"srcPort":        {name: "src_port", numeric: true},
	"dstPort":        {name: "dest_port", numeric: true},
	"usrName":        {name: "user"},
	"accountName":    {name: "user"},
	"srcMAC":         {name: "src_mac"},
	"dstMAC":         {name: "dest_mac"},
	"srcBytes":       {name: "bytes_out", numeric: true},
	"dstBytes":       {name: "bytes_in", numeric: true},
	"srcPostNAT":     {name: "src_translated_ip"},
	"dstPostNAT":     {name: "dest_translated_ip"},
	"srcPostNATPort": {name: "src_translated_port", numeric: true},
	"dstPostNATPort": {name: "dest_translated_port", numeric: true},
	"url":            {name: "url"},
	"cat":            {name: "category"},
	"identHostName":  {name: "src_host"},
}

// leefFieldsFor maps a LEEF record onto CIM fields, as cefFieldsFor does
// for CEF, and returns the event time from devTime when one parses.
func leefFieldsFor(l *LEEF, f map[string]any, extra *int, now time.Time) time.Time {
	f["sourcetype"] = "leef"
	f["vendor_product"] = vendorProduct(l.Vendor, l.Product)
	f["signature"] = l.EventID
	f["signature_id"] = l.EventID
	f["leef_version"] = l.Version
	f["leef_vendor"] = l.Vendor
	f["leef_product"] = l.Product
	f["leef_device_version"] = l.DeviceVersion
	var t time.Time
	for _, p := range l.Attributes {
		v := p.Value
		if v == "" {
			continue
		}
		switch p.Name {
		case "sev":
			if sev, id := cefSeverity(v); sev != "" {
				f["severity"] = sev
				if id != nil {
					f["severity_id"] = id
				}
			}
			continue
		case "devTime":
			if t.IsZero() {
				t, _ = cefTime(v, now)
			}
			continue
		case "devTimeFormat":
			continue
		case "proto":
			v = strings.ToLower(v)
			if name, ok := ipProtocols[v]; ok {
				v = name
			}
			f["transport"] = v
			continue
		}
		cf, ok := leefFields[p.Name]
		if !ok {
			cf, ok = cefFields[p.Name]
		}
		if ok {
			if !cf.numeric {
				f[cf.name] = v
				continue
			}
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				f[cf.name] = n
				continue
			}
		}
		addExtra(f, "leef_", p.Name, v, extra)
	}
	in, hasIn := f["bytes_in"].(int64)
	out, hasOut := f["bytes_out"].(int64)
	if hasIn || hasOut {
		f["bytes"] = in + out
	}
	return t
}
