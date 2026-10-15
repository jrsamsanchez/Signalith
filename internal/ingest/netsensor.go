package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Network sensors (Zeek and Suricata) write one JSON object per line.
// Fluent Bit on the sensor tails those files without a parser and sends
// each line in "log" under a zeek.* or suricata.* tag; the syslog receiver
// also takes Suricata's lines from firewalls such as pfSense and OPNsense.
// zeek.go and suricata.go map each line onto a data model; the helpers
// here are shared by both.

// Limits on one sensor line: the same as on any record (see body.go).
const (
	maxSensorLine  = MaxRecordBytes
	maxSensorDepth = MaxDepth
	// maxPayloadPrintable is how much of Suricata's payload_printable is
	// kept, when the sensor sends it at all.
	maxPayloadPrintable = 2048
	// maxSensorList caps the entries kept from one list (DNS answers,
	// ATT&CK IDs, certificate chains).
	maxSensorList = 32
)

// netDirection returns inbound, outbound, internal or external. localOrig
// and localResp are Zeek's local_orig/local_resp ("T"/"F", true/false or
// ""), used when set; otherwise addresses in private ranges count as local.
// It returns "" when it cannot tell.
func netDirection(src, dest string, localOrig, localResp string) string {
	lo, okO := zeekBool(localOrig)
	if !okO {
		if src == "" {
			return ""
		}
		lo = localAddr(src)
	}
	lr, okR := zeekBool(localResp)
	if !okR {
		if dest == "" {
			return ""
		}
		lr = localAddr(dest)
	}
	switch {
	case lo && lr:
		return "internal"
	case lo:
		return "outbound"
	case lr:
		return "inbound"
	}
	return "external"
}

// canonIP writes an IP address in its usual short form (IPv6 with "::"
// and no leading zeros, IPv4-mapped IPv6 as IPv4), so one host has one
// spelling whichever sensor saw it. Anything else is returned unchanged.
func canonIP(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return s
	}
	return a.Unmap().String()
}

// setLocalHost sets local_host on an alert: the end of the traffic that is
// inside your network, from its direction (src when outbound, dest when
// inbound, both when internal). It stays unset when neither end is.
func setLocalHost(f map[string]any) {
	src, dest := wstr(f["src"]), wstr(f["dest"])
	switch f["direction"] {
	case "outbound":
		setStr(f, "local_host", src)
	case "inbound":
		setStr(f, "local_host", dest)
	case "internal":
		if src == dest {
			setStr(f, "local_host", src)
		} else {
			f["local_host"] = []string{src, dest}
		}
	}
}

// zeekBool reads a Zeek boolean: T or F in its TSV logs, true or false in
// JSON.
func zeekBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "t", "true":
		return true, true
	case "f", "false":
		return false, true
	}
	return false, false
}

// localNets are the address ranges counted as inside the network when the
// sensor does not say: RFC 1918, RFC 4193 (fc00::/7), loopback,
// link-local and carrier-grade NAT (100.64.0.0/10).
var localNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
		"127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128", "fe80::/10"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// localAddr reports whether ip is in one of localNets.
func localAddr(ip string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	for _, p := range localNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// decodeSensorLine decodes one JSON object line, keeping numbers exact
// (Suricata's flow_id is past what a float holds). It reports false for
// anything else, or a line over maxSensorLine bytes or nested more than
// maxSensorDepth levels.
func decodeSensorLine(s string) (map[string]any, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '{' || len(s) > maxSensorLine || depth([]byte(s)) > maxSensorDepth {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var r map[string]any
	if err := dec.Decode(&r); err != nil || dec.More() || r == nil {
		return nil, false
	}
	return r, true
}

// neverStored are keys that must never be stored, at any depth: passwords
// (Zeek logs HTTP and FTP passwords when told to) and copies of packet
// contents (Suricata's payload, packet and HTTP bodies).
var neverStored = map[string]bool{
	"password": true, "payload": true, "packet": true,
	"http_request_body": true, "http_response_body": true,
	"http_request_body_printable": true, "http_response_body_printable": true,
}

// scrubSensitive deletes the neverStored keys from r and every object in
// it, cuts payload_printable to maxPayloadPrintable bytes, and reports
// whether it changed anything (the raw line is then encoded again).
func scrubSensitive(r map[string]any) bool {
	changed := false
	var walk func(v any, level int)
	walk = func(v any, level int) {
		if level > maxSensorDepth {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if neverStored[k] {
					delete(x, k)
					changed = true
					continue
				}
				walk(e, level+1)
			}
		case []any:
			for _, e := range x {
				walk(e, level+1)
			}
		}
	}
	walk(r, 0)
	// Suricata's ftp records log the argument of every command, the
	// password of PASS included.
	if ftp, ok := r["ftp"].(map[string]any); ok && strings.EqualFold(strings.TrimSpace(wstr(ftp["command"])), "PASS") {
		if _, ok := ftp["command_data"]; ok {
			ftp["command_data"] = "(hidden)"
			changed = true
		}
	}
	// Its rfb (VNC) records log the challenge and response of a sign-in,
	// from which the password can be cracked offline.
	if vnc, ok := wget(r, "rfb", "authentication", "vnc").(map[string]any); ok {
		for _, k := range []string{"challenge", "response"} {
			if _, ok := vnc[k]; ok {
				delete(vnc, k)
				changed = true
			}
		}
	}
	if p, ok := r["payload_printable"].(string); ok && len(p) > maxPayloadPrintable {
		r["payload_printable"] = cutUTF8(p, maxPayloadPrintable)
		changed = true
	}
	return changed
}

// cutUTF8 cuts s to at most n bytes without splitting a character.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// sensorDocID is the document ID of a sensor event: the first 32 hex
// digits of SHA-256(logType + "\n" + raw line), so a batch resent after a
// 503 is a duplicate, not a second copy.
func sensorDocID(logType, raw string) string {
	sum := sha256.Sum256([]byte(logType + "\n" + raw))
	return hex.EncodeToString(sum[:16])
}

// sensorHost picks the sensor's name: the record's "hostname" (Fluent
// Bit's sysinfo filter), Suricata's "host" (its sensor-name), or Zeek's
// "_node_name" or "peer"; "" lets the event's origin decide.
func sensorHost(r map[string]any) string {
	if _, eve := r["event_type"]; eve {
		// Only Suricata's "host" is the sensor: Zeek's http.log has one
		// that is the web server's name.
		return firstHost(r, "hostname", "host")
	}
	return firstHost(r, "hostname", "_node_name", "peer")
}

// firstHost returns the first of r's keys that holds a usable host name.
func firstHost(r map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := strings.TrimSpace(wstr(r[k])); s != "" && len(s) <= 255 {
			return s
		}
	}
	return ""
}

// lowerHash returns a hash in lower case without the colons TLS
// fingerprints are written with.
func lowerHash(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
}

// numberOf returns an int64 or float64 from a JSON number (exact or not)
// or a numeric string, and nil for anything else.
func numberOf(v any) any {
	var s string
	switch x := v.(type) {
	case json.Number:
		s = x.String()
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil
		}
		if x == math.Trunc(x) && math.Abs(x) < 1e15 {
			return int64(x)
		}
		return x
	case int64:
		return x
	case int:
		return int64(x)
	case string:
		s = strings.TrimSpace(x)
	default:
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	return f
}

// floatOf returns a number as a float64.
func floatOf(v any) (float64, bool) {
	switch n := numberOf(v).(type) {
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// intOf returns a whole number as an int64.
func intOf(v any) (int64, bool) {
	switch n := numberOf(v).(type) {
	case int64:
		return n, true
	case float64:
		if n == math.Trunc(n) && math.Abs(n) < 1e15 {
			return int64(n), true
		}
	}
	return 0, false
}

// setNum sets f[k] to v as a number, when it is one.
func setNum(f map[string]any, k string, v any) {
	if n := numberOf(v); n != nil {
		f[k] = n
	}
}

// setInt sets f[k] to v as a whole number, when it is one.
func setInt(f map[string]any, k string, v any) {
	if n, ok := intOf(v); ok {
		f[k] = n
	}
}

// setStr sets f[k] to v as text, when it has any.
func setStr(f map[string]any, k string, v any) {
	if s := wstr(v); s != "" {
		f[k] = s
	}
}

// listFirst returns the first entry of a list (or the value itself).
func listFirst(v any) any {
	if l, ok := v.([]any); ok {
		if len(l) == 0 {
			return nil
		}
		return l[0]
	}
	return v
}

// sensorList reads a list of strings (or one string), at most
// maxSensorList non-empty entries.
func sensorList(v any) []string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if s := wstr(e); s != "" && len(out) < maxSensorList {
				out = append(out, s)
			}
		}
	default:
		if s := wstr(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// replyCodes spells DNS reply codes as Sysmon and Windows do, so one
// search finds failed lookups from hosts and from the network.
var replyCodes = map[string]string{
	"NOERROR": "NoError", "NXDOMAIN": "NXDomain", "SERVFAIL": "ServFail", "REFUSED": "Refused",
	"FORMERR": "FormErr", "NOTIMP": "NotImp", "YXDOMAIN": "YXDomain", "NOTAUTH": "NotAuth",
}

// replyCode returns a DNS reply code in that spelling.
func replyCode(s string) string {
	if c, ok := replyCodes[strings.ToUpper(strings.TrimSpace(s))]; ok {
		return c
	}
	return s
}

// commonName returns the CN= part of a distinguished name, written either
// as CN=x,O=y (Zeek, OpenSSL) or CN=x, O=y (Suricata).
func commonName(dn string) string {
	for _, part := range splitDN(dn) {
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "CN") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// splitDN splits a distinguished name into its parts: on the commas
// between them, leaving escaped commas (\,) alone, or on slashes for the
// old OpenSSL form (/C=US/O=x/CN=y).
func splitDN(dn string) []string {
	if strings.HasPrefix(dn, "/") {
		return strings.Split(dn[1:], "/")
	}
	var parts []string
	start := 0
	for i := 0; i < len(dn); i++ {
		switch dn[i] {
		case '\\':
			i++
		case ',':
			parts = append(parts, dn[start:i])
			start = i + 1
		}
	}
	return append(parts, dn[start:])
}

// setCertNames sets the common names of a certificate's subject and
// issuer and whether it signs itself. selfSigned is what the sensor
// itself said, when it did.
func setCertNames(f map[string]any, selfSigned bool) {
	subject, _ := f["ssl_subject"].(string)
	issuer, _ := f["ssl_issuer"].(string)
	if cn := commonName(subject); cn != "" {
		f["ssl_subject_common_name"] = cn
	}
	if cn := commonName(issuer); cn != "" {
		f["ssl_issuer_common_name"] = cn
	}
	switch {
	case selfSigned || subject != "" && subject == issuer:
		f["ssl_self_signed"] = "true"
	case subject != "" && issuer != "":
		f["ssl_self_signed"] = "false"
	}
}

// splitURI splits a request target into its path and query.
func splitURI(f map[string]any, uri string) {
	path, query, _ := strings.Cut(uri, "?")
	if path != "" {
		f["uri_path"] = path
	}
	if query != "" {
		f["uri_query"] = query
	}
}

// webURL is the full address of a request to host for uri on port (left
// out when it is the scheme's own).
func webURL(scheme, host, uri string, port any) string {
	if host == "" {
		return ""
	}
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return uri // a proxy request carries the whole address
	}
	h := host
	if p, ok := intOf(port); ok && p > 0 && !(scheme == "http" && p == 80) && !(scheme == "https" && p == 443) &&
		!strings.Contains(host, ":") {
		h += ":" + strconv.FormatInt(p, 10)
	}
	if uri != "" && !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	return scheme + "://" + h + uri
}

// looksLikeHost reports whether s is a DNS name (not an address).
func looksLikeHost(s string) bool {
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	for _, c := range s {
		if !(c == '.' || c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// encodeRecord encodes a decoded record again, for the raw message of a
// record that was scrubbed.
func encodeRecord(r map[string]any) string {
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return string(b)
}
