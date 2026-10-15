package ingest

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Zeek writes one log file per kind of activity (conn.log, dns.log,
// http.log, ...), one JSON object per line once json-logs is loaded.
// Fluent Bit tails the folder with Tag zeek.*, which it expands to the
// file's path (zeek.opt.zeek.logs.current.conn.log), and sends each line
// in "log"; ParseZeek maps it onto the data model of its log type.

// ZeekTag is the tag prefix the generated sensor config sends Zeek's logs
// with, and ZeekVendor the vendor_product of every Zeek event.
const (
	ZeekTag    = "zeek"
	ZeekVendor = "Zeek"
)

// maxZeekGenericFields caps the fields kept from a log type without a
// mapping of its own.
const maxZeekGenericFields = 64

// zeekMapped are the log types with a mapping of their own.
var zeekMapped = map[string]bool{
	"conn": true, "dns": true, "http": true, "ssl": true, "x509": true, "files": true,
	"notice": true, "capture_loss": true, "stats": true,
}

// zeekAlsoGeneric are the log types mapped onto a data model that also
// keep every key as zeek_<key>, as a log without a mapping does (see
// zeekGeneric): Sigma's Zeek rules for them (Kerberos, RDP, SMB) name
// Zeek's own keys, which ZeekGenericField finds.
var zeekAlsoGeneric = map[string]bool{
	"ssh": true, "rdp": true, "kerberos": true, "ntlm": true, "smb_files": true, "smb_mapping": true,
	"known_hosts": true, "known_services": true, "software": true, "dhcp": true,
}

// isZeekTag reports whether a Fluent Bit tag is a Zeek one: "zeek" or
// "zeek.*".
func isZeekTag(tag string) bool {
	return tag == ZeekTag || strings.HasPrefix(tag, ZeekTag+".")
}

// IsZeekRecord reports whether a decoded object is a Zeek log line: it
// has "ts" and a connection or file ID, an address pair or capture loss.
func IsZeekRecord(r map[string]any) bool {
	if _, ok := r["ts"]; !ok {
		return false
	}
	for _, k := range []string{"uid", "id.orig_h", "fuid", "percent_lost"} {
		if _, ok := r[k]; ok {
			return true
		}
	}
	return false
}

// zeekLogType names the Zeek log a record comes from: from the tag
// (zeek.conn, or tail's expanded zeek.opt.zeek.logs.current.conn.log),
// else the record's "_path", else the base name in Path_Key "file", else
// guessed from its fields. A tag naming no known log type gives way to
// the others. Only [a-z0-9_] is kept, at most 40 bytes; "unknown" when
// nothing says.
func zeekLogType(tag string, r map[string]any) string {
	fromTag := ""
	if strings.HasPrefix(tag, ZeekTag+".") {
		t := strings.TrimSuffix(strings.TrimPrefix(tag, ZeekTag+"."), ".log")
		if i := strings.LastIndexByte(t, '.'); i >= 0 {
			t = t[i+1:]
		}
		fromTag = cleanLogType(t)
		if zeekMapped[fromTag] || zeekAlsoGeneric[fromTag] || strings.HasSuffix(tag, ".log") {
			return fromTag
		}
	}
	if p := cleanLogType(wstr(r["_path"])); p != "" {
		return p
	}
	if file := wstr(r["file"]); file != "" {
		if p := cleanLogType(strings.TrimSuffix(baseName(file), ".log")); p != "" {
			return p
		}
	}
	if g := zeekGuess(r); g != "" {
		return g
	}
	if fromTag != "" {
		return fromTag
	}
	return "unknown"
}

// zeekGuess guesses a log type from a record's fields.
func zeekGuess(r map[string]any) string {
	has := func(k string) bool { _, ok := r[k]; return ok }
	switch {
	case has("percent_lost"):
		return "capture_loss"
	case has("note"):
		return "notice"
	case has("certificate.subject") || wget(r, "certificate", "subject") != nil:
		return "x509"
	case has("fuid") && has("mime_type") && !has("uri"):
		return "files"
	case has("method") && has("uri"):
		return "http"
	case has("query") && (has("rcode") || has("qtype")):
		return "dns"
	case has("version") && (has("server_name") || has("cipher")):
		return "ssl"
	case has("proto") && has("conn_state"):
		return "conn"
	case has("pkts_proc"):
		return "stats"
	}
	return ""
}

// cleanLogType keeps [a-z0-9_] of a log type name (- becomes _), at most
// 40 bytes.
func cleanLogType(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_':
			b.WriteRune(c)
		case c == '-':
			b.WriteByte('_')
		}
		if b.Len() >= 40 {
			break
		}
	}
	return strings.Trim(b.String(), "_")
}

// parseZeekRecord maps a record sent under a Zeek tag (or one that looks
// like a Zeek line): either the line in "log", with the sensor's host
// name next to it, or a record Fluent Bit already decoded. A line that is
// not JSON (Zeek writes tab-separated logs until json-logs is loaded)
// stays searchable as zeek:unknown.
func parseZeekRecord(tag string, r map[string]any) Event {
	outerHost := strings.TrimSpace(wstr(r["hostname"]))
	if line, ok := r["log"].(string); ok {
		if rec, ok := decodeSensorLine(line); ok {
			if f := wstr(r["file"]); f != "" && rec["file"] == nil {
				rec["file"] = f
			}
			ev := ParseZeek(zeekLogType(tag, rec), rec, strings.TrimSpace(line))
			if outerHost != "" && len(outerHost) <= 255 {
				ev.Fields["host"], ev.Fields["dvc"] = outerHost, outerHost
			}
			return ev
		}
		ev := parseGeneric(r)
		ev.Fields["sourcetype"] = "zeek:unknown"
		ev.Fields["vendor_product"] = ZeekVendor
		ev.Fields["message"] = line
		delete(ev.Fields, "log")
		return ev
	}
	rec := make(map[string]any, len(r))
	for k, v := range r {
		rec[k] = v
	}
	return ParseZeek(zeekLogType(tag, rec), rec, "")
}

// ParseZeek maps one decoded Zeek record of log type lt. raw is its line;
// when empty, or when sensitive keys were dropped from it, the record is
// encoded again for the raw message.
func ParseZeek(lt string, r map[string]any, raw string) Event {
	if lt == "" {
		lt = "unknown"
	}
	if scrubSensitive(r) || raw == "" {
		raw = encodeRecord(r)
	}
	f := map[string]any{
		"sourcetype":     "zeek:" + lt,
		"vendor_product": ZeekVendor,
		"message":        raw,
	}
	h := sensorHost(r)
	if lt == "ntlm" {
		// ntlm.log's hostname is the workstation name the client sent,
		// which anyone on the wire chooses: never the sensor's name.
		h = firstHost(r, "_node_name", "peer")
	}
	if h != "" {
		f["host"], f["dvc"] = h, h
	}
	setStr(f, "session_id", r["uid"])
	setStr(f, "community_id", r["community_id"])
	src, dest := wstr(r["id.orig_h"]), wstr(r["id.resp_h"])
	if src != "" || dest != "" {
		setStr(f, "src", src)
		setInt(f, "src_port", r["id.orig_p"])
		setStr(f, "dest", dest)
		setInt(f, "dest_port", r["id.resp_p"])
		if d := netDirection(src, dest, wstr(r["local_orig"]), wstr(r["local_resp"])); d != "" {
			f["direction"] = d
		}
	}
	model := "Other"
	switch lt {
	case "conn":
		model = "Network_Traffic"
		zeekConn(r, f)
	case "dns":
		model = "Network_Resolution"
		zeekDNS(r, f)
	case "http":
		model = "Web"
		zeekHTTP(r, f)
	case "ssl":
		model = "Certificates"
		zeekSSL(r, f)
	case "x509":
		model = "Certificates"
		zeekX509(r, f)
	case "files":
		model = "File_Transfers"
		zeekFiles(r, f)
	case "notice":
		model = "Intrusion_Detection"
		zeekNotice(r, f)
	case "capture_loss":
		zeekCaptureLoss(r, f)
	case "stats":
		zeekStats(r, f)
	default:
		zeekGeneric(lt, r, f)
		switch lt {
		case "ssh", "rdp", "kerberos", "ntlm":
			model = "Authentication"
			zeekAuth(lt, r, f)
		case "smb_files":
			model = "Filesystem"
			zeekSMBFiles(r, f)
		case "smb_mapping":
			zeekSMBMapping(r, f)
		case "known_hosts", "known_services", "software", "dhcp":
			zeekInventory(lt, r, f)
		}
	}
	if model == "Intrusion_Detection" {
		setLocalHost(f)
		// A notice about one address (an Address_Scan has no dst) has
		// no direction: the scanner is local when its address is.
		if _, ok := f["local_host"]; !ok && f["direction"] == nil {
			if src := wstr(f["src"]); src != "" && localAddr(src) {
				f["local_host"] = src
			}
		}
	}
	ev := Event{Model: model, Fields: f, ID: sensorDocID("zeek:"+lt, raw)}
	if t, ok := zeekTime(r["ts"]); ok {
		ev.Time = t
	}
	return ev
}

// zeekTime reads a Zeek time: epoch seconds (JSON number or text), or
// RFC 3339 when the logs use ISO timestamps (Security Onion does).
func zeekTime(v any) (time.Time, bool) {
	switch x := v.(type) {
	case json.Number, float64:
		f, ok := floatOf(x)
		if !ok || f <= 0 || f > 4e11 {
			return time.Time{}, false
		}
		sec := int64(f)
		return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC().Round(time.Microsecond), true
	case string:
		s := strings.TrimSpace(x)
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return zeekTime(f)
		}
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// zget reads a Zeek field written flat with dots ("certificate.subject",
// Zeek's default) or nested (json-logs with nesting turned on).
func zget(r map[string]any, name string) any {
	if v, ok := r[name]; ok {
		return v
	}
	return wget(r, strings.Split(name, ".")...)
}

// zeekFailedStates are the connection states of a connection refused or
// never answered.
var zeekFailedStates = map[string]bool{"S0": true, "REJ": true, "RSTOS0": true, "RSTRH": true, "SH": true, "SHR": true}

// zeekConn maps conn.log onto Network_Traffic. Bytes and packets are seen
// from the originator: out is what src sent.
func zeekConn(r, f map[string]any) {
	f["signature"] = "Connection"
	setStr(f, "transport", r["proto"])
	if svc := wstr(r["service"]); svc != "" {
		svc, _, _ = strings.Cut(svc, ",")
		f["app"] = svc
	}
	if d, ok := floatOf(r["duration"]); ok {
		f["duration"] = d
	}
	setInt(f, "bytes_out", r["orig_bytes"])
	setInt(f, "bytes_in", r["resp_bytes"])
	out, okO := f["bytes_out"].(int64)
	in, okI := f["bytes_in"].(int64)
	if okO || okI {
		f["bytes"] = out + in
	}
	setInt(f, "packets_out", r["orig_pkts"])
	setInt(f, "packets_in", r["resp_pkts"])
	state := wstr(r["conn_state"])
	setStr(f, "conn_state", state)
	switch {
	case zeekFailedStates[state] || state == "OTH" && in == 0:
		f["action"] = "failed"
	case state != "":
		f["action"] = "allowed"
	}
	setStr(f, "src_mac", r["orig_l2_addr"])
	setStr(f, "dest_mac", r["resp_l2_addr"])
	setInt(f, "vlan", r["vlan"])
	setStr(f, "zeek_history", r["history"])
	setInt(f, "zeek_missed_bytes", r["missed_bytes"])
	setStr(f, "zeek_local_orig", r["local_orig"])
	setStr(f, "zeek_local_resp", r["local_resp"])
}

// zeekDNS maps dns.log onto Network_Resolution: src asked dest_ip, the
// resolver. dest stays unset: on host logs it is the host that looked up.
func zeekDNS(r, f map[string]any) {
	f["signature"] = "DNS query"
	if d, ok := f["dest"]; ok {
		f["dest_ip"] = d
		delete(f, "dest")
	}
	setStr(f, "transport", r["proto"])
	setStr(f, "query", r["query"])
	setStr(f, "query_type", r["qtype_name"])
	if rc := wstr(r["rcode_name"]); rc != "" {
		f["reply_code"] = replyCode(rc)
	}
	setInt(f, "reply_code_id", r["rcode"])
	if a := sensorList(r["answers"]); len(a) > 0 {
		f["answer"] = a
	}
	setInt(f, "ttl", listFirst(r["TTLs"]))
	setStr(f, "zeek_rejected", r["rejected"])
	setStr(f, "zeek_qclass_name", r["qclass_name"])
	if rtt, ok := floatOf(r["rtt"]); ok {
		f["zeek_rtt"] = rtt
	}
}

// hostOnly is a Host header without its port.
func hostOnly(h string) string {
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			return h[1:i]
		}
	}
	if strings.Count(h, ":") == 1 {
		h, _, _ = strings.Cut(h, ":")
	}
	return h
}

// zeekHTTP maps http.log onto Web. The password Zeek can log is dropped
// before this (scrubSensitive).
func zeekHTTP(r, f map[string]any) {
	f["signature"] = "Web request"
	setStr(f, "http_method", r["method"])
	host := wstr(r["host"])
	uri := wstr(r["uri"])
	if host != "" {
		f["dest_host"] = hostOnly(host)
		f["url_domain"] = hostOnly(host)
		port := r["id.resp_p"]
		if strings.Contains(host, ":") {
			port = nil // the Host header names its port already
		}
		f["url"] = webURL("http", host, uri, port)
	}
	splitURI(f, uri)
	setStr(f, "status", r["status_code"])
	setStr(f, "http_user_agent", r["user_agent"])
	setStr(f, "http_referrer", r["referrer"])
	setStr(f, "http_content_type", listFirst(r["resp_mime_types"]))
	setInt(f, "bytes_out", r["request_body_len"])
	setInt(f, "bytes_in", r["response_body_len"])
	setStr(f, "user", r["username"])
	setInt(f, "zeek_trans_depth", r["trans_depth"])
}

// zeekSSL maps ssl.log (a TLS session) onto Certificates.
func zeekSSL(r, f map[string]any) {
	f["signature"] = "TLS session"
	setStr(f, "ssl_version", r["version"])
	setStr(f, "ssl_cipher", r["cipher"])
	if sni := wstr(r["server_name"]); sni != "" {
		f["ssl_server_name"] = sni
		f["dest_host"] = sni
	}
	setStr(f, "ssl_subject", r["subject"])
	setStr(f, "ssl_issuer", r["issuer"])
	status := wstr(r["validation_status"])
	setStr(f, "ssl_validation_status", status)
	for _, k := range []string{"ja3", "ja3s", "ja4", "ja4s"} {
		setStr(f, k, r[k])
	}
	setCertNames(f, status == "self signed certificate")
	setStr(f, "zeek_established", r["established"])
	setStr(f, "zeek_resumed", r["resumed"])
	setStr(f, "zeek_curve", r["curve"])
	setStr(f, "zeek_next_protocol", r["next_protocol"])
	if fps := sensorList(r["cert_chain_fps"]); len(fps) > 0 {
		f["zeek_cert_chain_fps"] = fps
	}
}

// zeekX509 maps x509.log (a certificate seen) onto Certificates.
func zeekX509(r, f map[string]any) {
	f["signature"] = "Certificate"
	setStr(f, "ssl_subject", zget(r, "certificate.subject"))
	setStr(f, "ssl_issuer", zget(r, "certificate.issuer"))
	setStr(f, "ssl_serial", zget(r, "certificate.serial"))
	if t, ok := zeekTime(zget(r, "certificate.not_valid_before")); ok {
		f["ssl_start_time"] = t.Format(time.RFC3339)
	}
	if t, ok := zeekTime(zget(r, "certificate.not_valid_after")); ok {
		f["ssl_end_time"] = t.Format(time.RFC3339)
	}
	if fp := lowerHash(wstr(r["fingerprint"])); fp != "" && isHex(fp) {
		f["ssl_hash"] = fp
	}
	// Before Zeek 6 a certificate is named by its file ID instead.
	setStr(f, "zeek_fuid", r["id"])
	if names := sensorList(zget(r, "san.dns")); len(names) > 0 {
		f["dest_host"] = names[0]
	}
	setCertNames(f, false)
}

// zeekFiles maps files.log onto File_Transfers: src sent the file and
// dest received it.
func zeekFiles(r, f map[string]any) {
	f["signature"] = "File seen"
	setStr(f, "file_name", r["filename"])
	if _, ok := intOf(r["total_bytes"]); ok {
		setInt(f, "file_size", r["total_bytes"])
	} else {
		setInt(f, "file_size", r["seen_bytes"])
	}
	for k, field := range map[string]string{"md5": "file_md5", "sha1": "file_sha1", "sha256": "file_sha256"} {
		if h := strings.ToLower(wstr(r[k])); h != "" && isHex(h) {
			f[field] = h
		}
	}
	if h, ok := f["file_sha256"]; ok {
		f["file_hash"] = h
	}
	setStr(f, "mime_type", r["mime_type"])
	setStr(f, "app", r["source"])
	if _, ok := r["id.orig_h"]; ok {
		// Zeek 5 and later: the connection's addresses. A file the
		// originator did not send (is_orig false: a download) went from
		// the responder to the originator.
		if fromOrig, _ := zeekBool(wstr(r["is_orig"])); !fromOrig {
			for _, k := range []string{"src", "src_port", "dest", "dest_port"} {
				delete(f, k)
			}
			setStr(f, "src", r["id.resp_h"])
			setInt(f, "src_port", r["id.resp_p"])
			setStr(f, "dest", r["id.orig_h"])
			setInt(f, "dest_port", r["id.orig_p"])
		}
	} else {
		if tx := sensorList(r["tx_hosts"]); len(tx) > 0 {
			f["src"] = tx[0]
		}
		if rx := sensorList(r["rx_hosts"]); len(rx) > 0 {
			f["dest"] = rx[0]
		}
		if uids := sensorList(r["conn_uids"]); len(uids) > 0 && f["session_id"] == nil {
			f["session_id"] = uids[0]
		}
	}
	if src, dest := wstr(f["src"]), wstr(f["dest"]); src != "" && dest != "" {
		f["direction"] = netDirection(src, dest, "", "")
	}
	setStr(f, "zeek_fuid", r["fuid"])
	setStr(f, "zeek_is_orig", r["is_orig"])
	setInt(f, "zeek_seen_bytes", r["seen_bytes"])
	setInt(f, "zeek_missing_bytes", r["missing_bytes"])
	if a := sensorList(r["analyzers"]); len(a) > 0 {
		f["zeek_analyzers"] = a
	}
}

// zeekNotice maps notice.log onto Intrusion_Detection: what Zeek's
// scripts noticed, such as a port scan. message stays the raw line; the
// notice's text goes to reason.
func zeekNotice(r, f map[string]any) {
	note := wstr(r["note"])
	f["signature"] = note
	f["signature_id"] = note
	f["ids_type"] = "network"
	f["category"] = "Zeek notice"
	f["severity"] = "medium"
	f["severity_id"] = int64(2)
	f["action"] = "allowed"
	setStr(f, "reason", r["msg"])
	setStr(f, "transport", r["proto"])
	sub := wstr(r["sub"])
	if looksLikeHost(sub) {
		f["dest_host"] = sub
	}
	if _, ok := r["id.orig_h"]; !ok {
		setStr(f, "src", r["src"])
		setStr(f, "dest", r["dst"])
		setInt(f, "dest_port", r["p"])
		if src, dest := wstr(f["src"]), wstr(f["dest"]); src != "" && dest != "" {
			f["direction"] = netDirection(src, dest, "", "")
		}
	}
	setStr(f, "zeek_note", note)
	setStr(f, "zeek_sub", sub)
	setStr(f, "zeek_fuid", r["fuid"])
}

// zeekCaptureLoss keeps how much traffic a Zeek worker missed.
func zeekCaptureLoss(r, f map[string]any) {
	f["signature"] = "Capture loss"
	if p, ok := floatOf(r["percent_lost"]); ok {
		f["capture_loss_percent"] = p
	}
	setStr(f, "zeek_peer", r["peer"])
}

// zeekStats keeps the packet counters of Zeek's stats.log.
func zeekStats(r, f map[string]any) {
	f["signature"] = "Sensor stats"
	setInt(f, "packets_received", r["pkts_proc"])
	setInt(f, "packets_dropped", r["pkts_dropped"])
	setStr(f, "zeek_peer", r["peer"])
}

// zeekSkip are keys a generic log does not copy: the time, the log's own
// name, the 4-tuple and ID (mapped already) and the sensor's name.
var zeekSkip = map[string]bool{
	"ts": true, "_path": true, "_write_ts": true, "_node_name": true, "hostname": true, "file": true,
	"uid": true, "community_id": true, "id.orig_h": true, "id.orig_p": true, "id.resp_h": true, "id.resp_p": true,
}

// zeekGeneric keeps a log without a mapping of its own (ssh, rdp, smb,
// kerberos, weird, ...) as zeek_<key> fields, dots made underscores so
// OpenSearch makes no objects of them, objects and lists as JSON text,
// and at most maxZeekGenericFields of them.
func zeekGeneric(lt string, r, f map[string]any) {
	f["signature"] = "Zeek " + lt
	keys := make([]string, 0, len(r))
	for k := range r {
		// ntlm.log's hostname is the client's, kept as zeek_hostname.
		if !zeekSkip[k] || (k == "hostname" && lt == "ntlm") {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	n := 0
	for _, k := range keys {
		if n >= maxZeekGenericFields {
			break
		}
		name := cleanFieldPart(k)
		if name == "" {
			continue
		}
		name = "zeek_" + name
		if _, taken := f[name]; taken {
			continue
		}
		switch v := r[k].(type) {
		case map[string]any, []any:
			b, _ := json.Marshal(v)
			f[name] = string(b)
		case json.Number:
			if x := numberOf(v); x != nil {
				f[name] = x
			}
		case string:
			if zeekAlsoGeneric[lt] {
				// A copy of a mapped log's value, capped as the mapped
				// fields are, so it is searchable too.
				v = CapValue(v)
			}
			f[name] = v
		case bool:
			f[name] = strconv.FormatBool(v)
		case float64:
			if x := numberOf(v); x != nil {
				f[name] = x
			}
		default:
			continue
		}
		n++
	}
}

// ZeekGenericField returns the field a key of a Zeek log without a
// mapping of its own (ssh, rdp, smb_files, kerberos, dce_rpc, ...) is
// stored as by zeekGeneric: the connection's 4-tuple, uid and Community
// ID by their common names, any other key as zeek_<name>. It returns ""
// for a key such a log never keeps (ts, _path, the sensor's name), and
// for a log type that has a mapping of its own.
func ZeekGenericField(lt, key string) string {
	if zeekMapped[lt] {
		return ""
	}
	switch key {
	case "id.orig_h":
		return "src"
	case "id.orig_p":
		return "src_port"
	case "id.resp_h":
		return "dest"
	case "id.resp_p":
		return "dest_port"
	case "uid":
		return "session_id"
	case "community_id":
		return "community_id"
	}
	if zeekSkip[key] && !(key == "hostname" && lt == "ntlm") {
		return ""
	}
	if name := cleanFieldPart(key); name != "" {
		return "zeek_" + name
	}
	return ""
}

// cleanFieldPart makes a key part of a field name: lower case [a-z0-9_],
// other characters (dots) as _, at most 60 bytes.
func cleanFieldPart(k string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(k) {
		if b.Len() >= 60 {
			break
		}
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
