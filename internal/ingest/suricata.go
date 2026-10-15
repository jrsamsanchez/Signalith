package ingest

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// Suricata writes every event to eve.json, one JSON object per line, with
// "event_type" saying what it is: an alert from a rule (such as the
// Emerging Threats Open rules), a flow, a DNS lookup, a web request, a
// TLS session, a file, an anomaly or its own stats. Fluent Bit tails it
// under the tag suricata.eve and sends each line in "log"; firewalls that
// run Suricata (pfSense, OPNsense) can send the same lines over syslog
// (ParseSuricataText).

// SuricataTag is the tag prefix the generated sensor config sends
// eve.json with, and SuricataVendor the vendor_product of every Suricata
// event.
const (
	SuricataTag    = "suricata"
	SuricataVendor = "Suricata"
)

// maxSuricataPrefix is how much text may come before the JSON in a syslog
// message ("suricata[1234]: "), and maxSuricataDetail how much of an
// unmapped event type's own object is kept in suricata_detail.
const (
	maxSuricataPrefix = 256
	maxSuricataDetail = 32 << 10
)

// isSuricataTag reports whether a Fluent Bit tag is a Suricata one:
// "suricata" or "suricata.*".
func isSuricataTag(tag string) bool {
	return tag == SuricataTag || strings.HasPrefix(tag, SuricataTag+".")
}

// IsSuricataEVE reports whether a decoded object is a Suricata EVE event:
// it has "event_type" and "timestamp" as text, and an address or is a
// stats event. A Wazuh alert never is (Normalize checks Wazuh first).
func IsSuricataEVE(r map[string]any) bool {
	t, ok := r["event_type"].(string)
	if !ok || t == "" {
		return false
	}
	if _, ok := r["timestamp"].(string); !ok {
		return false
	}
	if IsWazuhAlert(r) {
		return false
	}
	_, src := r["src_ip"]
	_, dest := r["dest_ip"]
	return src || dest || t == "stats"
}

// parseSuricataRecord maps a record sent under a Suricata tag (or one
// that looks like an EVE event): the line in "log", with the sensor's
// host name next to it, or an event Fluent Bit already decoded. Anything
// else stays searchable as suricata:unknown.
func parseSuricataRecord(r map[string]any) Event {
	outerHost := strings.TrimSpace(wstr(r["hostname"]))
	if line, ok := r["log"].(string); ok {
		if rec, ok := decodeSensorLine(line); ok && IsSuricataEVE(rec) {
			ev := ParseSuricataEVE(rec, strings.TrimSpace(line))
			if outerHost != "" && len(outerHost) <= 255 {
				ev.Fields["host"], ev.Fields["dvc"] = outerHost, outerHost
			}
			return ev
		}
		ev := parseGeneric(r)
		ev.Fields["sourcetype"] = "suricata:unknown"
		ev.Fields["vendor_product"] = SuricataVendor
		ev.Fields["message"] = line
		delete(ev.Fields, "log")
		return ev
	}
	if IsSuricataEVE(r) {
		rec := make(map[string]any, len(r))
		for k, v := range r {
			rec[k] = v
		}
		return ParseSuricataEVE(rec, "")
	}
	ev := parseGeneric(r)
	ev.Fields["sourcetype"] = "suricata:unknown"
	ev.Fields["vendor_product"] = SuricataVendor
	return ev
}

// ParseSuricataText finds an EVE event in a syslog message's text, which
// may start with a tag such as "suricata[1234]: " (at most
// maxSuricataPrefix bytes before the "{"), and maps it. It reports false
// when the text is not a whole EVE event.
func ParseSuricataText(text string) (Event, bool) {
	i := strings.IndexByte(text, '{')
	if i < 0 || i > maxSuricataPrefix {
		return Event{}, false
	}
	body := strings.TrimSpace(text[i:])
	if !strings.HasSuffix(body, "}") || !strings.Contains(body, `"event_type"`) {
		return Event{}, false
	}
	r, ok := decodeSensorLine(body)
	if !ok || !IsSuricataEVE(r) {
		return Event{}, false
	}
	return ParseSuricataEVE(r, body), true
}

// suricataTime reads an EVE time, such as 2026-10-14T09:12:03.512345+0000,
// or RFC 3339.
func suricataTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range []string{"2006-01-02T15:04:05.999999999-0700", time.RFC3339Nano} {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// suricataSeverity names a rule's severity: 1 high, 2 medium, 3 low,
// anything else informational; an Emerging Threats rule whose metadata
// says signature_severity Critical is critical.
func suricataSeverity(n int64, metadata map[string]any) string {
	for _, s := range sensorList(metadata["signature_severity"]) {
		if strings.EqualFold(s, "critical") {
			return "critical"
		}
	}
	switch n {
	case 1:
		return "high"
	case 2:
		return "medium"
	case 3:
		return "low"
	}
	return "informational"
}

// ParseSuricataEVE maps one decoded EVE event. raw is its line; when
// empty, or when payloads or passwords were dropped from it, the event is
// encoded again for the raw message.
func ParseSuricataEVE(r map[string]any, raw string) Event {
	if scrubSensitive(r) || raw == "" {
		raw = encodeRecord(r)
	}
	t := cleanLogType(wstr(r["event_type"]))
	if t == "" {
		t = "unknown"
	}
	f := map[string]any{
		"sourcetype":          "suricata:" + t,
		"vendor_product":      SuricataVendor,
		"message":             raw,
		"suricata_event_type": t,
	}
	if h := sensorHost(r); h != "" {
		f["host"], f["dvc"] = h, h
	}
	setStr(f, "session_id", r["flow_id"])
	setStr(f, "community_id", r["community_id"])
	// Suricata writes IPv6 addresses in full (2001:0db8:0000:...); the
	// short form matches Zeek, threat intel and what people type.
	src, dest := canonIP(wstr(r["src_ip"])), canonIP(wstr(r["dest_ip"]))
	setStr(f, "src", src)
	setInt(f, "src_port", r["src_port"])
	setStr(f, "dest", dest)
	setInt(f, "dest_port", r["dest_port"])
	if p := wstr(r["proto"]); p != "" {
		f["transport"] = strings.ToLower(p)
	}
	setStr(f, "app", r["app_proto"])
	setInt(f, "vlan", listFirst(r["vlan"]))
	if src != "" && dest != "" {
		f["direction"] = netDirection(src, dest, "", "")
	}
	setStr(f, "suricata_in_iface", r["in_iface"])
	setInt(f, "suricata_tx_id", r["tx_id"])
	id := sensorDocID("suricata:"+t, raw)

	model := "Other"
	switch t {
	case "alert":
		model = "Intrusion_Detection"
		eveAlert(r, f)
	case "flow", "netflow":
		model = "Network_Traffic"
		eveFlow(r, f)
	case "dns":
		// Suricata logs a lookup twice: the question and the answer. The
		// answer carries both, so only it counts as a lookup; the
		// question is kept as a "DNS request" outside the data model.
		if eveDNS(r, f) {
			model = "Network_Resolution"
		} else {
			f["signature"] = "DNS request"
		}
	case "http":
		model = "Web"
		eveHTTP(r, f)
	case "tls":
		model = "Certificates"
		eveTLS(r, f)
	case "fileinfo":
		model = "File_Transfers"
		eveFileinfo(r, f)
	case "stats":
		eveStats(r, f)
	default:
		eveGeneric(t, r, f)
	}
	if model == "Intrusion_Detection" {
		setLocalHost(f)
	}
	ev := Event{Model: model, Fields: f, ID: id}
	if ts, ok := suricataTime(wstr(r["timestamp"])); ok {
		ev.Time = ts
	}
	return ev
}

// eveAlert maps an alert onto Intrusion_Detection.
func eveAlert(r, f map[string]any) {
	a, _ := r["alert"].(map[string]any)
	meta, _ := a["metadata"].(map[string]any)
	f["ids_type"] = "network"
	switch act := wstr(a["action"]); act {
	case "blocked", "drop", "rejected", "reject":
		f["action"] = "blocked"
	default:
		f["action"] = "allowed"
	}
	setStr(f, "signature", a["signature"])
	setStr(f, "signature_id", a["signature_id"])
	setStr(f, "category", a["category"])
	sev, ok := intOf(a["severity"])
	if ok {
		f["severity_id"] = sev
	}
	f["severity"] = suricataSeverity(sev, meta)
	if ids := sensorList(meta["mitre_technique_id"]); len(ids) > 0 {
		f["mitre"] = ids
	}
	host := wstr(wget(r, "http", "hostname"))
	switch {
	case host != "":
		f["dest_host"] = host
		f["url"] = webURL("http", host, wstr(wget(r, "http", "url")), eveServerPort(r))
	case wstr(wget(r, "tls", "sni")) != "":
		f["dest_host"] = wstr(wget(r, "tls", "sni"))
	default:
		for _, k := range []string{"query", "queries"} {
			if n := wstr(wget(listFirst(wget(r, "dns", k)), "rrname")); n != "" {
				f["dest_host"] = n
				break
			}
		}
		if f["dest_host"] == nil {
			setStr(f, "dest_host", wget(r, "dns", "rrname"))
		}
	}
	setInt(f, "suricata_gid", a["gid"])
	setInt(f, "suricata_rev", a["rev"])
	if p, ok := r["payload_printable"].(string); ok && p != "" {
		f["suricata_payload_printable"] = cutUTF8(p, maxPayloadPrintable)
	}
}

// eveFlow maps a flow (or netflow) record onto Network_Traffic: out is
// what the client (src) sent to the server.
func eveFlow(r, f map[string]any) {
	f["signature"] = "Connection"
	fl, _ := r["flow"].(map[string]any)
	if fl == nil {
		fl, _ = r["netflow"].(map[string]any)
	}
	setInt(f, "bytes_out", fl["bytes_toserver"])
	setInt(f, "bytes_in", fl["bytes_toclient"])
	setInt(f, "packets_out", fl["pkts_toserver"])
	setInt(f, "packets_in", fl["pkts_toclient"])
	// netflow records count one direction each.
	setInt(f, "bytes_out", fl["bytes"])
	setInt(f, "packets_out", fl["pkts"])
	out, okO := f["bytes_out"].(int64)
	in, okI := f["bytes_in"].(int64)
	if okO || okI {
		f["bytes"] = out + in
	}
	start, okS := suricataTime(wstr(fl["start"]))
	end, okE := suricataTime(wstr(fl["end"]))
	if okS && okE && !end.Before(start) {
		f["duration"] = math.Round(end.Sub(start).Seconds()*1e6) / 1e6
	}
	state := wstr(fl["state"])
	setStr(f, "conn_state", state)
	setStr(f, "suricata_flow_state", state)
	setStr(f, "suricata_flow_reason", fl["reason"])
	setStr(f, "suricata_alerted", fl["alerted"])
	pktsIn, hasIn := intOf(fl["pkts_toclient"])
	if f["transport"] == "tcp" && hasIn && pktsIn == 0 {
		f["action"] = "failed"
	} else {
		f["action"] = "allowed"
	}
}

// eveDNS maps a DNS record onto Network_Resolution, in Suricata 7's
// format (one query or answer per record: dns.type, rrname, rrtype,
// rcode, answers) and Suricata 8's (dns.queries, dns.answers). src is the
// host that asked and dest_ip the resolver; dest stays unset. It reports
// whether the record is an answer (or carries no type), not the question.
func eveDNS(r, f map[string]any) bool {
	f["signature"] = "DNS query"
	d, _ := r["dns"].(map[string]any)
	// Suricata writes both records in the flow's direction, asker first.
	// Only a record that plainly came from the server's side (a DNS port
	// to a port that is not one, as some older builds and relays write
	// it) is turned round; mDNS (5353 to 5353) and a resolver asking
	// upstream from port 53 stay as they are.
	sp, _ := intOf(r["src_port"])
	dp, _ := intOf(r["dest_port"])
	if dnsPort(sp) && !dnsPort(dp) {
		f["src"], f["dest"] = f["dest"], f["src"]
		f["src_port"], f["dest_port"] = f["dest_port"], f["src_port"]
		for _, k := range []string{"src", "dest", "src_port", "dest_port"} {
			if f[k] == nil {
				delete(f, k)
			}
		}
		if s, dd := wstr(f["src"]), wstr(f["dest"]); s != "" && dd != "" {
			f["direction"] = netDirection(s, dd, "", "")
		}
	}
	if v, ok := f["dest"]; ok {
		f["dest_ip"] = v
		delete(f, "dest")
	}
	q := wstr(d["rrname"])
	qt := wstr(d["rrtype"])
	if first, ok := listFirst(d["queries"]).(map[string]any); ok {
		q, qt = wstr(first["rrname"]), wstr(first["rrtype"])
	}
	setStr(f, "query", q)
	setStr(f, "query_type", qt)
	answer := true
	switch strings.ToLower(wstr(d["type"])) {
	case "query", "request":
		answer = false
	}
	if rc := wstr(d["rcode"]); rc != "" {
		f["reply_code"] = replyCode(rc)
		if id, ok := rcodeIDs[strings.ToUpper(rc)]; ok {
			f["reply_code_id"] = id
		}
	}
	var answers []string
	var ttl any
	if l, ok := d["answers"].([]any); ok {
		for _, e := range l {
			m, _ := e.(map[string]any)
			if s := canonIP(wstr(m["rdata"])); s != "" && len(answers) < maxSensorList {
				answers = append(answers, s)
			}
			if ttl == nil {
				ttl = m["ttl"]
			}
		}
	} else if g, ok := d["grouped"].(map[string]any); ok {
		for _, k := range sortedKeys(g) {
			for _, s := range sensorList(g[k]) {
				if len(answers) < maxSensorList {
					answers = append(answers, canonIP(s))
				}
			}
		}
	}
	if len(answers) > 0 {
		f["answer"] = answers
	}
	setInt(f, "ttl", ttl)
	return answer
}

// fileServerPort is the web server's port of a fileinfo event. Its
// addresses follow the file (a download comes from the server), so the
// server is the end on the lower port unless the record says otherwise.
func fileServerPort(r map[string]any) any {
	if p := wget(r, "http", "http_port"); p != nil {
		return p
	}
	if _, ok := r["direction"]; ok {
		return eveServerPort(r)
	}
	sp, okS := intOf(r["src_port"])
	dp, okD := intOf(r["dest_port"])
	if okS && okD && sp < dp {
		return sp
	}
	return r["dest_port"]
}

// dnsPort reports whether p is a DNS port: 53, 853 (DNS over TLS) or
// 5353 (mDNS).
func dnsPort(p int64) bool {
	return p == 53 || p == 853 || p == 5353
}

// eveServerPort is the web server's port of an event: the one its HTTP
// record names, else the destination port, or the source port of a packet
// the server sent (direction to_client).
func eveServerPort(r map[string]any) any {
	if p := wget(r, "http", "http_port"); p != nil {
		return p
	}
	if wstr(r["direction"]) == "to_client" {
		return r["src_port"]
	}
	return r["dest_port"]
}

// rcodeIDs are the numbers of the DNS reply codes Suricata names.
var rcodeIDs = map[string]int64{
	"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5,
	"YXDOMAIN": 6, "YXRRSET": 7, "NXRRSET": 8, "NOTAUTH": 9, "NOTZONE": 10,
}

// eveHTTP maps a web request onto Web.
func eveHTTP(r, f map[string]any) {
	f["signature"] = "Web request"
	h, _ := r["http"].(map[string]any)
	setStr(f, "http_method", h["http_method"])
	host := wstr(h["hostname"])
	uri := wstr(h["url"])
	if host != "" {
		f["dest_host"] = host
		f["url_domain"] = host
		f["url"] = webURL("http", host, uri, eveServerPort(r))
	}
	splitURI(f, uri)
	setStr(f, "status", h["status"])
	setStr(f, "http_user_agent", h["http_user_agent"])
	setStr(f, "http_referrer", h["http_refer"])
	setStr(f, "http_content_type", h["http_content_type"])
	setInt(f, "bytes_in", h["length"])
}

// eveTLS maps a TLS session onto Certificates.
func eveTLS(r, f map[string]any) {
	f["signature"] = "TLS session"
	t, _ := r["tls"].(map[string]any)
	setStr(f, "ssl_version", t["version"])
	setStr(f, "ssl_subject", t["subject"])
	setStr(f, "ssl_issuer", t["issuerdn"])
	setStr(f, "ssl_serial", t["serial"])
	if fp := lowerHash(wstr(t["fingerprint"])); fp != "" && isHex(fp) {
		f["ssl_hash"] = fp
	}
	if sni := wstr(t["sni"]); sni != "" {
		f["ssl_server_name"] = sni
		f["dest_host"] = sni
	}
	// Suricata writes certificate times without a zone; they are UTC.
	for k, field := range map[string]string{"notbefore": "ssl_start_time", "notafter": "ssl_end_time"} {
		if ts, ok := certTime(wstr(t[k])); ok {
			f[field] = ts.Format(time.RFC3339)
		}
	}
	setStr(f, "ja3", wget(t, "ja3", "hash"))
	setStr(f, "ja3s", wget(t, "ja3s", "hash"))
	if s, ok := t["ja4"].(string); ok {
		f["ja4"] = s
	} else {
		setStr(f, "ja4", wget(t, "ja4", "hash"))
	}
	setCertNames(f, false)
}

// certTime reads a certificate time as Suricata writes it
// (2026-01-01T00:00:00, UTC) or RFC 3339.
func certTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// eveFileinfo maps a file seen onto File_Transfers: src sent it and dest
// received it. A file in a web response went from the server (the flow's
// dest) to the client.
func eveFileinfo(r, f map[string]any) {
	f["signature"] = "File seen"
	fi, _ := r["fileinfo"].(map[string]any)
	if name := wstr(fi["filename"]); name != "" {
		f["file_name"] = baseName(name)
	}
	setInt(f, "file_size", fi["size"])
	for k, field := range map[string]string{"md5": "file_md5", "sha1": "file_sha1", "sha256": "file_sha256"} {
		if h := strings.ToLower(wstr(fi[k])); h != "" && isHex(h) {
			f[field] = h
		}
	}
	if h, ok := f["file_sha256"]; ok {
		f["file_hash"] = h
	}
	setStr(f, "mime_type", fi["magic"])
	if h, ok := r["http"].(map[string]any); ok {
		if host := wstr(h["hostname"]); host != "" {
			f["url"] = webURL("http", host, wstr(h["url"]), fileServerPort(r))
		}
	}
	// Suricata already writes a file's addresses in the file's own
	// direction: for a download src is the server that sent it.
	setStr(f, "suricata_file_state", fi["state"])
	setStr(f, "suricata_file_stored", fi["stored"])
}

// eveStats keeps Suricata's packet counters, and a one-line message in
// place of the stats object, which holds hundreds of counters.
func eveStats(r, f map[string]any) {
	f["signature"] = "Sensor stats"
	s, _ := r["stats"].(map[string]any)
	setInt(f, "uptime_seconds", s["uptime"])
	pk, okP := intOf(wget(s, "capture", "kernel_packets"))
	dr, okD := intOf(wget(s, "capture", "kernel_drops"))
	if okP {
		f["packets_received"] = pk
	}
	if okD {
		f["packets_dropped"] = dr
	}
	pct := 0.0
	if okP && okD && pk+dr > 0 {
		pct = math.Round(float64(dr)/float64(pk+dr)*10000) / 100
		f["drop_percent"] = pct
	}
	setStr(f, "sensor_interface", r["in_iface"])
	delete(f, "suricata_in_iface")
	f["message"] = fmt.Sprintf("Suricata stats: %d packets, %d dropped (%g%%)", pk, dr, pct)
}

// eveGeneric keeps an event type without a mapping (anomaly, ssh, smb,
// krb5, ...): its 4-tuple and protocol, and its own object as JSON text in
// suricata_detail, so it adds no field names.
func eveGeneric(t string, r, f map[string]any) {
	f["signature"] = "Suricata " + t
	if t == "anomaly" {
		setStr(f, "suricata_anomaly_type", wget(r, "anomaly", "type"))
		setStr(f, "suricata_anomaly_event", wget(r, "anomaly", "event"))
	}
	setStr(f, "suricata_app_proto", r["app_proto"])
	if v, ok := r[t]; ok {
		if b, err := json.Marshal(v); err == nil {
			f["suricata_detail"] = cutUTF8(string(b), maxSuricataDetail)
		}
	}
}

// sortedKeys returns a map's keys in order.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
