package sigmacheck

import (
	"encoding/json"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// Network rules: Zeek's own logs (product: zeek, by service) and the
// generic dns, proxy and firewall categories. Their test events are Zeek
// log lines, which the real Zeek parser reads: a Zeek rule's event by
// Zeek's own keys, a generic rule's event by Sigma's taxonomy (query,
// c-uri, dst_port), written as the Zeek log a network sensor sends for
// it (dns.log, http.log, conn.log).

// ZeekChannelPrefix starts the channel of a network test event: the
// Zeek log it is written as (zeek:dns).
const ZeekChannelPrefix = "zeek:"

// ZeekCategoryPrefix starts the category of a Zeek rule (zeek_dns for
// product zeek, service dns), as the converter names it.
const ZeekCategoryPrefix = "zeek_"

// genericZeekLogs are the Zeek logs the generic categories' events are
// written as.
var genericZeekLogs = map[string]string{"dns": "dns", "proxy": "http", "firewall": "conn"}

// IsNetworkCategory reports whether a category is a network one.
func IsNetworkCategory(category string) bool {
	_, generic := genericZeekLogs[category]
	return generic || strings.HasPrefix(category, ZeekCategoryPrefix)
}

// NetworkChannel is the channel of a network category's test events.
func NetworkChannel(category string) string {
	if log, ok := genericZeekLogs[category]; ok {
		return ZeekChannelPrefix + log
	}
	return ZeekChannelPrefix + strings.TrimPrefix(category, ZeekCategoryPrefix)
}

// NetworkBases are Bases for the network categories: a connection's
// 4-tuple, and the fields every line of the log has.
var NetworkBases = map[string]map[string]string{
	"dns": {
		"src_ip": "192.0.2.10", "src_port": "53124", "dst_ip": "192.0.2.53", "dst_port": "53",
		"query": "updates.example.com", "record_type": "A",
	},
	"proxy": {
		"c-ip": "192.0.2.10", "dst_ip": "198.51.100.20", "dst_port": "80",
		"cs-host": "downloads.example.com", "cs-method": "GET", "sc-status": "200",
		"c-useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	},
	"firewall": {
		"src_ip": "192.0.2.10", "src_port": "50123", "dst_ip": "198.51.100.20", "dst_port": "8443", "protocol": "tcp",
	},
}

// zeekTupleBase is the 4-tuple of a Zeek rule's events.
var zeekTupleBase = map[string]string{
	"id.orig_h": "192.0.2.10", "id.orig_p": "50123", "id.resp_h": "198.51.100.20", "id.resp_p": "445",
}

// zeekLogBases are the fields of each Zeek log's typical line, beyond the
// 4-tuple.
var zeekLogBases = map[string]map[string]string{
	"dns":       {"proto": "udp", "query": "updates.example.com", "qtype_name": "A", "rcode_name": "NOERROR", "id.resp_p": "53"},
	"http":      {"method": "GET", "host": "downloads.example.com", "uri": "/files/update.bin", "status_code": "200", "id.resp_p": "80"},
	"x509":      {"certificate.subject": "CN=www.example.com", "certificate.issuer": "CN=Example CA"},
	"smb_files": {"action": "SMB::FILE_OPEN", "path": `\\fs-01\share`, "name": "report.docx"},
	"dce_rpc":   {"endpoint": "samr", "operation": "SamrConnect5", "named_pipe": `\pipe\samr`},
	"kerberos":  {"request_type": "TGS", "client": "alice/CORP.EXAMPLE", "service": "host/fs-01.corp.example", "cipher": "aes256-cts-hmac-sha1-96"},
	"rdp":       {"cookie": "alice", "result": "Success", "security_protocol": "HYBRID", "id.resp_p": "3389"},
}

// NetworkBase returns the base event of a network category.
func NetworkBase(category string) map[string]string {
	if b, ok := NetworkBases[category]; ok {
		return b
	}
	log := strings.TrimPrefix(category, ZeekCategoryPrefix)
	out := maps.Clone(zeekTupleBase)
	if log == "x509" {
		// A certificate has no connection.
		out = map[string]string{}
	}
	maps.Copy(out, zeekLogBases[log])
	return out
}

// NetworkCases turns synthesized events of a network category into test
// cases. A generic rule's events that name a part of the address (c-uri)
// without the whole of it get the whole address, as a sensor sees it,
// and whether the rule matches is asked again of the event as written.
func NetworkCases(rule *Rule, category string, syn *Synthesis) []Case {
	channel := NetworkChannel(category)
	eventID := ""
	if _, generic := genericZeekLogs[category]; generic {
		eventID = category
	}
	var out []Case
	seen := map[string]bool{}
	add := func(ev map[string]string) {
		ev = maps.Clone(ev)
		if category == "proxy" {
			fullURI(ev)
		}
		m, err := rule.Match(ev)
		if err != nil {
			return
		}
		k := String(ev)
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, Case{Expect: m, Source: "synthesized", Channel: channel, EventID: eventID, Data: ev})
	}
	for _, ev := range syn.Positive {
		add(ev)
	}
	for _, ev := range syn.Negative {
		add(ev)
	}
	return out
}

// fullURI makes a proxy event's c-uri the whole address of the request,
// as a sensor's http.log line gives it: the server's name, the path
// (c-uri-stem) and the query (c-uri-query).
func fullURI(ev map[string]string) {
	u, hasURI := ev["c-uri"]
	stem, hasStem := ev["c-uri-stem"]
	q, hasQuery := ev["c-uri-query"]
	if !hasURI && !hasStem && !hasQuery {
		return
	}
	if !hasURI {
		u = stem
		if u == "" {
			u = "/"
		}
	}
	if hasQuery && !strings.Contains(u, "?") {
		u += "?" + q
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		host := ev["cs-host"]
		if host == "" {
			host = ev["r-dns"]
		}
		if host == "" {
			host = "downloads.example.com"
			ev["cs-host"] = host
		}
		if !strings.HasPrefix(u, "/") {
			u = "/" + u
		}
		u = "http://" + host + u
	}
	ev["c-uri"] = u
	// The path and query as the parser splits them from the address.
	rest := u[strings.Index(u, "://")+3:]
	path := "/"
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		path = rest[i:]
	}
	path, query, _ := strings.Cut(path, "?")
	if hasStem {
		ev["c-uri-stem"] = path
	}
	if hasQuery {
		ev["c-uri-query"] = query
	}
}

// zeekNumbers and zeekBools are the keys Zeek writes as JSON numbers and
// booleans; zeekLists those it writes as lists.
var (
	zeekNumbers = map[string]bool{
		"id.orig_p": true, "id.resp_p": true, "trans_id": true, "rcode": true, "qtype": true, "qclass": true, "Z": true,
		"status_code": true, "trans_depth": true, "request_body_len": true, "response_body_len": true,
		"orig_bytes": true, "resp_bytes": true, "orig_pkts": true, "resp_pkts": true, "missed_bytes": true,
		"size": true, "certificate.version": true, "certificate.key_length": true,
	}
	zeekBools = map[string]bool{
		"AA": true, "TC": true, "RD": true, "RA": true, "rejected": true, "local_orig": true, "local_resp": true,
		"established": true, "resumed": true, "success": true, "forwardable": true, "renewable": true,
	}
	zeekLists = map[string]bool{"answers": true, "TTLs": true, "resp_mime_types": true, "orig_mime_types": true, "san.dns": true}
)

// zeekValue is a key's value as Zeek writes it in JSON.
func zeekValue(k, v string) any {
	switch {
	case zeekNumbers[k]:
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	case zeekBools[k]:
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	case zeekLists[k]:
		return []any{v}
	}
	return v
}

// genericToZeek are the Zeek keys of the generic categories' fields.
var genericToZeek = map[string]map[string]string{
	"dns": {
		"query": "query", "answer": "answers", "record_type": "qtype_name",
		"src_ip": "id.orig_h", "src_port": "id.orig_p", "dst_ip": "id.resp_h", "dst_port": "id.resp_p",
	},
	"proxy": {
		"c-uri": "uri", "c-uri-stem": "", "c-uri-query": "", "c-useragent": "user_agent", "cs-host": "host", "r-dns": "host", "cs-method": "method",
		"sc-status": "status_code", "cs-referrer": "referrer", "cs-bytes": "request_body_len", "sc-bytes": "response_body_len",
		"c-ip": "id.orig_h", "src_ip": "id.orig_h", "dst_ip": "id.resp_h", "dst_port": "id.resp_p",
	},
	"firewall": {
		"src_ip": "id.orig_h", "src_port": "id.orig_p", "dst_ip": "id.resp_h", "dst_port": "id.resp_p", "protocol": "proto",
	},
}

// zeekRecord is a network case's Zeek log line: its own keys for a Zeek
// rule's event, else its fields as the Zeek keys a sensor writes them as.
func (c Case) zeekRecord(host string, t time.Time) (string, map[string]any) {
	log := strings.TrimPrefix(c.Channel, ZeekChannelPrefix)
	rec := map[string]any{"_path": log, "uid": "CHhAvVGS1DHFjwGM9"}
	if toZeek, generic := genericZeekLogs[c.EventID]; generic {
		log = toZeek
		names := genericToZeek[c.EventID]
		for k, v := range c.Data {
			zk, ok := names[strings.ToLower(k)]
			if !ok {
				zk = k // a field no Zeek key carries: kept as it is
			}
			if zk == "" {
				continue // a part of another field (c-uri-stem of c-uri)
			}
			rec[zk] = zeekValue(zk, v)
		}
		switch c.EventID {
		case "dns":
			rec["rcode_name"], rec["rcode"] = "NOERROR", int64(0)
		case "proxy":
			// A proxy's c-uri is the whole address, which a proxy
			// request's uri also is; the Host header names the server.
			if u, ok := rec["uri"].(string); ok && rec["host"] == nil {
				if h, ok := hostOf(u); ok {
					rec["host"] = h
				}
			}
		case "firewall":
			rec["conn_state"] = "SF"
		}
	} else {
		for k, v := range c.Data {
			rec[k] = zeekValue(k, v)
		}
	}
	rec["_path"] = log
	// The sensor's name, which also keeps two cases' lines (and so their
	// document IDs) apart.
	rec["_node_name"] = host
	rec["ts"] = float64(t.UnixMicro()) / 1e6
	line, _ := json.Marshal(rec)
	return ingest.ZeekTag + "." + log, map[string]any{"log": string(line), "hostname": host}
}

// hostOf is the host of a whole address.
func hostOf(u string) (string, bool) {
	for _, s := range []string{"http://", "https://"} {
		if rest, ok := strings.CutPrefix(u, s); ok {
			h, _, _ := strings.Cut(rest, "/")
			return h, h != ""
		}
	}
	return "", false
}
