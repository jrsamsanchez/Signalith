package detect

import (
	"strings"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// Sigma rules about network data: Zeek's own logs (product: zeek, by
// service: dns, http, x509, smb_files, ...), and the generic dns, proxy
// and firewall categories, which a network sensor (or a firewall) fills.
// Zeek rules name Zeek's own field names (query, qtype_name, id.resp_h);
// the generic categories name Sigma's taxonomy (c-uri, cs-host, dst_ip).

// zeekCategoryPrefix starts the category of a Zeek rule: zeek_dns for
// product zeek, service dns.
const zeekCategoryPrefix = "zeek_"

// sigmaNetworkCategory returns the category a network rule converts as,
// or "" for a rule about other data.
func sigmaNetworkCategory(ls map[string]any) string {
	get := func(k string) string { s, _ := ls[k].(string); return strings.ToLower(strings.TrimSpace(s)) }
	if get("product") == "zeek" && get("category") == "" && get("service") != "" {
		return zeekCategoryPrefix + get("service")
	}
	switch c := get("category"); c {
	case "dns", "proxy", "firewall":
		if p := get("product"); p == "" || p == "zeek" {
			return c
		}
	}
	return ""
}

// zeekLog returns the Zeek log a category is about (dns for zeek_dns).
func zeekLog(category string) (string, bool) {
	return strings.CutPrefix(category, zeekCategoryPrefix)
}

// zeekLogModels are the data models of the Zeek logs Signalith maps;
// every other Zeek log is in Other. The logs without zeekLogFields keep
// every key as zeek_<key> too (ingest.ZeekGenericField).
var zeekLogModels = map[string]string{
	"conn": "Network_Traffic", "dns": "Network_Resolution", "http": "Web", "ssl": "Certificates",
	"x509": "Certificates", "files": "File_Transfers", "notice": "Intrusion_Detection",
	"ssh": "Authentication", "rdp": "Authentication", "kerberos": "Authentication", "ntlm": "Authentication",
	"smb_files": "Filesystem",
}

// sigmaNetworkModel returns a network category's data model.
func sigmaNetworkModel(category string) (string, bool) {
	if log, ok := zeekLog(category); ok {
		if m, ok := zeekLogModels[log]; ok {
			return m, true
		}
		return "Other", true
	}
	switch category {
	case "dns":
		return "Network_Resolution", true
	case "proxy":
		return "Web", true
	case "firewall":
		return "Network_Traffic", true
	}
	return "", false
}

// sigmaNetworkScope limits a Zeek rule to its own log's events. The
// generic categories search their data model: a dns rule the lookups
// that name the address that asked (src), as a sensor's or a DNS
// server's do (a host's own lookups, Sysmon 22, name only the host, and
// the dns_query rules cover them); a proxy rule the web requests a
// client made, not web servers' access logs (url there is only the
// path, and the requests come in from the internet); a firewall rule
// every connection, from a sensor or a firewall.
func sigmaNetworkScope(category string) query.Expr {
	if log, ok := zeekLog(category); ok {
		return &query.Compare{Field: "sourcetype", Op: "=", Value: "zeek:" + log}
	}
	switch category {
	case "dns":
		return &query.Compare{Field: "src", Op: "=", Value: "*"}
	case "proxy":
		return &query.Not{Child: &query.In{Field: "sourcetype", Values: webServerSourcetypes}}
	}
	return nil
}

// webServerSourcetypes are the sourcetypes of web servers' access logs
// (ingest.parseWebRecord).
var webServerSourcetypes = []string{"apache:access", "nginx:access"}

// zeekTuple is how every Zeek log's connection fields are stored.
var zeekTuple = map[string]string{
	"id.orig_h": "src", "id.orig_p": "src_port", "id.resp_h": "dest", "id.resp_p": "dest_port",
	"uid": "session_id", "community_id": "community_id",
}

// zeekLogFields maps the keys of the Zeek logs with a mapping of their own
// (see ingest.ParseZeek) to Signalith fields; keys left out are not
// stored, or not as they are.
var zeekLogFields = map[string]map[string]string{
	"conn": {
		"proto": "transport", "duration": "duration", "orig_bytes": "bytes_out", "resp_bytes": "bytes_in",
		"orig_pkts": "packets_out", "resp_pkts": "packets_in", "conn_state": "conn_state", "history": "zeek_history",
		"missed_bytes": "zeek_missed_bytes", "local_orig": "zeek_local_orig", "local_resp": "zeek_local_resp",
		"orig_l2_addr": "src_mac", "resp_l2_addr": "dest_mac", "vlan": "vlan",
	},
	"dns": {
		// The resolver is dest_ip: dest is the host that looked up, in
		// host logs.
		"id.resp_h": "dest_ip", "proto": "transport", "query": "query", "qtype_name": "query_type",
		"rcode": "reply_code_id", "answers": "answer", "rejected": "zeek_rejected", "qclass_name": "zeek_qclass_name",
		"rtt": "zeek_rtt",
	},
	"http": {
		// uri is the path and query the client asked for; url is the
		// whole address (http://host/uri), so a uri that starts with /
		// is the path.
		"method": "http_method", "host": "url_domain", "uri": "uri_path", "status_code": "status",
		"user_agent": "http_user_agent", "referrer": "http_referrer", "resp_mime_types": "http_content_type",
		"request_body_len": "bytes_out", "response_body_len": "bytes_in", "username": "user", "trans_depth": "zeek_trans_depth",
	},
	"ssl": {
		"version": "ssl_version", "cipher": "ssl_cipher", "server_name": "ssl_server_name", "subject": "ssl_subject",
		"issuer": "ssl_issuer", "validation_status": "ssl_validation_status", "ja3": "ja3", "ja3s": "ja3s", "ja4": "ja4",
		"established": "zeek_established", "resumed": "zeek_resumed", "curve": "zeek_curve", "next_protocol": "zeek_next_protocol",
	},
	"x509": {
		"certificate.subject": "ssl_subject", "certificate.issuer": "ssl_issuer", "certificate.serial": "ssl_serial",
		"fingerprint": "ssl_hash", "id": "zeek_fuid",
	},
	"files": {
		"filename": "file_name", "md5": "file_md5", "sha1": "file_sha1", "sha256": "file_sha256",
		"mime_type": "mime_type", "source": "app", "fuid": "zeek_fuid", "is_orig": "zeek_is_orig",
		"seen_bytes": "zeek_seen_bytes", "missing_bytes": "zeek_missing_bytes",
	},
	"notice": {
		"note": "signature", "msg": "reason", "proto": "transport", "sub": "zeek_sub", "fuid": "zeek_fuid",
	},
}

// sigmaDNSFields, sigmaProxyFields and sigmaFirewallFields map Sigma's
// taxonomy of the generic dns, proxy and firewall categories.
var (
	sigmaDNSFields = map[string]string{
		"query": "query", "answer": "answer", "record_type": "query_type",
		"src_ip": "src", "src_port": "src_port", "dst_ip": "dest_ip", "dst_port": "dest_port",
	}
	sigmaProxyFields = map[string]string{
		// c-uri is the whole address; cs-host and r-dns the server's
		// name.
		"c-uri": "url", "c-uri-query": "uri_query", "c-uri-stem": "uri_path", "c-useragent": "http_user_agent",
		"cs-host": "url_domain", "r-dns": "url_domain", "cs-method": "http_method", "sc-status": "status",
		"cs-referrer": "http_referrer", "cs-bytes": "bytes_out", "sc-bytes": "bytes_in",
		"c-ip": "src", "src_ip": "src", "dst_ip": "dest", "dst_port": "dest_port",
	}
	// A firewall's action (accept, forward, 2) is left out: Signalith's
	// action says allowed, blocked or failed.
	sigmaFirewallFields = map[string]string{
		"src_ip": "src", "src_port": "src_port", "dst_ip": "dest", "dst_port": "dest_port",
		"protocol": "transport",
	}
)

// networkField maps a field of a network rule. ok is false when the
// rule is not about network data; field is "" when the field has no
// Signalith mapping.
func (c *sigmaConv) networkField(name string) (field string, ok bool) {
	if log, isZeek := zeekLog(c.category); isZeek {
		if _, mapped := zeekLogFields[log]; !mapped {
			return ingest.ZeekGenericField(log, name), true
		}
		if f, ok := zeekLogFields[log][name]; ok {
			return f, true
		}
		return zeekTuple[name], true
	}
	var m map[string]string
	switch c.category {
	case "dns":
		m = sigmaDNSFields
	case "proxy":
		m = sigmaProxyFields
	case "firewall":
		m = sigmaFirewallFields
	default:
		return "", false
	}
	return m[strings.ToLower(name)], true
}

// packNetworkThrottle is the throttle of a network pack rule: the
// address that sent the traffic, and what it reached.
func packNetworkThrottle(category, datamodel string) []string {
	if category == zeekCategoryPrefix+"x509" {
		return []string{"host", "ssl_hash", "ssl_serial", "ssl_subject"}
	}
	switch datamodel {
	case "Network_Resolution":
		return []string{"src", "query", "query_type"}
	case "Web":
		return []string{"src", "url_domain", "url"}
	case "Certificates":
		return []string{"src", "dest", "ssl_server_name"}
	}
	return []string{"src", "dest", "dest_port"}
}
