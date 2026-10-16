package onboard

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

// synonyms maps a sender's key, lowercased with everything but letters
// and digits removed, to the data model field it usually holds.
var synonyms = map[string]string{
	// Addresses and ports.
	"src": "src", "srcip": "src", "srcaddr": "src", "sourceip": "src", "sourceaddress": "src", "sourceaddr": "src",
	"clientip": "src", "clientaddr": "src", "clientaddress": "src", "remoteip": "src", "remoteaddr": "src",
	"remoteaddress": "src", "ipsrc": "src", "saddr": "src", "cip": "src", "callingstationid": "src", "sip": "src",
	"dst": "dest", "dest": "dest", "dstip": "dest", "destip": "dest", "dstaddr": "dest", "destaddr": "dest",
	"destination": "dest", "destinationip": "dest", "destinationaddress": "dest", "daddr": "dest", "ipdst": "dest",
	"serverip": "dest", "targetip": "dest", "dip": "dest",
	"srcport": "src_port", "sport": "src_port", "sourceport": "src_port", "spt": "src_port", "clientport": "src_port",
	"dstport": "dest_port", "dport": "dest_port", "destport": "dest_port", "destinationport": "dest_port",
	"dpt": "dest_port", "serverport": "dest_port", "targetport": "dest_port",
	"proto": "transport", "protocol": "transport", "ipproto": "transport", "transport": "transport",
	"srcmac": "src_mac", "smac": "src_mac", "dstmac": "dest_mac", "dmac": "dest_mac", "vlan": "vlan", "vlanid": "vlan",
	"dsthost": "dest_host", "desthost": "dest_host", "dsthostname": "dest_host", "destinationhost": "dest_host",
	"desthostname": "dest_host", "servername": "dest_host", "srchost": "src_host", "srchostname": "src_host",
	"clienthostname": "src_host", "workstation": "src_host", "workstationname": "src_host",
	// Traffic.
	"bytes": "bytes", "totalbytes": "bytes", "bytesin": "bytes_in", "rcvdbyte": "bytes_in", "rcvdbytes": "bytes_in",
	"bytesreceived": "bytes_in", "recvbytes": "bytes_in", "bytesout": "bytes_out", "sentbyte": "bytes_out",
	"sentbytes": "bytes_out", "bytessent": "bytes_out", "packetsin": "packets_in", "rcvdpkt": "packets_in",
	"packetsout": "packets_out", "sentpkt": "packets_out", "duration": "duration", "elapsed": "duration",
	"direction": "direction", "dir": "direction",
	// Accounts and outcomes.
	"user": "user", "username": "user", "usr": "user", "userid": "user", "account": "user", "accountname": "user",
	"login": "user", "loginname": "user", "uname": "user", "suser": "src_user", "srcuser": "src_user", "duser": "user",
	"targetuser": "user", "targetusername": "user", "subjectusername": "src_user", "userdomain": "user_domain",
	"domain": "user_domain", "authmethod": "authentication_method", "authenticationmethod": "authentication_method",
	"authtype": "authentication_method", "logontype": "logon_type",
	"action": "action", "act": "action", "outcome": "action", "result": "action", "decision": "action",
	"disposition": "action", "verdict": "action", "reason": "reason", "failurereason": "reason",
	// Web.
	"url": "url", "requesturl": "url", "fullurl": "url", "uri": "uri_path", "uripath": "uri_path", "path": "uri_path",
	"requesturi": "uri_path", "csuristem": "uri_path", "query": "uri_query", "uriquery": "uri_query",
	"csuriquery": "uri_query", "querystring": "uri_query", "method": "http_method", "httpmethod": "http_method",
	"requestmethod": "http_method", "csmethod": "http_method", "verb": "http_method", "status": "status",
	"statuscode": "status", "httpstatus": "status", "responsecode": "status", "scstatus": "status",
	"useragent": "http_user_agent", "httpuseragent": "http_user_agent", "ua": "http_user_agent",
	"csuseragent": "http_user_agent", "referer": "http_referrer", "referrer": "http_referrer",
	"httpreferrer": "http_referrer", "httpreferer": "http_referrer", "contenttype": "http_content_type",
	"vhost": "dest_host", "domainname": "url_domain", "urldomain": "url_domain",
	// Processes and files.
	"commandline": "process", "cmdline": "process", "cmd": "process", "command": "process",
	"processname": "process_name", "image": "process_path", "exe": "process_path", "processpath": "process_path",
	"pid": "process_id", "processid": "process_id", "ppid": "parent_process_id", "parentprocessid": "parent_process_id",
	"parentimage": "parent_process_path", "parentcommandline": "parent_process", "parentprocessname": "parent_process_name",
	"filename": "file_name", "fname": "file_name", "filepath": "file_path", "fullpath": "file_path",
	"filehash": "file_hash", "hash": "file_hash", "md5": "file_md5", "sha1": "file_sha1", "sha256": "file_sha256",
	"filesize": "file_size", "fsize": "file_size",
	// DNS.
	"qname": "query", "dnsquery": "query", "queryname": "query", "qtype": "query_type", "querytype": "query_type",
	"rcode": "reply_code", "replycode": "reply_code", "responsecodename": "reply_code", "answer": "answer", "answers": "answer",
	// Alerts and signatures.
	"signature": "signature", "sig": "signature", "rule": "signature", "rulename": "signature", "attack": "signature",
	"threatname": "signature", "alertname": "signature", "eventname": "signature",
	"signatureid": "signature_id", "sid": "signature_id", "ruleid": "signature_id", "eventid": "signature_id",
	"eventcode": "signature_id", "severity": "severity", "sev": "severity", "level": "severity", "priority": "severity",
	"category": "category", "cat": "category", "virus": "signature", "malware": "signature", "threat": "signature",
	// The reporting system and program.
	"hostname": "host", "devname": "host", "devicename": "host", "device": "host", "computer": "host",
	"computername": "host", "host": "host", "app": "app", "application": "app", "appname": "app",
	"program": "app", "service": "app", "vendor": "vendor_product", "product": "vendor_product",
	"object": "object", "objectname": "object", "objecttype": "object_category",
}

// modelSynonyms are the readings of a key that depend on the data model,
// tried before synonyms.
var modelSynonyms = map[string]map[string]string{
	"Network_Resolution": {"query": "query", "name": "query", "type": "query_type", "ttl": "ttl"},
	"Filesystem":         {"path": "file_path", "name": "file_name", "size": "file_size", "operation": "action"},
	"Endpoint":           {"path": "process_path", "name": "process_name", "parent": "parent_process_name"},
	"Inventory":          {"name": "name", "version": "version", "os": "os"},
	"Change":             {"status": "status", "operation": "change_type", "eventtype": "change_type"},
}

// MapNameFor is MapName for a data model: a reading the model does not
// have is dropped, so a web log's path is a uri_path but a file log's is
// a file_path.
func MapNameFor(model, key string) string {
	if t, ok := modelSynonyms[model][squash(key)]; ok && modelHas(model, t) {
		return t
	}
	t := MapName(key)
	if t == "" {
		return ""
	}
	switch t {
	case "host", "vendor_product", "signature", "signature_id":
		return t
	}
	if model == "Other" {
		// Other takes any field the index knows, so the obvious ones
		// (src, user...) still help searches.
		return t
	}
	if !modelHas(model, t) {
		return ""
	}
	return t
}

// modelHints are words in the sample that suggest a data model.
var modelHints = []struct {
	model string
	re    *regexp.Regexp
}{
	{"Authentication", regexp.MustCompile(`(?i)\b(log ?in|log ?on|logged (in|on)|sign(ed)?[ -]?in|authenticat\w*|password|passwd|mfa|sshd|kerberos|radius|session opened)\b`)},
	{"Network_Traffic", regexp.MustCompile(`(?i)\b(deny|denied|accept(ed)?|permit(ted)?|drop(ped)?|block(ed)?|firewall|conn(ection)?|traffic|nat|policy|teardown|built)\b`)},
	{"Web", regexp.MustCompile(`(?:"|\b)(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS) /|\bHTTP/\d`)},
	{"Malware", regexp.MustCompile(`(?i)\b(virus|malware|trojan|quarantin\w*|infected|threat detected|ransomware)\b`)},
	{"Intrusion_Detection", regexp.MustCompile(`(?i)\b(ids|ips|intrusion|attack|exploit|signature|snort|suricata)\b`)},
	{"Network_Resolution", regexp.MustCompile(`(?i)\b(dns|query\[|qname|nxdomain|resolv\w*)\b`)},
	{"Endpoint", regexp.MustCompile(`(?i)\b(process (created|started)|cmdline|commandline|command line|execve|parent process)\b`)},
	{"Change", regexp.MustCompile(`(?i)\b(created|deleted|modified|changed|added|removed|updated) (user|group|role|policy|account|permission|config\w*)\b`)},
}

// fieldWeight is how strongly a mapped field points at its models: 3
// for fields only one or two models have.
var fieldWeight = map[string]int{
	"http_method": 3, "uri_path": 3, "http_user_agent": 3, "http_referrer": 3, "status": 1, "url": 2,
	"query": 3, "query_type": 3, "reply_code": 3, "answer": 3,
	"process": 3, "parent_process": 3, "parent_process_name": 3, "process_path": 2,
	"authentication_method": 3, "logon_type": 3, "src_user": 2,
	"bytes_in": 2, "bytes_out": 2, "packets_in": 2, "transport": 2, "dest_port": 2, "src_port": 1,
	"file_hash": 2, "file_name": 1, "file_path": 1, "signature": 1, "severity": 1,
}

// MapName suggests the data model field a sender's key holds, or "".
func MapName(key string) string {
	if t, ok := synonyms[squash(key)]; ok {
		return t
	}
	// A dotted JSON key: its last part (source.ip, client.address).
	if i := strings.LastIndexByte(key, '.'); i > 0 {
		if t, ok := synonyms[squash(key)]; ok {
			return t
		}
		parent := key[:i]
		last := key[i+1:]
		if j := strings.LastIndexByte(parent, '.'); j >= 0 {
			parent = parent[j+1:]
		}
		switch squash(last) {
		case "ip", "address", "addr":
			if t, ok := synonyms[squash(parent)+"ip"]; ok {
				return t
			}
		case "port":
			if t, ok := synonyms[squash(parent)+"port"]; ok {
				return t
			}
		}
		if t, ok := synonyms[squash(last)]; ok {
			return t
		}
	}
	return ""
}

func squash(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// modelHas reports whether a data model (or the common fields) has a field.
func modelHas(model, field string) bool {
	if slices.ContainsFunc(datamodel.Common, func(f datamodel.Field) bool { return f.Name == field }) {
		return true
	}
	m, ok := datamodel.Get(model)
	return ok && slices.ContainsFunc(m.Fields, func(f datamodel.Field) bool { return f.Name == field })
}

// GuessModel picks the data model that fits the mapped fields and the
// sample's words best, or Other when none fits well.
func GuessModel(mapped []string, sample string) string {
	best, bestScore := "Other", 0
	for _, m := range Models() {
		if m == "Other" {
			continue
		}
		score := 0
		for _, f := range mapped {
			if f == "host" || f == "vendor_product" || f == "signature_id" {
				continue
			}
			if modelHas(m, f) {
				w := fieldWeight[f]
				if w == 0 {
					w = 1
				}
				score += w
			}
		}
		for _, h := range modelHints {
			if h.model == m && h.re.MatchString(sample) {
				score += 3
			}
		}
		if score > bestScore {
			best, bestScore = m, score
		}
	}
	if bestScore < 4 {
		return "Other"
	}
	return best
}

var (
	allowedWords = []string{"allow", "allowed", "accept", "accepted", "permit", "permitted", "pass", "passed", "built", "ok", "success", "successful", "succeeded", "open", "opened"}
	blockedWords = []string{"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "reset", "discard", "discarded", "prevent", "prevented", "refused", "quarantine", "quarantined"}
	successWords = []string{"success", "succeeded", "successful", "accept", "accepted", "ok", "pass", "passed", "allow", "allowed", "granted", "login", "logon", "authenticated"}
	failureWords = []string{"fail", "failed", "failure", "deny", "denied", "reject", "rejected", "invalid", "error", "blocked", "bad", "locked"}
)

// NormalAction maps a sender's action word onto the data model's values,
// or returns "" when it is not one Signalith knows.
func NormalAction(model, v string) string {
	w := strings.ToLower(strings.TrimSpace(v))
	switch model {
	case "Authentication", "Change":
		switch {
		case slices.Contains(successWords, w):
			return "success"
		case slices.Contains(failureWords, w):
			return "failure"
		}
	case "Network_Traffic", "Intrusion_Detection", "Web", "Malware", "Filesystem", "File_Transfers":
		switch {
		case slices.Contains(allowedWords, w):
			return "allowed"
		case slices.Contains(blockedWords, w):
			return "blocked"
		}
	}
	return ""
}

// valueKind says what a field's values look like: ip, number, time or
// text.
func valueKind(values []string) string {
	if len(values) == 0 {
		return "text"
	}
	ip, num := true, true
	for _, v := range values {
		if _, err := netip.ParseAddr(v); err != nil {
			ip = false
		}
		if _, ok := number(v); !ok {
			num = false
		}
	}
	switch {
	case ip:
		return "ip"
	case num:
		return "number"
	}
	return "text"
}
