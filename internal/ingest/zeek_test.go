package ingest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// sensorLines reads a testdata file of one JSON object per line.
func sensorLines(t *testing.T, parts ...string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimRight(l, "\r"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// zeekDocs sends a Zeek log's test lines as Fluent Bit's tail input does
// (the line in "log", the sensor's name from the sysinfo filter, the tag
// expanded from the path) and returns the documents.
func zeekDocs(t *testing.T, log string) []map[string]any {
	t.Helper()
	var docs []map[string]any
	for _, line := range sensorLines(t, "zeek", log+".json") {
		ev := Normalize("zeek.opt.zeek.logs.current."+log+".log", map[string]any{"log": line, "hostname": "nsm-01"}, now)
		if ev.ID == "" {
			t.Errorf("%s: no document ID", log)
		}
		doc := ev.Document()
		if doc["host"] != "nsm-01" || doc["dvc"] != "nsm-01" || doc["vendor_product"] != "Zeek" || doc["sourcetype"] != "zeek:"+log {
			t.Errorf("%s: host %v dvc %v vendor %v sourcetype %v", log, doc["host"], doc["dvc"], doc["vendor_product"], doc["sourcetype"])
		}
		for k := range doc {
			if strings.Contains(k, ".") {
				t.Errorf("%s: dotted field %q", log, k)
			}
		}
		docs = append(docs, doc)
	}
	return docs
}

func TestZeekConn(t *testing.T) {
	d := zeekDocs(t, "conn")
	expect(t, d[0], map[string]any{
		"datamodel": "Network_Traffic", "src": "192.168.10.21", "src_port": int64(51522), "dest": "198.51.100.120",
		"dest_port": int64(443), "transport": "tcp", "app": "ssl", "duration": 0.4, "bytes_out": int64(1520),
		"bytes_in": int64(48210), "bytes": int64(49730), "packets_out": int64(14), "packets_in": int64(38),
		"conn_state": "SF", "action": "allowed", "direction": "outbound", "session_id": "CHhAvVGS1DHFjwGM9",
		"community_id": "1:LQU9qZlK+B5F3KDmev6m5PMibrg=", "src_mac": "00:50:56:aa:bb:01", "vlan": int64(10),
		"signature": "Connection", "zeek_history": "ShADadFf", "zeek_local_orig": "true", "zeek_local_resp": "false",
		"@timestamp": "2026-10-11T12:00:00.123456Z",
	})
	// No answer: failed, and direction from the addresses.
	expect(t, d[1], map[string]any{"conn_state": "S0", "action": "failed", "direction": "internal", "bytes": nil})
	// Refused, with Zeek's T/F flags saying the responder is local.
	expect(t, d[2], map[string]any{"conn_state": "REJ", "action": "failed", "direction": "inbound", "duration": 0.000215})
	// The first service of a list.
	expect(t, d[3], map[string]any{"app": "dns", "transport": "udp", "direction": "internal"})
	// OTH with nothing back from the responder, between two outside hosts.
	expect(t, d[4], map[string]any{"action": "failed", "direction": "external"})
}

func TestZeekDNS(t *testing.T) {
	d := zeekDocs(t, "dns")
	expect(t, d[0], map[string]any{
		"datamodel": "Network_Resolution", "query": "nothere.example", "query_type": "A", "reply_code": "NXDomain",
		"reply_code_id": int64(3), "src": "192.168.10.21", "src_port": int64(53211), "dest_ip": "192.168.10.2",
		"dest_port": int64(53), "transport": "udp", "dest": nil, "signature": "DNS query", "zeek_rejected": "false",
		"zeek_qclass_name": "C_INTERNET", "zeek_rtt": 0.0123,
	})
	expect(t, d[1], map[string]any{"reply_code": "NoError", "reply_code_id": int64(0), "ttl": int64(300)})
	if a := d[1]["answer"]; !reflect.DeepEqual(a, []string{"cdn.updates.example.net", "198.51.100.120"}) {
		t.Errorf("answer = %#v", a)
	}
}

func TestZeekHTTP(t *testing.T) {
	d := zeekDocs(t, "http")
	expect(t, d[0], map[string]any{
		"datamodel": "Web", "http_method": "GET", "dest_host": "updates.example.net", "url_domain": "updates.example.net",
		"url": "http://updates.example.net:8080/v2/check?os=win&ver=10", "uri_path": "/v2/check", "uri_query": "os=win&ver=10",
		"status": "404", "http_user_agent": "curl/8.5.0", "http_content_type": "text/html", "bytes_out": int64(0),
		"bytes_in": int64(162), "user": "svc-update", "zeek_trans_depth": int64(1), "direction": "outbound",
	})
	if _, ok := d[0]["password"]; ok {
		t.Error("password stored as a field")
	}
	if msg := d[0]["message"].(string); strings.Contains(msg, "Sup3rSecret") || strings.Contains(msg, "password") {
		t.Errorf("password left in message: %s", msg)
	}
	expect(t, d[1], map[string]any{"url": "http://forms.example.com/submit", "uri_query": nil, "status": "302",
		"http_referrer": "http://forms.example.com/", "http_method": "POST", "bytes_out": int64(512)})
}

func TestZeekSSLAndX509(t *testing.T) {
	d := zeekDocs(t, "ssl")
	expect(t, d[0], map[string]any{
		"datamodel": "Certificates", "ssl_version": "TLSv12", "ssl_cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"ssl_server_name": "c2.badcorp.example", "dest_host": "c2.badcorp.example",
		"ssl_subject_common_name": "c2.badcorp.example", "ssl_issuer_common_name": "c2.badcorp.example",
		"ssl_self_signed": "true", "ssl_validation_status": "self signed certificate",
		"ja3": "72a589da586844d7f0818ce684948eea", "ja3s": "f4febc55ea12b31ae17cfb7e614afda8",
		"ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1", "ja4s": "t120200_c030_52d195ce1d92", "zeek_established": "true", "zeek_curve": "secp256r1",
	})
	// Zeek 5 and later log no subject in ssl.log: nothing to say about it.
	expect(t, d[1], map[string]any{"ssl_self_signed": nil, "zeek_next_protocol": "h2", "zeek_resumed": "true"})

	x := zeekDocs(t, "x509")
	expect(t, x[0], map[string]any{
		"datamodel": "Certificates", "ssl_serial": "7A3F91B2", "ssl_start_time": "2026-01-01T00:00:00Z",
		"ssl_end_time": "2027-01-01T00:00:00Z", "ssl_hash": "5d2c1d1b8c06a9f0e1d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2",
		"dest_host": "c2.badcorp.example", "ssl_self_signed": "true", "ssl_subject_common_name": "c2.badcorp.example",
		"src": nil, "dest": nil,
	})
	// Before Zeek 6: the file ID instead of a fingerprint, and ISO times.
	expect(t, x[1], map[string]any{"ssl_hash": nil, "zeek_fuid": "FhYbT03u8kTd5Q2Abc", "ssl_self_signed": "false",
		"ssl_issuer_common_name": "Example Issuing CA", "ssl_start_time": "2026-01-01T00:00:00Z", "dest_host": "www.example.com"})
}

func TestZeekFiles(t *testing.T) {
	d := zeekDocs(t, "files")
	// A download: the server sent the file to the workstation.
	expect(t, d[0], map[string]any{
		"datamodel": "File_Transfers", "file_name": "invoice.exe", "file_size": int64(73802),
		"file_md5": "5a2b9c3d4e5f60718293a4b5c6d7e8f9", "file_sha1": "1f2e3d4c5b6a79881726354453627180a9b8c7d6",
		"file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"file_hash":   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"mime_type":   "application/x-dosexec", "app": "HTTP", "src": "198.51.100.120", "src_port": int64(80),
		"dest": "192.168.10.21", "dest_port": int64(49822), "direction": "inbound", "zeek_fuid": "FgYfdg2nJRbjL0Bqo4",
		"zeek_is_orig": "false", "zeek_seen_bytes": int64(73802), "session_id": "CmES5u32sYpV7JYN",
	})
	// Before Zeek 5: tx_hosts and rx_hosts, and only seen_bytes.
	expect(t, d[1], map[string]any{"src": "192.168.10.21", "dest": "192.168.10.5", "direction": "internal",
		"file_size": int64(20480), "session_id": "C4J4Th3PJpwUYZZ6gc", "app": "SMB"})
}

func TestZeekNotice(t *testing.T) {
	d := zeekDocs(t, "notice")
	expect(t, d[0], map[string]any{
		"datamodel": "Intrusion_Detection", "signature": "Scan::Port_Scan", "signature_id": "Scan::Port_Scan",
		"ids_type": "network", "category": "Zeek notice", "severity": "medium", "severity_id": int64(2),
		"action": "allowed", "src": "203.0.113.66", "dest": "192.168.10.5", "direction": "inbound",
		"reason":    "203.0.113.66 scanned at least 15 unique ports of host 192.168.10.5 in 0m3s",
		"dest_host": nil, "zeek_sub": "local", "zeek_note": "Scan::Port_Scan",
	})
	if !strings.HasPrefix(d[0]["message"].(string), `{"ts":1791720050.0,"note"`) {
		t.Errorf("message is not the raw line: %v", d[0]["message"])
	}
	expect(t, d[1], map[string]any{"dest_host": "c2.badcorp.example", "src": "192.168.10.21", "dest": "203.0.113.66",
		"dest_port": int64(8443), "direction": "outbound", "transport": "tcp", "local_host": "192.168.10.21"})
	expect(t, d[0], map[string]any{"local_host": "192.168.10.5"})

	// An Address_Scan notice names only the scanner: local_host is set
	// when it is one of yours, so a scan from the internet has none.
	for src, want := range map[string]any{"192.168.10.21": "192.168.10.21", "203.0.113.66": nil} {
		r := map[string]any{"ts": 1791720000.0, "note": "Scan::Address_Scan", "src": src, "p": 445,
			"msg": src + " scanned at least 25 unique hosts on port 445/tcp in 0m50s"}
		got := ParseZeek("notice", r, "nsm-01").Fields
		if got["local_host"] != want || got["direction"] != nil {
			t.Errorf("Address_Scan from %s: local_host %v, direction %v", src, got["local_host"], got["direction"])
		}
	}
}

func TestZeekNTLMHostnameIsNotTheSensor(t *testing.T) {
	// ntlm.log's hostname is the name the client sent; a record decoded
	// before it reached Signalith must not take it as the sensor's name.
	r := map[string]any{"ts": 1791720000.0, "uid": "Cntlm", "id.orig_h": "192.168.10.21", "id.resp_h": "192.168.10.5",
		"hostname": "DC01", "username": "bob", "domainname": "CORP", "_node_name": "nsm-01"}
	d := Normalize("zeek.opt.zeek.logs.current.ntlm.log", r, now).Document()
	expect(t, d, map[string]any{"host": "nsm-01", "dvc": "nsm-01", "zeek_hostname": "DC01"})
	// Without another name, the event's origin decides.
	delete(r, "_node_name")
	if h := ParseZeek("ntlm", r, "").Fields["host"]; h != nil {
		t.Errorf("host = %v", h)
	}
}

func TestZeekHealth(t *testing.T) {
	c := zeekDocs(t, "capture_loss")
	expect(t, c[0], map[string]any{"datamodel": "Other", "capture_loss_percent": 0.3, "zeek_peer": "worker-1-1"})
	s := zeekDocs(t, "stats")
	expect(t, s[0], map[string]any{"datamodel": "Other", "packets_received": int64(1840220), "packets_dropped": int64(120), "zeek_peer": "zeek"})
	if len(s[0]) > 15 {
		t.Errorf("stats keeps %d fields", len(s[0]))
	}
}

func TestZeekGenericLog(t *testing.T) {
	d := zeekDocs(t, "smb_mapping")[0]
	expect(t, d, map[string]any{
		"datamodel": "Other", "sourcetype": "zeek:smb_mapping", "src": "192.168.10.21", "dest_port": int64(445),
		"session_id": "C4J4Th3PJpwUYZZ6gc", "zeek_path": `\\FILE-01\Finance`, "zeek_share_type": "DISK",
		"zeek_smb_dialect": "SMB 3.1.1", "zeek_nested": `{"a":1}`,
	})
	// A log with very many keys keeps at most maxZeekGenericFields of them.
	r := map[string]any{"ts": 1791720000.0, "uid": "Cabc"}
	for i := range 200 {
		r["k"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	ev := ParseZeek("weird", r, "")
	n := 0
	for k := range ev.Fields {
		if strings.HasPrefix(k, "zeek_") {
			n++
		}
	}
	if n > maxZeekGenericFields {
		t.Errorf("%d zeek_ fields", n)
	}
}

func TestZeekLogTypeFromTag(t *testing.T) {
	for _, c := range []struct {
		tag  string
		rec  map[string]any
		want string
	}{
		{"zeek.conn", nil, "conn"},
		{"zeek.opt.zeek.logs.current.conn.log", nil, "conn"},
		{"zeek.nsm.zeek.logs.current.dns.log", nil, "dns"},
		{"zeek.usr.local.zeek.logs.current.known-hosts.log", nil, "known_hosts"},
		{"zeek", map[string]any{"_path": "http"}, "http"},
		{"zeek.sensor1", map[string]any{"_path": "ssl"}, "ssl"},
		{"zeek", map[string]any{"file": "/opt/zeek/logs/current/files.log"}, "files"},
		{"zeek", map[string]any{"proto": "tcp", "conn_state": "SF"}, "conn"},
		{"zeek", map[string]any{"query": "a.example", "rcode": 0}, "dns"},
		{"zeek", map[string]any{"method": "GET", "uri": "/"}, "http"},
		{"zeek", map[string]any{"version": "TLSv13", "server_name": "a.example"}, "ssl"},
		{"zeek", map[string]any{"certificate.subject": "CN=a"}, "x509"},
		{"zeek", map[string]any{"fuid": "F1", "mime_type": "text/plain"}, "files"},
		{"zeek", map[string]any{"note": "Scan::Port_Scan"}, "notice"},
		{"zeek", map[string]any{"percent_lost": 0.1}, "capture_loss"},
		{"zeek.$(rm -rf).log", nil, "rm_rf"},
		{"zeek", map[string]any{}, "unknown"},
		{"zeek.sensor1", map[string]any{}, "sensor1"},
	} {
		if got := zeekLogType(c.tag, c.rec); got != c.want {
			t.Errorf("zeekLogType(%q, %v) = %q, want %q", c.tag, c.rec, got, c.want)
		}
	}
	if got := zeekLogType("zeek."+strings.Repeat("a", 100)+".log", nil); len(got) > 40 {
		t.Errorf("log type of %d bytes", len(got))
	}
}

func TestZeekTimes(t *testing.T) {
	want := time.Date(2026, 10, 11, 12, 0, 0, 500000000, time.UTC)
	for _, v := range []any{1791720000.5, json.Number("1791720000.5"), "1791720000.5", "2026-10-11T12:00:00.5Z"} {
		got, ok := zeekTime(v)
		if !ok || !got.Equal(want) {
			t.Errorf("zeekTime(%#v) = %v %v", v, got, ok)
		}
	}
	for _, v := range []any{nil, "", "yesterday", -5.0, json.Number("1e300"), true} {
		if _, ok := zeekTime(v); ok {
			t.Errorf("zeekTime(%#v) is a time", v)
		}
	}
	// No ts: the record's time, as for any record.
	ev := Normalize("zeek.conn", map[string]any{"log": `{"uid":"C1","id.orig_h":"192.0.2.1","proto":"tcp","conn_state":"SF"}`}, now)
	if !ev.Time.Equal(now) {
		t.Errorf("time = %v", ev.Time)
	}
}

func TestZeekRawLine(t *testing.T) {
	line := sensorLines(t, "zeek", "conn.json")[0]
	a := Normalize("zeek.conn", map[string]any{"log": line, "hostname": "nsm-01"}, now)
	b := Normalize("zeek.conn", map[string]any{"log": line + "\n", "hostname": "nsm-01"}, now.Add(time.Hour))
	c := Normalize("zeek.conn", map[string]any{"log": sensorLines(t, "zeek", "conn.json")[1], "hostname": "nsm-01"}, now)
	if a.Fields["host"] != "nsm-01" || a.ID == "" || a.ID != b.ID || a.ID == c.ID || len(a.ID) != 32 {
		t.Errorf("host %v, IDs %q %q %q", a.Fields["host"], a.ID, b.ID, c.ID)
	}
	if a.Fields["message"] != line {
		t.Errorf("message = %v", a.Fields["message"])
	}
	// The same line as another log type is another event.
	if d := Normalize("zeek.dns", map[string]any{"log": line}, now); d.ID == a.ID {
		t.Error("same ID for another log type")
	}
	// Tab-separated logs (json-logs not loaded) stay searchable.
	tsv := "1791720000.123456\tCHhAvVGS1DHFjwGM9\t192.168.10.21\t51522\t198.51.100.120\t443\ttcp"
	u := Normalize("zeek.conn", map[string]any{"log": tsv, "hostname": "nsm-01"}, now)
	if u.Model != "Other" || u.Fields["sourcetype"] != "zeek:unknown" || u.Fields["message"] != tsv || u.Fields["vendor_product"] != "Zeek" {
		t.Errorf("tsv line: %s %v", u.Model, u.Fields)
	}
	// A record Fluent Bit decoded already.
	rec := decode(t, line)
	ev := Normalize("zeek.conn", rec, now)
	if ev.Model != "Network_Traffic" || ev.ID == "" || ev.Fields["src"] != "192.168.10.21" {
		t.Errorf("decoded record: %s %v", ev.Model, ev.Fields)
	}
}
