package ingest

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// eveDocs sends eve.json's test lines as Fluent Bit's tail input does and
// returns the events.
func eveDocs(t *testing.T) []Event {
	t.Helper()
	var evs []Event
	for _, line := range sensorLines(t, "suricata", "eve.json") {
		ev := Normalize("suricata.eve", map[string]any{"log": line, "hostname": "nsm-01"}, now)
		if ev.ID == "" || ev.Fields["vendor_product"] != "Suricata" || ev.Fields["host"] != "nsm-01" {
			t.Errorf("ID %q vendor %v host %v", ev.ID, ev.Fields["vendor_product"], ev.Fields["host"])
		}
		for k := range ev.Fields {
			if strings.Contains(k, ".") {
				t.Errorf("dotted field %q", k)
			}
		}
		evs = append(evs, ev)
	}
	return evs
}

func TestSuricataAlerts(t *testing.T) {
	evs := eveDocs(t)
	a := evs[0].Document()
	expect(t, a, map[string]any{
		"datamodel": "Intrusion_Detection", "sourcetype": "suricata:alert", "action": "allowed", "ids_type": "network",
		"signature": "ET INFO EXE - Served Attached HTTP", "signature_id": "2014520", "category": "Misc activity",
		"severity": "high", "severity_id": int64(1), "src": "203.0.113.80", "src_port": int64(80),
		"dest": "192.168.10.21", "dest_port": int64(49822), "transport": "tcp", "app": "http", "vlan": int64(10),
		"direction": "inbound", "dest_host": "files.badcorp.example",
		"url": "http://files.badcorp.example/invoice.exe", "session_id": "1805461738637437123",
		"community_id": "1:wF8Jz4qkWxS1Zy3XaGQm9tTo4M0=", "suricata_gid": int64(1), "suricata_rev": int64(7),
		"suricata_in_iface": "ens192", "suricata_tx_id": int64(0), "suricata_event_type": "alert",
		"@timestamp": "2026-10-11T12:01:00.123456Z",
	})
	if m := a["mitre"]; !reflect.DeepEqual(m, []string{"T1105"}) {
		t.Errorf("mitre = %#v", m)
	}
	for _, k := range []string{"payload", "packet"} {
		if _, ok := a[k]; ok {
			t.Errorf("%s stored as a field", k)
		}
	}
	msg := a["message"].(string)
	if strings.Contains(msg, `"payload"`) || strings.Contains(msg, `"packet"`) || strings.Contains(msg, "R0VUIC9pbnZvaWNl") {
		t.Errorf("payload left in message")
	}
	if !strings.Contains(msg, "1805461738637437123") {
		t.Errorf("flow_id changed in message")
	}
	if p := a["suricata_payload_printable"].(string); len(p) != maxPayloadPrintable || !strings.HasPrefix(p, "GET /invoice.exe") {
		t.Errorf("payload_printable: %d bytes", len(p))
	}
	if strings.Contains(msg, strings.Repeat("A", maxPayloadPrintable)) {
		t.Error("payload_printable not cut in message")
	}
	expect(t, evs[1].Document(), map[string]any{"severity": "medium", "action": "blocked", "dest_host": "c2.badcorp.example", "url": nil, "direction": "outbound"})
	expect(t, evs[2].Document(), map[string]any{"severity": "low", "severity_id": int64(3), "dest_host": "lookup.badcorp.example", "transport": "udp"})
	expect(t, evs[3].Document(), map[string]any{"severity": "informational", "severity_id": int64(4)})
	expect(t, evs[4].Document(), map[string]any{"severity": "critical", "severity_id": int64(2), "dest_host": "pay.ransom.example"})
}

func TestSuricataFlow(t *testing.T) {
	evs := eveDocs(t)
	expect(t, evs[5].Document(), map[string]any{
		"datamodel": "Network_Traffic", "action": "failed", "bytes_out": int64(180), "bytes_in": int64(0), "bytes": int64(180),
		"packets_out": int64(3), "packets_in": int64(0), "duration": 3.0, "conn_state": "new", "suricata_flow_state": "new",
		"suricata_flow_reason": "timeout", "suricata_alerted": "false", "direction": "internal", "community_id": "1:abc=",
		"signature": "Connection",
	})
	expect(t, evs[6].Document(), map[string]any{"action": "allowed", "duration": 0.4, "bytes": int64(31800), "app": "tls",
		"direction": "outbound", "suricata_alerted": "true"})
}

func TestSuricataDNS(t *testing.T) {
	evs := eveDocs(t)
	// Suricata 7: a query (kept outside the data model; see
	// TestSuricataDNSDirectionAndDuplicates).
	expect(t, evs[7].Document(), map[string]any{
		"datamodel": "Other", "query": "updates.example.net", "query_type": "A", "src": "192.168.10.21",
		"src_port": int64(53211), "dest_ip": "192.168.10.2", "dest_port": int64(53), "dest": nil, "reply_code": nil,
	})
	// Suricata 7: an answer, written asker first like the question.
	expect(t, evs[8].Document(), map[string]any{"query": "nothere.example", "reply_code": "NXDomain", "reply_code_id": int64(3),
		"src": "192.168.10.21", "src_port": int64(53211), "dest_ip": "192.168.10.2", "dest_port": int64(53), "dest": nil})
	// Suricata 8.
	d := evs[9].Document()
	expect(t, d, map[string]any{"query": "www.example.com", "query_type": "AAAA", "reply_code": "NoError", "reply_code_id": int64(0), "ttl": int64(120)})
	if a := d["answer"]; !reflect.DeepEqual(a, []string{"2001:db8::10", "2001:db8::11"}) {
		t.Errorf("answer = %#v", a)
	}
}

func TestSuricataDNSDirectionAndDuplicates(t *testing.T) {
	evs := eveDocs(t)
	// The question is kept outside Network_Resolution, so a lookup
	// counts once (its answer).
	q := evs[7].Document()
	expect(t, q, map[string]any{"datamodel": "Other", "signature": "DNS request", "query": "updates.example.net"})
	if evs[7].Model != "Other" || evs[8].Model != "Network_Resolution" {
		t.Errorf("models %s %s", evs[7].Model, evs[8].Model)
	}
	// mDNS: 5353 to 5353 keeps its asker.
	expect(t, evs[16].Document(), map[string]any{"datamodel": "Network_Resolution", "src": "192.168.10.30",
		"dest_ip": "224.0.0.251", "query": "printer.local"})
	// IPv6 in Suricata's full form is stored in the short form.
	expect(t, evs[17].Document(), map[string]any{"datamodel": "Other", "signature": "DNS request",
		"src": "2001:db8::10", "dest_ip": "2001:db8::53"})
	d := evs[18].Document()
	expect(t, d, map[string]any{"datamodel": "Network_Resolution", "src": "2001:db8::10", "dest_ip": "2001:db8::53"})
	if a := d["answer"]; !reflect.DeepEqual(a, []string{"2001:db8::11"}) {
		t.Errorf("answer = %#v", a)
	}
	// A record that plainly came from the server's side (DNS port to a
	// port that is not one) is still turned round.
	r := decode(t, `{"event_type":"dns","src_ip":"192.0.2.53","src_port":53,"dest_ip":"192.0.2.10","dest_port":40000,"proto":"UDP","dns":{"type":"answer","rrname":"a.example","rrtype":"A","rcode":"NOERROR"}}`)
	expect(t, ParseSuricataEVE(r, "").Document(), map[string]any{"src": "192.0.2.10", "src_port": int64(40000),
		"dest_ip": "192.0.2.53", "dest_port": int64(53)})
}

func TestSuricataAlertWithoutPortsAndLocalHost(t *testing.T) {
	evs := eveDocs(t)
	expect(t, evs[19].Document(), map[string]any{"datamodel": "Intrusion_Detection", "severity": "high",
		"src": "192.168.10.21", "dest": "203.0.113.66", "dest_port": nil, "direction": "outbound", "local_host": "192.168.10.21"})
	// Inbound: the local end is dest.
	expect(t, evs[0].Document(), map[string]any{"direction": "inbound", "local_host": "192.168.10.21"})
	// Internal: both ends.
	if lh := evs[2].Document()["local_host"]; !reflect.DeepEqual(lh, []string{"192.168.10.21", "192.168.10.2"}) {
		t.Errorf("internal local_host = %#v", lh)
	}
}

func TestSuricataFTPAndVNCSecretsDropped(t *testing.T) {
	evs := eveDocs(t)
	for _, i := range []int{20, 21} {
		d := evs[i].Document()
		all := fmt.Sprint(d)
		for _, secret := range []string{"Hunter2-ftp-secret", "0805b790b58e967f2b350a0c99de3881", "aecb26faeaaa62179636a5934bac1078"} {
			if strings.Contains(all, secret) {
				t.Errorf("event %d keeps a secret: %s", i, all)
			}
		}
	}
	if d, _ := evs[20].Document()["suricata_detail"].(string); !strings.Contains(d, "(hidden)") {
		t.Errorf("ftp detail = %q", d)
	}
}

func TestSuricataHTTPAndTLS(t *testing.T) {
	evs := eveDocs(t)
	h := evs[10].Document()
	expect(t, h, map[string]any{
		"datamodel": "Web", "http_method": "GET", "dest_host": "updates.example.net", "url_domain": "updates.example.net",
		"url": "http://updates.example.net:8080/v2/check?os=win", "uri_path": "/v2/check", "uri_query": "os=win",
		"status": "404", "http_user_agent": "curl/8.5.0", "http_referrer": "http://portal.example.com/",
		"http_content_type": "text/html", "bytes_in": int64(162),
	})
	if msg := h["message"].(string); strings.Contains(msg, "http_request_body") || strings.Contains(msg, "secret page") {
		t.Errorf("HTTP body left in message: %s", msg)
	}
	expect(t, evs[11].Document(), map[string]any{
		"datamodel": "Certificates", "ssl_version": "TLS 1.2", "ssl_hash": "aabbccddeeff00112233445566778899aabbccdd",
		"ssl_serial": "7A:3F:91:B2", "ssl_server_name": "c2.badcorp.example", "dest_host": "c2.badcorp.example",
		"ssl_start_time": "2026-01-01T00:00:00Z", "ssl_end_time": "2027-01-01T00:00:00Z",
		"ja3": "72a589da586844d7f0818ce684948eea", "ja3s": "f4febc55ea12b31ae17cfb7e614afda8",
		"ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1", "ssl_subject_common_name": "c2.badcorp.example",
		"ssl_self_signed": "true",
	})
}

func TestSuricataFileinfo(t *testing.T) {
	evs := eveDocs(t)
	expect(t, evs[12].Document(), map[string]any{
		"datamodel": "File_Transfers", "file_name": "invoice.exe", "file_size": int64(73802),
		"file_md5": "5a2b9c3d4e5f60718293a4b5c6d7e8f9", "file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"mime_type": "PE32 executable (GUI) Intel 80386, for MS Windows", "url": "http://files.badcorp.example/invoice.exe",
		// The download went from the server to the workstation.
		"src": "203.0.113.80", "src_port": int64(80), "dest": "192.168.10.21", "dest_port": int64(49822), "direction": "inbound",
		"suricata_file_state": "CLOSED", "suricata_file_stored": "false",
	})
}

func TestSuricataStatsAnomalyAndOthers(t *testing.T) {
	evs := eveDocs(t)
	s := evs[13].Document()
	expect(t, s, map[string]any{"datamodel": "Other", "sourcetype": "suricata:stats", "uptime_seconds": int64(3600),
		"packets_received": int64(99880), "packets_dropped": int64(120), "drop_percent": 0.12,
		"message": "Suricata stats: 99880 packets, 120 dropped (0.12%)"})
	if len(s) > 15 {
		t.Errorf("stats keeps %d fields: %v", len(s), s)
	}
	expect(t, evs[14].Document(), map[string]any{"datamodel": "Other", "sourcetype": "suricata:anomaly",
		"suricata_anomaly_type": "decode", "suricata_anomaly_event": "ipv4.trunc_pkt", "src": "192.168.10.21", "dest": "198.51.100.7"})
	o := evs[15].Document()
	expect(t, o, map[string]any{"datamodel": "Other", "sourcetype": "suricata:ssh", "app": "ssh", "dest_port": int64(22)})
	if d, _ := o["suricata_detail"].(string); !strings.Contains(d, "OpenSSH_9.6") {
		t.Errorf("suricata_detail = %v", o["suricata_detail"])
	}
	for k := range o {
		if strings.HasPrefix(k, "ssh") {
			t.Errorf("field %s from an unmapped type", k)
		}
	}
	// A line that is not EVE JSON stays searchable.
	u := Normalize("suricata.eve", map[string]any{"log": "10/11/2026-12:00:00 [**] fast.log line", "hostname": "nsm-01"}, now)
	if u.Model != "Other" || u.Fields["sourcetype"] != "suricata:unknown" || u.ID != "" {
		t.Errorf("non-EVE line: %s %v", u.Model, u.Fields)
	}
}

func TestIsSuricataEVE(t *testing.T) {
	yes := decode(t, `{"timestamp":"2026-10-11T12:00:00.000000+0000","event_type":"alert","src_ip":"192.0.2.1","dest_ip":"192.0.2.2"}`)
	if !IsSuricataEVE(yes) {
		t.Error("EVE alert not recognized")
	}
	if !IsSuricataEVE(decode(t, `{"timestamp":"2026-10-11T12:00:00.000000+0000","event_type":"stats","stats":{}}`)) {
		t.Error("EVE stats not recognized")
	}
	for _, s := range []string{
		// A Wazuh alert.
		`{"timestamp":"2026-10-11T12:00:00.000+0000","event_type":"x","src_ip":"192.0.2.1","rule":{"id":"1"},"agent":{"name":"a"}}`,
		// JSON with event_type but no time.
		`{"event_type":"login","src_ip":"192.0.2.1"}`,
		// A Zeek record.
		`{"ts":1791720000.1,"uid":"C1","id.orig_h":"192.0.2.1"}`,
		// No address, not stats.
		`{"timestamp":"2026-10-11T12:00:00Z","event_type":"alert"}`,
		`{"timestamp":"2026-10-11T12:00:00Z","event_type":5,"src_ip":"192.0.2.1"}`,
	} {
		if IsSuricataEVE(decode(t, s)) {
			t.Errorf("recognized as EVE: %s", s)
		}
	}
}

func TestParseSuricataText(t *testing.T) {
	line := sensorLines(t, "suricata", "eve.json")[1]
	for _, text := range []string{"suricata[123]: " + line, line, "  " + line + "  "} {
		ev, ok := ParseSuricataText(text)
		if !ok || ev.Model != "Intrusion_Detection" || ev.Fields["signature_id"] != "2033966" || ev.Fields["message"] != line {
			t.Errorf("ParseSuricataText(%.40q) = %v %s", text, ok, ev.Model)
		}
	}
	for _, text := range []string{
		strings.Repeat("x", 300) + line,                // prefix over 256 bytes
		line[:len(line)-10],                            // cut short
		`suricata: {"event_type":"alert"}`,             // not EVE
		`hello {"a":1}`,                                // no event_type
		"suricata[1]: started",                         // no JSON
		`{"timestamp":"x","event_type":"alert"} extra`, // text after
	} {
		if _, ok := ParseSuricataText(text); ok {
			t.Errorf("ParseSuricataText(%.60q) took it", text)
		}
	}
}
