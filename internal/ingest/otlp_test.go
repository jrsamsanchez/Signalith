package ingest

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A small OTLP encoder for tests, in protobuf and JSON, so every case runs
// through both decoders.

type tKV struct {
	k string
	v any // string, bool, int, int64, float64, []byte, []any or []tKV (a kvlist)
}

type tRec struct {
	time, observed uint64
	sev            int
	sevText        string
	body           any
	attrs          []tKV
	trace, span    []byte
	eventName      string
}

type tRes struct {
	attrs []tKV
	scope string
	recs  []tRec
}

func pbTag(b []byte, num, wire int) []byte {
	return binary.AppendUvarint(b, uint64(num)<<3|uint64(wire))
}

func pbLen(b []byte, num int, data []byte) []byte {
	b = pbTag(b, num, wireBytes)
	b = binary.AppendUvarint(b, uint64(len(data)))
	return append(b, data...)
}

func pbAny(v any) []byte {
	var b []byte
	switch x := v.(type) {
	case string:
		b = pbLen(b, 1, []byte(x))
	case bool:
		b = pbTag(b, 2, wireVarint)
		if x {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	case int:
		b = binary.AppendUvarint(pbTag(b, 3, wireVarint), uint64(int64(x)))
	case int64:
		b = binary.AppendUvarint(pbTag(b, 3, wireVarint), uint64(x))
	case float64:
		b = binary.LittleEndian.AppendUint64(pbTag(b, 4, wireFixed64), math.Float64bits(x))
	case []any:
		var arr []byte
		for _, e := range x {
			arr = pbLen(arr, 1, pbAny(e))
		}
		b = pbLen(b, 5, arr)
	case []tKV:
		var kvl []byte
		for _, kv := range x {
			kvl = pbLen(kvl, 1, pbKV(kv))
		}
		b = pbLen(b, 6, kvl)
	case []byte:
		b = pbLen(b, 7, x)
	}
	return b
}

func pbKV(kv tKV) []byte { return pbLen(pbLen(nil, 1, []byte(kv.k)), 2, pbAny(kv.v)) }

func encodeProto(rs ...tRes) []byte {
	var req []byte
	for _, r := range rs {
		var res []byte
		for _, kv := range r.attrs {
			res = pbLen(res, 1, pbKV(kv))
		}
		var sl []byte
		sl = pbLen(sl, 1, pbLen(nil, 1, []byte(r.scope)))
		for _, rec := range r.recs {
			var lr []byte
			if rec.time > 0 {
				lr = binary.LittleEndian.AppendUint64(pbTag(lr, 1, wireFixed64), rec.time)
			}
			if rec.sev > 0 {
				lr = binary.AppendUvarint(pbTag(lr, 2, wireVarint), uint64(rec.sev))
			}
			if rec.sevText != "" {
				lr = pbLen(lr, 3, []byte(rec.sevText))
			}
			if rec.body != nil {
				lr = pbLen(lr, 5, pbAny(rec.body))
			}
			for _, kv := range rec.attrs {
				lr = pbLen(lr, 6, pbKV(kv))
			}
			// A field Signalith does not read (flags), which must be skipped.
			lr = binary.LittleEndian.AppendUint32(pbTag(lr, 8, wireFixed32), 1)
			if rec.trace != nil {
				lr = pbLen(lr, 9, rec.trace)
			}
			if rec.span != nil {
				lr = pbLen(lr, 10, rec.span)
			}
			if rec.observed > 0 {
				lr = binary.LittleEndian.AppendUint64(pbTag(lr, 11, wireFixed64), rec.observed)
			}
			if rec.eventName != "" {
				lr = pbLen(lr, 12, []byte(rec.eventName))
			}
			sl = pbLen(sl, 2, lr)
		}
		// scope_logs before resource, which decoders must accept.
		var rl []byte
		rl = pbLen(rl, 2, sl)
		rl = pbLen(rl, 1, res)
		req = pbLen(req, 1, rl)
	}
	return req
}

func jsonAny(v any) map[string]any {
	switch x := v.(type) {
	case string:
		return map[string]any{"stringValue": x}
	case bool:
		return map[string]any{"boolValue": x}
	case int:
		return map[string]any{"intValue": strconv.Itoa(x)}
	case int64:
		return map[string]any{"intValue": strconv.FormatInt(x, 10)}
	case float64:
		return map[string]any{"doubleValue": x}
	case []any:
		vals := []any{}
		for _, e := range x {
			vals = append(vals, jsonAny(e))
		}
		return map[string]any{"arrayValue": map[string]any{"values": vals}}
	case []tKV:
		return map[string]any{"kvlistValue": map[string]any{"values": jsonKVs(x)}}
	case []byte:
		return map[string]any{"bytesValue": base64.StdEncoding.EncodeToString(x)}
	}
	return map[string]any{}
}

func jsonKVs(kvs []tKV) []any {
	out := []any{}
	for _, kv := range kvs {
		out = append(out, map[string]any{"key": kv.k, "value": jsonAny(kv.v)})
	}
	return out
}

func encodeJSON(rs ...tRes) []byte {
	var rls []any
	for _, r := range rs {
		var recs []any
		for _, rec := range r.recs {
			m := map[string]any{"attributes": jsonKVs(rec.attrs)}
			if rec.time > 0 {
				m["timeUnixNano"] = strconv.FormatUint(rec.time, 10)
			}
			if rec.observed > 0 {
				m["observedTimeUnixNano"] = strconv.FormatUint(rec.observed, 10)
			}
			if rec.sev > 0 {
				m["severityNumber"] = rec.sev
			}
			if rec.sevText != "" {
				m["severityText"] = rec.sevText
			}
			if rec.body != nil {
				m["body"] = jsonAny(rec.body)
			}
			if rec.trace != nil {
				m["traceId"] = hex.EncodeToString(rec.trace)
			}
			if rec.span != nil {
				m["spanId"] = hex.EncodeToString(rec.span)
			}
			if rec.eventName != "" {
				m["eventName"] = rec.eventName
			}
			recs = append(recs, m)
		}
		rls = append(rls, map[string]any{
			"resource":  map[string]any{"attributes": jsonKVs(r.attrs)},
			"scopeLogs": []any{map[string]any{"scope": map[string]any{"name": r.scope}, "logRecords": recs}},
		})
	}
	b, _ := json.Marshal(map[string]any{"resourceLogs": rls})
	return b
}

// otlpDocs ingests the request in both encodings and returns the documents
// written for each, which must be the same.
func otlpDocs(t *testing.T, rs ...tRes) []map[string]any {
	t.Helper()
	var docs [2][]map[string]any
	for i, isJSON := range []bool{false, true} {
		body := encodeProto(rs...)
		if isJSON {
			body = encodeJSON(rs...)
		}
		b := &countingBulk{keep: true}
		p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
		res, err := p.IngestOTLP(context.Background(), body, isJSON)
		if err != nil {
			t.Fatalf("json=%v: %v", isJSON, err)
		}
		if res.Indexed != res.Received {
			t.Fatalf("json=%v: %+v", isJSON, res)
		}
		for _, d := range b.docs {
			doc := d.Doc
			doc["_index"] = d.Index
			docs[i] = append(docs[i], doc)
		}
	}
	a, _ := json.Marshal(docs[0])
	j, _ := json.Marshal(docs[1])
	if string(a) != string(j) {
		t.Errorf("protobuf and JSON differ:\n%s\n%s", a, j)
	}
	return docs[0]
}

var host = []tKV{{"host.name", "web1"}, {"service.name", "checkout"}, {"os.type", "linux"}}

func TestOTLPAppLog(t *testing.T) {
	ts := uint64(now.Add(-time.Minute).UnixNano())
	docs := otlpDocs(t, tRes{attrs: host, scope: "app.logger", recs: []tRec{{
		time: ts, sev: 17, body: "payment failed",
		attrs: []tKV{{"user.name", "ann"}, {"client.address", "203.0.113.9"}, {"http.route", "/pay"},
			{"retries", 3}, {"tags", []any{"a", "b"}}, {"ratio", 0.5}, {"ok", false}},
		trace: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		span:  []byte{0, 0, 0, 0, 0, 0, 0, 0}, // all zeros: not set
	}}})
	if len(docs) != 1 {
		t.Fatalf("docs = %v", docs)
	}
	expect(t, docs[0], map[string]any{
		"_index": "sig-other-2026.10.11", "datamodel": "Other", "sourcetype": "otel",
		"message": "payment failed", "host": "web1", "service": "checkout", "os_type": "linux",
		"severity": "ERROR", "severity_id": int64(17), "user": "ann", "src": "203.0.113.9",
		"http_route": "/pay", "retries": int64(3), "tags": `["a","b"]`, "ratio": 0.5, "ok": false,
		"trace_id": "0102030405060708090a0b0c0d0e0f10", "otel_scope": "app.logger",
		"@timestamp": now.Add(-time.Minute).Format(time.RFC3339Nano),
	})
	if _, ok := docs[0]["span_id"]; ok {
		t.Error("an all-zero span ID was kept")
	}
}

func TestOTLPMapBody(t *testing.T) {
	docs := otlpDocs(t, tRes{attrs: host, recs: []tRec{{
		observed: uint64(now.Add(-2 * time.Second).UnixNano()), sevText: "Warning",
		body: []tKV{{"msg", "disk almost full"}, {"disk", []tKV{{"free_pct", 3}}}, {"bin", []byte("hi")}},
	}}})
	expect(t, docs[0], map[string]any{
		"msg": "disk almost full", "disk": `{"free_pct":3}`, "bin": "aGk=", "severity": "Warning",
		"@timestamp": now.Add(-2 * time.Second).Format(time.RFC3339Nano),
	})
	if m, _ := docs[0]["message"].(string); !strings.Contains(m, `"disk almost full"`) {
		t.Errorf("message = %q", m)
	}
}

func TestOTLPFilelogAuthLine(t *testing.T) {
	docs := otlpDocs(t, tRes{attrs: host, recs: []tRec{{
		observed: uint64(now.UnixNano()),
		body:     "Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 50022 ssh2",
		attrs:    []tKV{{"log.file.name", "auth.log"}},
	}}})
	expect(t, docs[0], map[string]any{
		"datamodel": "Authentication", "_index": "sig-authentication-2026.10.11", "sourcetype": "linux:auth",
		"action": "failure", "user": "bob", "src": "192.0.2.4", "app": "sshd", "host": "web1", "service": "checkout",
	})
}

func TestOTLPSyslogReceiver(t *testing.T) {
	ts := uint64(now.Add(-time.Hour).UnixNano())
	docs := otlpDocs(t, tRes{recs: []tRec{{
		time: ts, sev: 9, sevText: "info",
		body: "<38>Oct 11 11:00:00 bastion sshd[42]: Accepted publickey for alice from 198.51.100.4 port 2222 ssh2",
		attrs: []tKV{{"appname", "sshd"}, {"hostname", "bastion"}, {"proc_id", "42"}, {"facility", 4},
			{"message", "Accepted publickey for alice from 198.51.100.4 port 2222 ssh2"}},
	}}})
	expect(t, docs[0], map[string]any{
		"datamodel": "Authentication", "action": "success", "user": "alice", "src": "198.51.100.4",
		"host": "bastion", "sourcetype": "syslog", "authentication_method": "publickey",
		"@timestamp": now.Add(-time.Hour).Format(time.RFC3339Nano),
	})
}

func TestOTLPJournald(t *testing.T) {
	docs := otlpDocs(t, tRes{recs: []tRec{{
		body: []tKV{{"MESSAGE", "Invalid user admin from 203.0.113.50 port 4242"}, {"SYSLOG_IDENTIFIER", "sshd"},
			{"_HOSTNAME", "db1"}, {"_PID", "99"}, {"__REALTIME_TIMESTAMP", strconv.FormatInt(now.Add(-time.Minute).UnixMicro(), 10)}},
	}}})
	expect(t, docs[0], map[string]any{
		"datamodel": "Authentication", "action": "failure", "user": "admin", "reason": "unknown user", "host": "db1",
		"@timestamp": now.Add(-time.Minute).Format(time.RFC3339Nano),
	})
}

// windowsBody is a record of the Collector's windowseventlog receiver.
func windowsBody(channel string, id int, data []tKV, array bool, message string) []tKV {
	var ed []tKV
	if array {
		var list []any
		for _, kv := range data {
			list = append(list, []tKV{kv})
		}
		ed = []tKV{{"data", list}}
	} else {
		ed = data
	}
	return []tKV{
		{"channel", channel}, {"computer", "DC01.corp.example"},
		{"event_id", []tKV{{"id", id}, {"qualifiers", 0}}},
		{"provider", []tKV{{"name", "Microsoft-Windows-Security-Auditing"}}},
		{"system_time", now.Add(-time.Minute).Format("2006-01-02T15:04:05.0000000Z")},
		{"message", message}, {"event_data", ed},
	}
}

func TestOTLPWindowsSecurity(t *testing.T) {
	// 4625 in schema order, as the event carries it.
	data := []tKV{{"SubjectUserSid", "S-1-0-0"}, {"SubjectUserName", "-"}, {"SubjectDomainName", "-"}, {"SubjectLogonId", "0x0"},
		{"TargetUserSid", "S-1-0-0"}, {"TargetUserName", "administrator"}, {"TargetDomainName", "CORP"}, {"Status", "0xc000006d"},
		{"FailureReason", "%%2313"}, {"SubStatus", "0xc000006a"}, {"LogonType", "3"}, {"LogonProcessName", "NtLmSsp"},
		{"AuthenticationPackageName", "NTLM"}, {"WorkstationName", "KALI"}, {"TransmittedServices", "-"}, {"LmPackageName", "-"},
		{"KeyLength", "0"}, {"ProcessId", "0x0"}, {"ProcessName", "-"}, {"IpAddress", "203.0.113.9"}, {"IpPort", "51234"}}
	// The map format: the order is lost, so it is shuffled here.
	shuffled := append([]tKV(nil), data...)
	for i := range shuffled {
		j := (i*7 + 3) % len(shuffled)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	for _, tc := range []struct {
		name  string
		data  []tKV
		array bool
	}{{"array", data, true}, {"map", shuffled, false}} {
		t.Run(tc.name, func(t *testing.T) {
			docs := otlpDocs(t, tRes{attrs: []tKV{{"host.name", "ignored"}}, recs: []tRec{{
				body: windowsBody("Security", 4625, tc.data, tc.array, "An account failed to log on."),
			}}})
			expect(t, docs[0], map[string]any{
				"datamodel": "Authentication", "action": "failure", "user": "administrator", "src": "203.0.113.9",
				"src_port": int64(51234), "logon_type": int64(3), "reason": "bad password", "host": "DC01.corp.example",
				"signature_id": "4625", "sourcetype": "WinEventLog:Security", "message": "An account failed to log on.",
				"@timestamp": now.Add(-time.Minute).Format(time.RFC3339Nano),
			})
		})
	}
}

func TestOTLPWindowsSysmon(t *testing.T) {
	data := []tKV{{"RuleName", "-"}, {"Image", `C:\Tools\nc.exe`}, {"User", `CORP\bob`}, {"Protocol", "tcp"},
		{"SourceIp", "10.0.0.5"}, {"SourcePort", "50000"}, {"DestinationIp", "198.51.100.7"}, {"DestinationPort", "4444"}}
	for _, array := range []bool{true, false} {
		// Without rendering, the receiver has no message.
		docs := otlpDocs(t, tRes{recs: []tRec{{body: windowsBody("Microsoft-Windows-Sysmon/Operational", 3, data, array, "")}}})
		expect(t, docs[0], map[string]any{
			"datamodel": "Network_Traffic", "src": "10.0.0.5", "dest": "198.51.100.7", "dest_port": int64(4444),
			"process_name": "nc.exe", "transport": "tcp", "vendor_product": "Microsoft Sysmon",
		})
		if m, _ := docs[0]["message"].(string); !strings.Contains(m, "nc.exe") {
			t.Errorf("message = %q", m)
		}
	}
}

// defenderThreatData is Defender's threat event (1116, 1117) data, by
// name in schema order, as the event XML carries it.
func defenderThreatData(action string) []tKV {
	return []tKV{{"Product Name", "Microsoft Defender Antivirus"}, {"Product Version", "4.18.24090.11"},
		{"Detection ID", "{8E3F7C2A-1B4D-4F6E-9A0B-3C5D7E9F1A2B}"}, {"Detection Time", "2026-10-13T09:14:02.481Z"},
		{"Unused", ""}, {"Unused2", ""}, {"Threat ID", "2147519003"}, {"Threat Name", "Virus:DOS/EICAR_Test_File"},
		{"Severity ID", "5"}, {"Severity Name", "Severe"}, {"Category ID", "42"}, {"Category Name", "Virus"},
		{"FWLink", "https://go.microsoft.com/fwlink/?linkid=37020&name=Virus:DOS/EICAR_Test_File&threatid=2147519003&enterprise=0"},
		{"Status Code", "1"}, {"Status Description", ""}, {"State", "1"}, {"Source ID", "3"}, {"Source Name", "Real-Time Protection"},
		{"Process Name", `C:\Windows\explorer.exe`}, {"Detection User", `CORP\alice`}, {"Unused3", ""},
		{"Path", `file:_C:\Users\alice\Downloads\eicar.com`}, {"Origin ID", "4"}, {"Origin Name", "Internet"},
		{"Execution ID", "0"}, {"Execution Name", "Unknown"}, {"Type ID", "0"}, {"Type Name", "Concrete"},
		{"Pre Execution Status", "0"}, {"Action ID", "2"}, {"Action Name", action}, {"Unused4", ""},
		{"Error Code", "0x00000000"}, {"Error Description", "The operation completed successfully. "}, {"Unused5", ""},
		{"Post Clean Status", "0"}, {"Additional Actions ID", "0"}, {"Additional Actions String", "No additional actions required"},
		{"Remediation User", ""}, {"Unused6", ""},
		{"Security intelligence Version", "AV: 1.419.236.0, AS: 1.419.236.0, NIS: 1.419.236.0"},
		{"Engine Version", "AM: 1.1.24090.11, NIS: 1.1.24090.11"}}
}

func TestOTLPWindowsDefender(t *testing.T) {
	// Without rendering, the receiver has no message: the named values
	// (map) or the inserts in order (array) are read instead.
	for _, array := range []bool{false, true} {
		docs := otlpDocs(t, tRes{recs: []tRec{{body: windowsBody(DefenderChannel, 1117, defenderThreatData("Quarantine"), array, "")}}})
		expect(t, docs[0], map[string]any{
			"datamodel": "Malware", "type": "threat", "action": "quarantined", "signature": "Virus:DOS/EICAR_Test_File",
			"threat_id": "2147519003", "vendor_severity": "Severe", "vendor_category": "Virus", "severity": "critical",
			"detection_source": "Real-Time Protection", "process_name": "explorer.exe", "user": `CORP\alice`,
			"file_path": `C:\Users\alice\Downloads\eicar.com`, "file_name": "eicar.com",
			"signature_version": "1.419.236.0", "engine_version": "1.1.24090.11", "vendor_action": "Quarantine",
			"vendor_product": DefenderProduct, "sourcetype": "WinEventLog:" + DefenderChannel, "signature_id": "1117",
			"host": "DC01.corp.example",
		})
		if array {
			continue
		}
		// An attack surface reduction block, and an exclusion added.
		asr := []tKV{{"Product Name", "Microsoft Defender Antivirus"}, {"Product Version", "4.18.24090.11"}, {"Unused", ""},
			{"ID", "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"}, {"Detection Time", "2026-10-13T09:14:02.481Z"}, {"User", `CORP\alice`},
			{"Path", `C:\Users\alice\AppData\Local\Temp\x.exe`}, {"Process Name", `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`},
			{"Target Commandline", `"C:\Users\alice\AppData\Local\Temp\x.exe"`}, {"Security intelligence Version", "1.419.236.0"},
			{"Engine Version", "1.1.24090.11"}}
		docs = otlpDocs(t, tRes{recs: []tRec{{body: windowsBody(DefenderChannel, 1121, asr, false, "")}}})
		expect(t, docs[0], map[string]any{
			"datamodel": "Malware", "type": "rule", "action": "blocked", "rule": "Office app started a child process",
			"rule_id": "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "user": `CORP\alice`, "process_name": "WINWORD.EXE",
			"file_name": "x.exe",
		})
		cfg := []tKV{{"Product Name", "Microsoft Defender Antivirus"}, {"Product Version", "4.18.24090.11"},
			{"Old Value", ""}, {"New Value", `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Temp = 0x0`}}
		docs = otlpDocs(t, tRes{recs: []tRec{{body: windowsBody(DefenderChannel, 5007, cfg, false, "")}}})
		expect(t, docs[0], map[string]any{
			"datamodel": "Malware", "type": "health", "action": "exclusion_added", "exclusion": `C:\Temp`, "exclusion_type": "path",
		})
	}
	// A rendered message wins over the named values.
	msg := "Microsoft Defender Antivirus has detected malware or other potentially unwanted software.\r\n Name: Trojan:Win32/Wacatac.B!ml\r\n Severity: Severe\r\n Path: file:_C:\\Temp\\a.exe"
	docs := otlpDocs(t, tRes{recs: []tRec{{body: windowsBody(DefenderChannel, 1116, defenderThreatData("Not Applicable"), false, msg)}}})
	expect(t, docs[0], map[string]any{
		"datamodel": "Malware", "action": "detected", "signature": "Trojan:Win32/Wacatac.B!ml", "file_path": `C:\Temp\a.exe`,
		"user": `CORP\alice`, "category": "trojan", "message": msg,
	})
}

// eventXML is the part of a Windows event's XML the Collector reads.
type eventXML struct {
	System struct {
		EventID  int    `xml:"EventID"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// TestOTLPDefenderSamples sends real Defender events (testdata/defender)
// as the Collector's windowseventlog receiver does, without a rendered
// message, in both event_data formats.
func TestOTLPDefenderSamples(t *testing.T) {
	for _, c := range []struct {
		id   string
		want map[string]any
	}{
		{"1116", map[string]any{"type": "threat", "action": "detected", "signature": "Virus:DOS/EICAR_Test_File", "severity": "critical",
			"user": `EC2AMAZ-FKEOM7G\Administrator`, "detection_source": "User", "signature_version": "1.457.160.0", "threat_id": "2147519003"}},
		{"1117", map[string]any{"type": "threat", "action": "quarantined", "signature": "Virus:DOS/EICAR_Test_File", "vendor_action": "Quarantine"}},
		{"1121", map[string]any{"type": "rule", "action": "blocked", "rule": "Office app created executable content",
			"user": `researchvmhaa\research`, "process_name": "WINWORD.EXE", "file_name": "script.vbs"}},
		{"5007", map[string]any{"type": "health", "action": "modified", "signature": "Antivirus setting changed",
			"old_value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\Controls\48 = 0x1`}},
	} {
		b, err := os.ReadFile(filepath.Join("testdata", "defender", c.id+".xml"))
		if err != nil {
			t.Fatal(err)
		}
		var e eventXML
		if err := xml.Unmarshal(b, &e); err != nil {
			t.Fatal(err)
		}
		var data []tKV
		for _, d := range e.Data {
			data = append(data, tKV{d.Name, d.Value})
		}
		for _, array := range []bool{false, true} {
			body := windowsBody(e.System.Channel, e.System.EventID, data, array, "")
			body[1] = tKV{"computer", e.System.Computer}
			docs := otlpDocs(t, tRes{recs: []tRec{{body: body}}})
			want := map[string]any{"datamodel": "Malware", "host": e.System.Computer, "signature_id": c.id, "vendor_product": DefenderProduct}
			maps.Copy(want, c.want)
			t.Run(fmt.Sprintf("%s/array=%v", c.id, array), func(t *testing.T) { expect(t, docs[0], want) })
		}
	}
}

func TestOTLPEmptyAndMultipleResources(t *testing.T) {
	p := &Pipeline{Store: &countingBulk{}, Now: func() time.Time { return now }}
	for _, body := range [][]byte{nil, []byte("{}"), encodeProto()} {
		for _, isJSON := range []bool{false, true} {
			if len(body) > 0 && body[0] == '{' && !isJSON {
				continue
			}
			res, err := p.IngestOTLP(context.Background(), body, isJSON)
			if err != nil || res.Received != 0 {
				t.Errorf("%q json=%v: %+v %v", body, isJSON, res, err)
			}
		}
	}
	docs := otlpDocs(t,
		tRes{attrs: []tKV{{"host.name", "a"}}, recs: []tRec{{body: "one"}, {body: "two"}}},
		tRes{attrs: []tKV{{"host.name", "b"}}, recs: []tRec{{body: "three"}}})
	var got []string
	for _, d := range docs {
		got = append(got, fmt.Sprint(d["host"], ":", d["message"]))
	}
	if strings.Join(got, ",") != "a:one,a:two,b:three" {
		t.Errorf("got %v", got)
	}
}

func TestOTLPRefusesBadRequests(t *testing.T) {
	deep := any("x")
	for range MaxDepth + 1 {
		deep = []any{deep}
	}
	big := strings.Repeat("x", MaxRecordBytes)
	cases := []struct {
		name   string
		body   []byte
		isJSON bool
		status int
	}{
		{"truncated protobuf", encodeProto(tRes{recs: []tRec{{body: "hello"}}})[:12], false, http.StatusBadRequest},
		{"group wire type", []byte{0x0b}, false, http.StatusBadRequest},
		{"too deep protobuf", encodeProto(tRes{recs: []tRec{{body: deep}}}), false, http.StatusBadRequest},
		{"too deep JSON", encodeJSON(tRes{recs: []tRec{{body: deep}}}), true, http.StatusBadRequest},
		{"record too large", encodeProto(tRes{recs: []tRec{{body: big}}}), false, http.StatusRequestEntityTooLarge},
		{"record too large JSON", encodeJSON(tRes{recs: []tRec{{body: big}}}), true, http.StatusRequestEntityTooLarge},
		{"not JSON", []byte("[1,2"), true, http.StatusBadRequest},
		{"wrong JSON types", []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"intValue":"x"}}]}]}]}`), true, http.StatusBadRequest},
		// The second record is bad: nothing at all is written.
		{"bad record after good", []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"ok"}},{"attributes":7}]}]}]}`), true, http.StatusBadRequest},
	}
	for _, tc := range cases {
		b := &countingBulk{}
		p := &Pipeline{Store: b, Now: func() time.Time { return now }}
		_, err := p.IngestOTLP(context.Background(), tc.body, tc.isJSON)
		var bad *BodyError
		if !errors.As(err, &bad) || bad.Status != tc.status {
			t.Errorf("%s: err = %v, want status %d", tc.name, err, tc.status)
		}
		if len(b.calls) != 0 || p.Stats().Received != 0 {
			t.Errorf("%s: wrote %v", tc.name, b.calls)
		}
	}
}

func TestOTLPBatchesLargeRequests(t *testing.T) {
	recs := make([]tRec, batchEvents+10)
	for i := range recs {
		recs[i] = tRec{body: "line " + strconv.Itoa(i)}
	}
	b := &countingBulk{}
	p := &Pipeline{Store: b, Now: func() time.Time { return now }}
	res, err := p.IngestOTLP(context.Background(), encodeProto(tRes{recs: recs}), false)
	if err != nil || res.Indexed != len(recs) {
		t.Fatalf("%+v %v", res, err)
	}
	if len(b.calls) != 2 || b.calls[0] != batchEvents {
		t.Errorf("bulk calls = %v", b.calls)
	}
}
