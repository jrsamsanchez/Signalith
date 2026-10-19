// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
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

func TestOTLPFilelogAccessLine(t *testing.T) {
	docs := otlpDocs(t, tRes{attrs: host, recs: []tRec{{
		observed: uint64(now.UnixNano()),
		body:     `203.0.113.7 - - [11/Oct/2026:11:58:01 +0000] "POST /wp-login.php HTTP/1.1" 200 512 "-" "curl/8.5"`,
		attrs:    []tKV{{"log.file.name", "access.log"}, {"log.file.path", "/var/log/nginx/access.log"}},
	}}})
	expect(t, docs[0], map[string]any{
		"datamodel": "Web", "sourcetype": "nginx:access", "src": "203.0.113.7", "http_method": "POST",
		"url": "/wp-login.php", "status": "200", "http_user_agent": "curl/8.5", "host": "web1",
		"@timestamp": "2026-10-11T11:58:01Z",
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
	cases := []struct {
		name   string
		body   []byte
		isJSON bool
		status int
	}{
		// Too deep in the resource, which every record shares.
		{"too deep resource", encodeProto(tRes{attrs: []tKV{{"k", deep}}, recs: []tRec{{body: "ok"}}}), false, http.StatusBadRequest},
		{"too deep resource JSON", encodeJSON(tRes{attrs: []tKV{{"k", deep}}, recs: []tRec{{body: "ok"}}}), true, http.StatusBadRequest},
		{"truncated protobuf", encodeProto(tRes{recs: []tRec{{body: "hello"}}})[:12], false, http.StatusBadRequest},
		{"group wire type", []byte{0x0b}, false, http.StatusBadRequest},

		{"not JSON", []byte("[1,2"), true, http.StatusBadRequest},
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

// A record that is too large, too deep or doesn't decode is rejected on its
// own; the rest of the request is written.
func TestOTLPRejectsBadRecordsAlone(t *testing.T) {
	deep := any("x")
	for range MaxDepth + 1 {
		deep = []any{deep}
	}
	big := strings.Repeat("x", MaxRecordBytes)
	good := tRec{body: "fine"}
	cases := []struct {
		name   string
		body   []byte
		isJSON bool
		reason string
	}{
		{"too deep protobuf", encodeProto(tRes{recs: []tRec{good, {body: deep}, good}}), false, "log record 2: a log record nests values more than 32 levels deep"},
		{"too deep JSON", encodeJSON(tRes{recs: []tRec{good, {body: deep}, good}}), true, "log record 2: a log record nests values more than 32 levels deep"},
		{"record too large", encodeProto(tRes{recs: []tRec{good, {body: big}, good}}), false, "log record 2 is "},
		{"record too large JSON", encodeJSON(tRes{recs: []tRec{good, {body: big}, good}}), true, "log record 2 is "},
		{"wrong JSON types", []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"ok"}},{"body":{"intValue":"x"}},{"body":{"stringValue":"ok"}}]}]}]}`), true, "log record 2: invalid intValue"},
		{"bad record after good", []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"ok"}},{"attributes":7},{"body":{"stringValue":"ok"}}]}]}]}`), true, "invalid log record 2"},
	}
	for _, tc := range cases {
		b := &countingBulk{keep: true}
		p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
		res, err := p.IngestOTLP(context.Background(), tc.body, tc.isJSON)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if res.Received != 3 || res.Indexed != 2 || res.Rejected != 1 || len(b.docs) != 2 {
			t.Errorf("%s: %+v, %d documents", tc.name, res, len(b.docs))
		}
		if len(res.Errors) != 1 || !strings.HasPrefix(res.Errors[0].Reason, tc.reason) {
			t.Errorf("%s: errors %+v, want %q", tc.name, res.Errors, tc.reason)
		}
		if st := p.Stats(); st.Received != 3 || st.Failed != 1 {
			t.Errorf("%s: stats %+v", tc.name, st)
		}
	}
}

// An Event Hub message split into more records than a batch holds is
// written in batches of the usual size.
func TestOTLPBatchesSplitMessages(t *testing.T) {
	recs := make([]string, batchEvents+10)
	for i := range recs {
		recs[i] = `{"time":"2026-10-11T11:58:01Z","category":"Administrative","operationName":"x","tenantId":"t"}`
	}
	msg := `{"records": [` + strings.Join(recs, ",") + `]}`
	b := &countingBulk{}
	p := &Pipeline{Store: b, Now: func() time.Time { return now }}
	res, err := p.IngestOTLP(context.Background(), encodeProto(tRes{recs: []tRec{{body: msg}}}), false)
	if err != nil || res.Received != len(recs) || res.Indexed != len(recs) {
		t.Fatalf("%+v %v", res, err)
	}
	if len(b.calls) != 2 || b.calls[0] != batchEvents {
		t.Errorf("bulk calls = %v", b.calls)
	}
}
