// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

const gcpEntryText = `{"logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity", "resource": {"type": "project"},
	"timestamp": "2026-10-11T11:00:00Z", "protoPayload": {"methodName": "SetIamPolicy"}}`

func TestGCPEntryForms(t *testing.T) {
	if GCPEntry(decode(t, gcpEntryText)) == nil {
		t.Error("a LogEntry itself")
	}
	if GCPEntry(map[string]any{"data": decode(t, gcpEntryText)}) == nil {
		t.Error("Splunk's add-on's data")
	}
	std := base64.StdEncoding.EncodeToString([]byte(gcpEntryText))
	if GCPEntry(map[string]any{"message": map[string]any{"data": std}}) == nil {
		t.Error("a Pub/Sub message")
	}
	// URL-safe base64, of text whose encoding has / in standard base64.
	withSlash := `{"logName": "projects/p/logs/x", "resource": {"type": "project"}, "q": "?????????"}`
	url := base64.URLEncoding.EncodeToString([]byte(withSlash))
	if _, err := base64.StdEncoding.DecodeString(url); err == nil {
		t.Fatal("the URL-safe text is also standard base64")
	}
	if got := GCPEntry(map[string]any{"message": map[string]any{"data": url}}); got == nil || got["q"] != "?????????" {
		t.Errorf("URL-safe base64 = %v", got)
	}
	for name, r := range map[string]map[string]any{
		"no message":  {"other": 1},
		"no data":     {"message": map[string]any{}},
		"not base64":  {"message": map[string]any{"data": "!!!"}},
		"not a entry": {"message": map[string]any{"data": base64.StdEncoding.EncodeToString([]byte(`{"x": 1}`))}},
	} {
		if got := GCPEntry(r); got != nil {
			t.Errorf("%s: %v", name, got)
		}
	}
	if gcpFromOTLP(gcpEntryText) == nil || gcpFromOTLP(decode(t, gcpEntryText)) == nil {
		t.Error("gcpFromOTLP missed an entry")
	}
	if gcpFromOTLP("plain") != nil || gcpFromOTLP(map[string]any{"x": 1}) != nil || gcpFromOTLP(3) != nil {
		t.Error("gcpFromOTLP took what is not an entry")
	}
}

func TestGCPFieldsAndRecords(t *testing.T) {
	for _, c := range []struct {
		name string
		want bool
	}{
		{"logName", true}, {"protoPayload.methodName", true}, {"resource.labels.project_id", true},
		{"protoPayload.request.metadata.labels.x", false}, {"other.x", false},
	} {
		if got := GCPField(c.name); got != c.want {
			t.Errorf("GCPField(%q) = %v, want %v", c.name, got, c.want)
		}
	}
	if f, ok := GCPSigmaField("data.protoPayload.methodName"); !ok || f != "protoPayload.methodName" {
		t.Errorf("GCPSigmaField(data.protoPayload.methodName) = %q %v", f, ok)
	}
	if _, ok := GCPSigmaField("nope"); ok {
		t.Error("GCPSigmaField(nope)")
	}

	r := GCPRecord("h1", now, map[string]string{
		"protoPayload.status.code":                    "7",
		"protoPayload.authorizationInfo{}.permission": "iam.roles.create",
		"protoPayload.authorizationInfo{}.granted":    "true",
		"nope": "skipped",
	})
	p := r["protoPayload"].(map[string]any)
	if p["status"].(map[string]any)["code"] != json.Number("7") {
		t.Errorf("status = %#v", p["status"])
	}
	ai := p["authorizationInfo"].([]any)[0].(map[string]any)
	if ai["permission"] != "iam.roles.create" || ai["granted"] != true {
		t.Errorf("authorizationInfo = %#v", ai)
	}
	r = GCPRecord("h1", now, map[string]string{"protoPayload.status.code": "denied"})
	if r["protoPayload"].(map[string]any)["status"].(map[string]any)["code"] != "denied" {
		t.Errorf("text code = %#v", r["protoPayload"])
	}

	m := map[string]any{}
	gcpPut(m, "a{}.b", 1)
	gcpPut(m, "a{}.c", 2)
	gcpPut(m, "x.list{}", "v1")
	gcpPut(m, "x.list{}", "v2")
	if a := m["a"].([]any); len(a) != 1 || !reflect.DeepEqual(a[0], map[string]any{"b": 1, "c": 2}) {
		t.Errorf("a = %#v", m["a"])
	}
	if l := m["x"].(map[string]any)["list"]; !reflect.DeepEqual(l, []any{"v1", "v2"}) {
		t.Errorf("x.list = %#v", l)
	}
	m = map[string]any{"a": []any{"not an object"}}
	gcpPut(m, "a{}.b", 1)
	if a := m["a"].([]any); !reflect.DeepEqual(a[0], map[string]any{"b": 1}) {
		t.Errorf("a over a string = %#v", m["a"])
	}
}

func TestZeekGenericFieldNames(t *testing.T) {
	for _, c := range []struct{ lt, key, want string }{
		{"ssh", "id.orig_h", "src"}, {"ssh", "id.orig_p", "src_port"}, {"ssh", "id.resp_h", "dest"},
		{"ssh", "id.resp_p", "dest_port"}, {"ssh", "uid", "session_id"}, {"ssh", "community_id", "community_id"},
		{"ssh", "ts", ""}, {"ntlm", "hostname", "zeek_hostname"}, {"ssh", "hostname", ""},
		{"ssh", "auth.success", "zeek_auth_success"}, {"ssh", "!!", ""}, {"conn", "proto", ""},
	} {
		if got := ZeekGenericField(c.lt, c.key); got != c.want {
			t.Errorf("ZeekGenericField(%s, %s) = %q, want %q", c.lt, c.key, got, c.want)
		}
	}
	long := ""
	for i := 0; i < 80; i++ {
		long += "a"
	}
	if got := cleanFieldPart(long); len(got) != 60 {
		t.Errorf("cleanFieldPart kept %d bytes", len(got))
	}
}

func TestZeekGenericValues(t *testing.T) {
	f := map[string]any{}
	zeekGeneric("ssh", map[string]any{
		"auth.success": true, "rtt": 0.5, "count": 3.0, "nothing": nil, "!!": "x",
		"a.b": "first", "a_b": "second", "ts": "skip",
	}, f)
	if f["zeek_auth_success"] != "true" || f["zeek_rtt"] == nil || f["zeek_count"] == nil {
		t.Errorf("fields = %v", f)
	}
	if _, ok := f["zeek_nothing"]; ok {
		t.Error("a null was kept")
	}
	if f["zeek_a_b"] != "first" {
		t.Errorf("zeek_a_b = %v, want the first key's", f["zeek_a_b"])
	}
	if f["signature"] != "Zeek ssh" {
		t.Errorf("signature = %v", f["signature"])
	}
}

func TestZeekRecordsAndHosts(t *testing.T) {
	if IsZeekRecord(map[string]any{"ts": 1.0}) {
		t.Error("ts alone is a Zeek record")
	}
	// The line's own file name is kept, from the record around it.
	ev := parseZeekRecord("zeek", map[string]any{"log": `{"ts": 1760180400.0, "uid": "C1", "_path": "ssh", "id.orig_h": "192.0.2.1"}`, "file": "/opt/zeek/ssh.log"})
	if ev.Fields["src"] != "192.0.2.1" {
		t.Errorf("ssh line = %v", ev.Fields)
	}
	ev = ParseZeek("", map[string]any{"ts": 1760180400.0, "uid": "C1"}, "")
	if ev.Fields["signature"] != "Zeek unknown" {
		t.Errorf("no log type = %v", ev.Fields)
	}
	for in, want := range map[string]string{"[2001:db8::1]:8080": "2001:db8::1", "example.com:8080": "example.com",
		"example.com": "example.com", "2001:db8::1": "2001:db8::1", "[bad": "[bad"} {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
	f := map[string]any{}
	zeekHTTP(map[string]any{"host": "example.com:8080", "uri": "/x", "id.resp_p": json.Number("8080")}, f)
	if f["url"] != "http://example.com:8080/x" {
		t.Errorf("url = %v", f["url"])
	}
}

func TestSuricataRecordForms(t *testing.T) {
	ev := parseSuricataRecord(map[string]any{"message": "not eve"})
	if ev.Fields["sourcetype"] != "suricata:unknown" {
		t.Errorf("not EVE = %v", ev.Fields)
	}
	ev = ParseSuricataEVE(map[string]any{"event_type": "!!", "timestamp": "2026-10-11T11:00:00Z"}, "")
	if ev.Fields["sourcetype"] != "suricata:unknown" {
		t.Errorf("odd event type = %v", ev.Fields["sourcetype"])
	}
	f := map[string]any{}
	eveFlow(map[string]any{"netflow": map[string]any{"bytes_toserver": json.Number("10")}}, f)
	if f["bytes_out"] != int64(10) {
		t.Errorf("netflow bytes_out = %#v", f["bytes_out"])
	}
	f = map[string]any{}
	eveDNS(map[string]any{"dns": map[string]any{"type": "answer", "rrname": "example.com",
		"grouped": map[string]any{"A": []any{"192.0.2.2", "192.0.2.1"}}}}, f)
	if got := f["answer"]; !reflect.DeepEqual(got, []string{"192.0.2.2", "192.0.2.1"}) {
		t.Errorf("grouped answers = %#v", got)
	}
	if got := sortedKeys(map[string]any{"b": 1, "a": 2}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("sortedKeys = %v", got)
	}
}

func TestSuricataPortsAndTimes(t *testing.T) {
	for _, c := range []struct {
		r    map[string]any
		want any
	}{
		{map[string]any{"http": map[string]any{"http_port": json.Number("8080")}}, json.Number("8080")},
		{map[string]any{"src_port": json.Number("80"), "dest_port": json.Number("51000")}, int64(80)},
		{map[string]any{"src_port": json.Number("51000"), "dest_port": json.Number("80")}, json.Number("80")},
	} {
		if got := fileServerPort(c.r); got != c.want {
			t.Errorf("fileServerPort(%v) = %#v, want %#v", c.r, got, c.want)
		}
	}
	if got := fileServerPort(map[string]any{"direction": "to_client", "src_port": json.Number("80"), "dest_port": json.Number("51000")}); got == nil {
		t.Error("fileServerPort with a direction = nil")
	}
	if ts, ok := certTime("2026-01-01T00:00:00+02:00"); !ok || !ts.Equal(time.Date(2025, 12, 31, 22, 0, 0, 0, time.UTC)) {
		t.Errorf("certTime(RFC 3339) = %v %v", ts, ok)
	}
	if _, ok := certTime("yesterday"); ok {
		t.Error("certTime(yesterday)")
	}
	f := map[string]any{}
	eveTLS(map[string]any{"tls": map[string]any{"ja4": map[string]any{"hash": "t13d"}}}, f)
	if f["ja4"] != "t13d" {
		t.Errorf("ja4 = %v", f["ja4"])
	}
}
