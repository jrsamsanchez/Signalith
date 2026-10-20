// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
)

// The intake fuzz targets send fuzzed bodies, with headers picked by a
// fuzzed byte, to the routes agents and senders use. Whatever arrives,
// the server must not panic, must answer a bad request with a 4xx (the
// fakes never fail, so a 5xx is a bug), and must label its answer.

// fuzzClient gives up on an answer that takes far longer than a small
// body ever should.
var fuzzClient = &http.Client{Timeout: 20 * time.Second}

// fuzzSend sends one request and returns the status, Content-Type and body.
func fuzzSend(t *testing.T, method, url string, body []byte, header map[string]string) (int, string, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	start := time.Now()
	resp, err := fuzzClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s with %d bytes: %v", method, url, len(body), err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("%s %s with %d bytes took %s", method, url, len(body), d)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), raw
}

// checkAnswer fails on a 5xx, or on an answer that is not the JSON
// object it says it is.
func checkAnswer(t *testing.T, status int, ct string, raw []byte, wantCT string) {
	t.Helper()
	if status >= 500 {
		t.Fatalf("status %d: %s", status, raw)
	}
	if ct != wantCT {
		t.Fatalf("status %d: Content-Type %q, want %q: %s", status, ct, wantCT, raw)
	}
	if wantCT == "application/json" {
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("status %d: not a JSON object: %q", status, raw)
		}
	}
}

// pick returns the choice mode selects.
func pick(mode byte, choices []string) string { return choices[int(mode)%len(choices)] }

const fuzzToken = "tok-0123456789abcdef"

func FuzzIngest(f *testing.F) {
	for _, s := range []string{
		`[{"msg":"a"},{"msg":"b"}]`,
		`{"log":"Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 50022 ssh2","host":"web1"}`,
		"{\"msg\":\"a\"}\n{\"msg\":\"b\"}\r\n",
		`[{"date":1760000000.5,"log":"x","nested":{"a":[1,2,{"b":null}]}}]`,
		`[]`, ``, `   `, `[1,"x",null]`, `{"a":`, `[{"a":1}`, "\xff\xfe", `{"@timestamp":"2026-10-11T09:15:02Z","message":"m"}`,
		strings.Repeat("[", 40) + strings.Repeat("]", 40),
	} {
		f.Add([]byte(s), byte(0))
	}
	ts, fos := newTestServer(f)
	f.Fuzz(func(t *testing.T, body []byte, mode byte) {
		defer func() { fos.bulk = nil }()
		status, ct, raw := fuzzSend(t, "POST", ts.URL+"/api/ingest", body, map[string]string{
			"Authorization":   "Bearer " + fuzzToken,
			"Content-Type":    pick(mode, []string{"", "application/json", "application/x-ndjson", "text/plain"}),
			"X-Signalith-Tag": pick(mode>>2, []string{"", "syslog", "linux.auth", "a\tb"}),
		})
		checkAnswer(t, status, ct, raw, "application/json")
	})
}

func FuzzOTLPLogs(f *testing.F) {
	js := `{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api"}}]},` +
		`"scopeLogs":[{"logRecords":[{"severityText":"ERROR","body":{"stringValue":"boom"},"attributes":[{"key":"n","value":{"intValue":"7"}}]}]}]}]}`
	for _, c := range []struct {
		body []byte
		mode byte
	}{
		{otlpProtoRequest("Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 50022 ssh2", "app started"), 0},
		{otlpProtoRequest("x"), 2},  // protobuf, gzipped here
		{[]byte(js), 1},             // JSON
		{[]byte(js), 3},             // JSON, gzipped here
		{[]byte{0x0a, 0x7f}, 0},     // bad protobuf
		{[]byte("{"), 1},            // bad JSON
		{[]byte("not gzip"), 4},     // says gzip, is not
		{otlpProtoRequest("x"), 12}, // text/plain
		{[]byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"kvlistValue":{"values":[{"key":"a","value":{"arrayValue":{"values":[{"bytesValue":"AAE="}]}}}]}}}]}]}]}`), 1},
	} {
		f.Add(c.body, c.mode)
	}
	ts, fos := newTestServer(f)
	types := []string{"application/x-protobuf", "application/json", "application/json; charset=utf-8", "text/plain", ""}
	f.Fuzz(func(t *testing.T, body []byte, mode byte) {
		defer func() { fos.bulk = nil }()
		ct := types[int(mode>>2)%len(types)]
		// The low bits: 0 plain, 1 Content-Encoding identity, 2 the body
		// gzipped, 3 gzip said but not done.
		enc := ""
		switch mode & 3 {
		case 1:
			enc = "identity"
		case 2:
			body, enc = gz(body), "gzip"
		case 3:
			enc = "GZIP"
		}
		status, got, raw := fuzzSend(t, "POST", ts.URL+"/api/otlp/v1/logs", body, map[string]string{
			"Authorization": "Bearer " + fuzzToken, "Content-Type": ct, "Content-Encoding": enc,
		})
		want := "application/x-protobuf"
		if strings.HasPrefix(ct, "application/json") {
			want = "application/json"
		}
		checkAnswer(t, status, got, raw, want)
	})
}

func FuzzLookupUpload(f *testing.F) {
	for _, s := range []string{
		"host,ip,cidr,owner,priority,category,bunit,location\nDC01.corp.local,10.0.0.10,,it-ops,critical,domain_controller|pci,IT,HQ\n",
		"identity,name,email,manager,priority,category,bunit,watchlist\nbob|CORP\\bob,Bob Smith,bob@corp.com,alice,high,admin,IT,true\n",
		"host,priority\nweb1,urgent\n", "hostname\nx\n", "identity\n\"open\n", "",
	} {
		f.Add([]byte(s), byte(0))
		f.Add([]byte(s), byte(1))
	}
	ts, _ := newTestServer(f)
	f.Fuzz(func(t *testing.T, body []byte, mode byte) {
		kind := pick(mode, []string{"assets", "identities"})
		req, err := http.NewRequest("PUT", ts.URL+"/api/lookups/"+kind, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("admin", "s3cret-pass")
		req.Header.Set("Content-Type", pick(mode>>1, []string{"text/csv", "", "application/octet-stream"}))
		resp, err := fuzzClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		checkAnswer(t, resp.StatusCode, resp.Header.Get("Content-Type"), raw, "application/json")
	})
}

// FuzzOsquery sends fuzzed bodies to osquery's routes, with KEY in the
// body standing for the node key of a host enrolled first, so requests
// get past the key check.
func FuzzOsquery(f *testing.F) {
	routes := []string{"enroll", "config", "log", "distributed/read", "distributed/write"}
	seeds := []struct {
		route int
		body  string
	}{
		{0, fmt.Sprintf(enrollBody, fuzzToken)},
		{0, `{"enroll_secret":"wrong"}`},
		{1, `{"node_key":"KEY"}`},
		{2, `{"node_key":"KEY","log_type":"result","data":[{"name":"signalith_software","unixTime":1760000000,` +
			`"diffResults":{"added":[{"name":"openssl","version":"3.0.2"}],"removed":[]}}]}`},
		{2, `{"node_key":"KEY","log_type":"status","data":["{\"severity\":\"2\",\"message\":\"boom\"}",{"severity":1}]}`},
		{2, `{"node_key":"KEY","log_type":"result","data":[{"name":"x","snapshot":[{"a":"b"}],"action":"snapshot"}]}`},
		{3, `{"node_key":"KEY"}`},
		{4, `{"node_key":"KEY","queries":{"q1":[{"a":"b"}]},"statuses":{"q1":0},"messages":{"q1":""}}`},
		{4, `{"node_key":"nope"}`},
		{2, `{`},
	}
	for _, s := range seeds {
		f.Add([]byte(s.body), byte(s.route))
		f.Add([]byte(s.body), byte(s.route)|8) // gzipped
	}
	st := endpoint.NewStore(endpoint.NewMemoryDocs(), "signalith")
	ts, fos := newTestServerWith(f, func(s *Server) { s.Endpoints = st })
	resp, err := http.Post(ts.URL+"/api/osquery/enroll", "application/json", strings.NewReader(fmt.Sprintf(enrollBody, fuzzToken)))
	if err != nil {
		f.Fatal(err)
	}
	var enrolled struct {
		Key string `json:"node_key"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&enrolled)
	resp.Body.Close()
	if enrolled.Key == "" {
		f.Fatal("no node key")
	}
	f.Fuzz(func(t *testing.T, body []byte, mode byte) {
		defer func() { fos.bulk = nil }()
		route := routes[int(mode&7)%len(routes)]
		body = bytes.ReplaceAll(body, []byte("KEY"), []byte(enrolled.Key))
		enc := ""
		if mode&8 != 0 {
			body, enc = gz(body), "gzip"
		}
		status, ct, raw := fuzzSend(t, "POST", ts.URL+"/api/osquery/"+route, body, map[string]string{
			"Content-Type": "application/json", "Content-Encoding": enc,
		})
		checkAnswer(t, status, ct, raw, "application/json")
	})
}
