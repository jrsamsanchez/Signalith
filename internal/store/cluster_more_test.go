// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

// routes answers each path (without query) with a fixed status and body;
// unknown paths get 404.
func routes(t *testing.T, m map[string]string) (*Client, *[]string) {
	t.Helper()
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		key := r.Method + " " + r.URL.Path
		body, ok := m[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":{"type":"index_not_found_exception","reason":"no such index"},"status":404}`)
			return
		}
		if strings.HasPrefix(body, "!") {
			w.WriteHeader(http.StatusInternalServerError)
			body = body[1:]
		}
		io.WriteString(w, body)
	}))
	t.Cleanup(ts.Close)
	return New(Config{URL: ts.URL}), &seen
}

func TestShardRoom(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name        string
		settings    string
		used, limit int
	}{
		{"default", `{}`, 7, 3000},
		{"persistent", `{"persistent":{"cluster.max_shards_per_node":"500"}}`, 7, 1500},
		{"transient wins", `{"transient":{"cluster.max_shards_per_node":200},"defaults":{"cluster.max_shards_per_node":"1000"}}`, 7, 600},
		{"bad value ignored", `{"persistent":{"cluster.max_shards_per_node":"lots"},"defaults":{"cluster.max_shards_per_node":"900"}}`, 7, 2700},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl, _ := routes(t, map[string]string{
				"GET /_cluster/health":   `{"number_of_data_nodes":3,"active_shards":5,"unassigned_shards":2}`,
				"GET /_cluster/settings": c.settings,
			})
			used, limit, err := cl.ShardRoom(ctx)
			if err != nil || used != c.used || limit != c.limit {
				t.Fatalf("got %d/%d %v, want %d/%d", used, limit, err, c.used, c.limit)
			}
		})
	}
	// No data nodes counts as one.
	cl, _ := routes(t, map[string]string{
		"GET /_cluster/health":   `{"number_of_data_nodes":0,"active_shards":1}`,
		"GET /_cluster/settings": `{}`,
	})
	if _, limit, err := cl.ShardRoom(ctx); err != nil || limit != 1000 {
		t.Fatalf("zero nodes: %d %v", limit, err)
	}
	cl, _ = routes(t, map[string]string{"GET /_cluster/health": `!{"error":"boom"}`})
	if _, _, err := cl.ShardRoom(ctx); err == nil {
		t.Fatal("health error not returned")
	}
	cl, _ = routes(t, map[string]string{"GET /_cluster/health": `{"number_of_data_nodes":1}`, "GET /_cluster/settings": `!{"error":"boom"}`})
	if _, _, err := cl.ShardRoom(ctx); err == nil {
		t.Fatal("settings error not returned")
	}
}

func TestDataNodesAndSearchThreads(t *testing.T) {
	ctx := context.Background()
	cl, seen := routes(t, map[string]string{
		"GET /_cluster/health":                 `{"number_of_data_nodes":4}`,
		"GET /_nodes/data:true/thread_pool":    `{"nodes":{"a":{"thread_pool":{"search":{"size":13}}},"b":{"thread_pool":{"search":{"size":7}}}}}`,
		"GET /_cat/indices/signalith-events-*": `[{"index":"signalith-events-2"},{"index":"signalith-events-1"}]`,
	})
	if n, err := cl.DataNodes(ctx); err != nil || n != 4 {
		t.Fatalf("data nodes %d %v", n, err)
	}
	if n, err := cl.SearchThreads(ctx); err != nil || n != 20 {
		t.Fatalf("search threads %d %v", n, err)
	}
	names, err := cl.ListIndices(ctx, "signalith-events-*")
	if err != nil || !slices.Equal(names, []string{"signalith-events-2", "signalith-events-1"}) {
		t.Fatalf("list %v %v", names, err)
	}
	if _, err := cl.ListIndices(ctx, "missing-*"); err == nil {
		t.Fatal("list error not returned")
	}
	if !slices.ContainsFunc(*seen, func(s string) bool { return strings.Contains(s, "expand_wildcards=open") }) {
		t.Errorf("list asked %v", *seen)
	}
	empty, _ := routes(t, nil)
	if n, err := empty.SearchThreads(ctx); err == nil || n != 0 {
		t.Fatalf("search threads error: %d %v", n, err)
	}
}

func TestDeleteIndexAndMapping(t *testing.T) {
	ctx := context.Background()
	cl, seen := routes(t, map[string]string{
		"DELETE /old-index": `{"acknowledged":true}`,
		"GET /ev-*/_mapping": `{
			"ev-1":{"mappings":{"properties":{"host":{"properties":{"name":{"type":"keyword"},"ip":{"type":"ip"}}},"@timestamp":{"type":"date"},"odd":"x"}}},
			"ev-2":{"mappings":{"properties":{"message":{"type":"text"},"geo":{"type":"object"}}}}}`,
	})
	if err := cl.DeleteIndex(ctx, "old-index"); err != nil {
		t.Fatal(err)
	}
	if err := cl.DeleteIndex(ctx, "nope"); err == nil {
		t.Fatal("delete of a missing index succeeded")
	}
	if (*seen)[0] != "DELETE /old-index" {
		t.Errorf("sent %v", *seen)
	}
	fields, err := cl.Mapping(ctx, "ev-*")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"host.name": "keyword", "host.ip": "ip", "@timestamp": "date", "message": "text", "geo": "object"}
	if len(fields) != len(want) {
		t.Fatalf("fields %v", fields)
	}
	for k, v := range want {
		if fields[k] != v {
			t.Errorf("%s = %q, want %q", k, fields[k], v)
		}
	}
	if _, err := cl.Mapping(ctx, "missing"); err == nil {
		t.Fatal("mapping error not returned")
	}
}

func TestClientBulkEncodesActions(t *testing.T) {
	ctx := context.Background()
	var body string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		io.WriteString(w, `{"errors":true,"items":[{"create":{"_index":"a","status":201}},{"index":{"_index":"b","status":400,"error":{"type":"mapper_parsing_exception","reason":"bad field"}}}]}`)
	}))
	defer ts.Close()
	cl := New(Config{URL: ts.URL})
	if errs, err := cl.Bulk(ctx, nil); errs != nil || err != nil {
		t.Fatalf("empty bulk: %v %v", errs, err)
	}
	errs, err := cl.Bulk(ctx, []IndexedDoc{
		{Index: "a", Doc: map[string]any{"x": 1}},
		{Index: "b", ID: "id1", Replace: true, Doc: map[string]any{"y": 2}},
	})
	if err != nil || len(errs) != 1 || errs[0].Pos != 1 || errs[0].Type != "mapper_parsing_exception" || errs[0].Status != 400 || errs[0].Index != "b" {
		t.Fatalf("errs %+v %v", errs, err)
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 4 || lines[0] != `{"create":{"_index":"a"}}` || lines[2] != `{"index":{"_id":"id1","_index":"b"}}` {
		t.Fatalf("body %q", body)
	}
	// A document that can't be encoded is refused before anything is sent.
	if _, err := cl.Bulk(ctx, []IndexedDoc{{Index: "a", Doc: map[string]any{"bad": math.NaN()}}}); err == nil {
		t.Fatal("NaN encoded")
	}
	g := NewBulkGroup(cl, 0)
	if _, err := g.Bulk(ctx, []IndexedDoc{{Index: "a", Doc: map[string]any{"bad": math.Inf(1)}}}); err == nil {
		t.Fatal("bulk group encoded Inf")
	}
	// The server's error for position 1 is not this caller's document.
	if errs, err := g.Bulk(ctx, []IndexedDoc{{Index: "a", Doc: map[string]any{"x": 1}}}); err != nil || len(errs) != 0 {
		t.Fatalf("bulk group: %v %v", errs, err)
	}
}

func TestErrorMessage(t *testing.T) {
	for _, c := range []struct {
		e    Error
		want string
	}{
		{Error{Status: 400, Body: `{"error":{"type":"t","reason":"r","root_cause":[{"reason":"deeper"}]}}`}, "opensearch returned 400: t: r (deeper)"},
		{Error{Status: 400, Body: `{"error":{"type":"t","reason":"r","root_cause":[{"reason":"r"}]}}`}, "opensearch returned 400: t: r"},
		{Error{Status: 502, Body: "plain"}, "opensearch returned 502: plain"},
		{Error{Status: 500, Body: strings.Repeat("x", 600)}, "opensearch returned 500: " + strings.Repeat("x", 500) + "..."},
	} {
		if got := c.e.Error(); got != c.want {
			t.Errorf("got %q want %q", got, c.want)
		}
	}
}

func TestVersionStringAndRecheckLimit(t *testing.T) {
	if s := (Version{SeqNo: 4, PrimaryTerm: 2}).String(); s != "4.2" {
		t.Errorf("String %q", s)
	}
	until := time.Now().Add(time.Minute)
	ctx := WithRecheckLimit(context.Background(), until)
	if got, ok := ctx.Value(recheckKey{}).(time.Time); !ok || !got.Equal(until) {
		t.Errorf("limit %v", got)
	}
	if !strings.HasPrefix(NewWriteID(), "w_") || len(NewWriteID()) != 26 {
		t.Error("write id")
	}
	if refreshQuery("?", true) != "?refresh=wait_for" || refreshQuery("&", false) != "" {
		t.Error("refreshQuery")
	}
}

func TestDocWritesRefuseConfigAndBadBodies(t *testing.T) {
	c, _ := newDocsClient(t)
	ctx := context.Background()
	if _, err := c.UpdateIf(ctx, "s_config", "x", map[string]any{"a": 1}, Version{PrimaryTerm: 1}, false); err == nil {
		t.Error("partial update of config allowed")
	}
	if _, err := c.Update(ctx, "s_config", "x", map[string]any{"a": 1}, false); err == nil {
		t.Error("update of config allowed")
	}
	if _, err := c.UpdateIf(ctx, "s_runtime", "x", map[string]any{"a": math.NaN()}, Version{PrimaryTerm: 1}, false); err == nil {
		t.Error("NaN update")
	}
	if _, err := c.Update(ctx, "s_runtime", "x", map[string]any{"a": math.NaN()}, false); err == nil {
		t.Error("NaN update")
	}
	if _, err := c.PutIf(ctx, "s_runtime", "x", "string", Version{PrimaryTerm: 1}, false); err == nil {
		t.Error("non-object put")
	}
	if _, err := c.Update(ctx, "s_runtime", "missing", map[string]any{"a": 1}, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("update of a missing doc: %v", err)
	}
}

func TestDocWritesWithServerErrors(t *testing.T) {
	c, os := newDocsClient(t)
	ctx := context.Background()
	v, err := c.Create(ctx, "s_runtime", "d", map[string]any{"a": 1}, true)
	if err != nil {
		t.Fatal(err)
	}
	// A plain refusal, not about versions, is returned as it is.
	os.SetFault(func(m, p string) *ostest.Fault {
		if m != "GET" {
			return &ostest.Fault{Status: 400, Type: "illegal_argument_exception"}
		}
		return nil
	})
	if _, err := c.Create(ctx, "s_runtime", "e", map[string]any{"a": 1}, false); err == nil || errors.Is(err, ErrExists) {
		t.Errorf("create: %v", err)
	}
	if err := c.DeleteIf(ctx, "s_runtime", "d", v, false); err == nil || errors.Is(err, ErrConflict) {
		t.Errorf("delete: %v", err)
	}
	// A lost delete answer where the document is still at v keeps the
	// original error; one where the reread fails too keeps it as well.
	os.SetFault(func(m, p string) *ostest.Fault {
		if m == "DELETE" {
			return &ostest.Fault{Status: 503, Type: "unavailable"}
		}
		return nil
	})
	if err := c.DeleteIf(ctx, "s_runtime", "d", v, false); err == nil || errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
		t.Errorf("lost delete at the same version: %v", err)
	}
	os.SetFault(func(m, p string) *ostest.Fault { return &ostest.Fault{Status: 503, Type: "unavailable"} })
	if err := c.DeleteIf(ctx, "s_runtime", "d", v, false); err == nil || errors.Is(err, ErrConflict) {
		t.Errorf("delete, reread failing: %v", err)
	}
	if _, err := c.Create(ctx, "s_runtime", "f", map[string]any{"a": 1}, false); err == nil {
		t.Errorf("create, reread failing: %v", err)
	}
	if _, err := c.PutIf(ctx, "s_runtime", "d", map[string]any{"a": 2}, v, false); err == nil || errors.Is(err, ErrConflict) {
		t.Errorf("put, reread failing: %v", err)
	}
	if _, _, _, err := c.Get(ctx, "s_runtime", "d"); err == nil {
		t.Error("get error not returned")
	}
	// A lost delete answer where someone else changed the document is a
	// conflict.
	os.SetFault(nil)
	os.Put("s_runtime", "d", map[string]any{"a": 9})
	os.SetFault(func(m, p string) *ostest.Fault {
		if m == "DELETE" {
			return &ostest.Fault{Drop: true}
		}
		return nil
	})
	if err := c.DeleteIf(ctx, "s_runtime", "d", v, false); !errors.Is(err, ErrConflict) {
		t.Errorf("lost delete after another write: %v", err)
	}
	// A lost create whose document someone else wrote is ErrExists; a lost
	// put on a document deleted meanwhile is a conflict.
	os.SetFault(func(m, p string) *ostest.Fault {
		if m == "PUT" {
			return &ostest.Fault{Drop: true}
		}
		return nil
	})
	if _, err := c.Create(ctx, "s_runtime", "d", map[string]any{"a": 1}, false); !errors.Is(err, ErrExists) {
		t.Errorf("lost create over another: %v", err)
	}
	if _, err := c.PutIf(ctx, "s_runtime", "gone", map[string]any{"a": 1}, v, false); !errors.Is(err, ErrConflict) {
		t.Errorf("lost put on a missing doc: %v", err)
	}
}

func TestReplicate(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name     string
		settings string
		replicas map[string]any
		put      bool
		wantErr  bool
	}{
		{"fixed zero gets auto", `{"i":{"settings":{"index":{"number_of_replicas":"0"}}}}`, nil, true, false},
		{"auto expand left alone", `{"i":{"settings":{"index":{"number_of_replicas":"0","auto_expand_replicas":"0-1"}}}}`, nil, false, false},
		{"auto false changes", `{"i":{"settings":{"index":{"number_of_replicas":"0","auto_expand_replicas":"false"}}}}`, map[string]any{"number_of_replicas": 2}, true, false},
		{"set replicas left alone", `{"i":{"settings":{"index":{"number_of_replicas":"2"}}}}`, nil, false, false},
		{"no copies wanted", `{"i":{"settings":{"index":{"number_of_replicas":"0"}}}}`, map[string]any{"number_of_replicas": 0}, false, false},
		{"empty answer", `{}`, nil, false, false},
		{"settings error", `!{"error":"boom"}`, nil, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := map[string]string{"GET /i/_settings": c.settings, "PUT /i/_settings": `{"acknowledged":true}`}
			cl, seen := routes(t, m)
			err := Replicate(ctx, cl, "i", c.replicas)
			if (err != nil) != c.wantErr {
				t.Fatalf("err %v", err)
			}
			put := slices.ContainsFunc(*seen, func(s string) bool { return strings.HasPrefix(s, "PUT") })
			if put != c.put {
				t.Fatalf("put %v, sent %v", put, *seen)
			}
		})
	}
	// The index vanishing between the read and the write is fine.
	cl, _ := routes(t, map[string]string{"GET /i/_settings": `{"i":{"settings":{"index":{"number_of_replicas":"0"}}}}`})
	if err := Replicate(ctx, cl, "i", nil); err != nil {
		t.Fatalf("missing on write: %v", err)
	}
	s := SmallIndexSettings(map[string]any{"number_of_replicas": 1})
	if s["number_of_shards"] != 1 || s["number_of_replicas"] != 1 || s["auto_expand_replicas"] != nil {
		t.Errorf("settings %v", s)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestExplainCheck(t *testing.T) {
	jsonBody := func(typ, reason string) string {
		b, _ := json.Marshal(map[string]any{"error": map[string]any{"type": typ, "reason": reason}})
		return string(b)
	}
	for _, c := range []struct {
		name    string
		cfg     Config
		err     error
		reached bool
		problem string
		message string
	}{
		{"forbidden", Config{URL: "https://os:9200"}, &Error{Status: 403, Body: "no"}, true, "forbidden", "cluster_monitor"},
		{"bad request", Config{URL: "http://os:9200"}, &Error{Status: 400, Body: jsonBody("x", "bad")}, true, "error", "answered with an error: 400: x: bad"},
		{"other status", Config{URL: "http://os:9200"}, &Error{Status: 418, Body: "teapot"}, true, "error", "418: teapot"},
		{"hostname", Config{URL: "https://os:9200"}, &url.Error{Op: "Get", URL: "https://os:9200", Err: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "os"}}, true, "tls", "is for another name"},
		{"expired", Config{URL: "https://os:9200"}, x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired}, true, "tls", "it has expired or is not valid yet"},
		{"other invalid", Config{URL: "https://os:9200"}, x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.NotAuthorizedToSign, Detail: "d"}, true, "tls", "not authorized to sign"},
		{"dns", Config{URL: "https://nohost.invalid:9200"}, &net.DNSError{Name: "nohost.invalid", Err: "no such host"}, false, "unreachable", "The name nohost.invalid could not be found"},
		{"net timeout", Config{URL: "http://os:9200"}, &url.Error{Op: "Get", URL: "x", Err: timeoutErr{}}, false, "unreachable", "No answer from os:9200 within 10 seconds"},
		{"deadline", Config{URL: "http://os:9200"}, context.DeadlineExceeded, false, "unreachable", "No answer from"},
		{"reset on http", Config{URL: "http://os:9200"}, &url.Error{Op: "Get", URL: "x", Err: syscall.ECONNRESET}, true, "http", "closed the connection"},
		{"eof on http", Config{URL: "http://os:9200"}, fmt.Errorf("read: %w", io.EOF), true, "http", "closed the connection"},
		{"eof on https", Config{URL: "https://os:9200"}, &url.Error{Op: "Get", URL: "x", Err: io.EOF}, false, "unreachable", "Could not connect to os:9200: EOF."},
		{"other", Config{URL: "http://os:9200"}, errors.New("weird"), false, "unreachable", "Could not connect to os:9200: weird."},
		{"refused windows", Config{URL: "http://os:9200"}, &url.Error{Op: "Get", URL: "x", Err: syscall.Errno(10061)}, false, "unreachable", "Nothing answered at os:9200"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var rep Report
			explainCheck(&rep, c.cfg, c.err)
			if rep.Reached != c.reached || rep.Problem != c.problem || !strings.Contains(rep.Message, c.message) {
				t.Errorf("%+v", rep)
			}
		})
	}
	if got := certReason(errors.New("tls: x509: certificate signed by nobody")); got != "certificate signed by nobody" {
		t.Errorf("certReason %q", got)
	}
	if got := certReason(errors.New("plain")); got != "plain" {
		t.Errorf("certReason %q", got)
	}
	if got := certReason(x509.UnknownAuthorityError{}); !strings.Contains(got, "self-signed") {
		t.Errorf("certReason %q", got)
	}
}

func TestTransportReportsBrokenSettings(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "ca.txt")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"bad proxy", Config{Proxy: "::nope"}, "is not a URL such as http://proxy:3128"},
		{"proxy without host", Config{Proxy: "http://"}, "is not a URL"},
		{"missing ca", Config{CAFile: filepath.Join(dir, "missing.pem")}, "opensearch CA file"},
		{"ca not pem", Config{CAFile: notPEM}, "holds no PEM certificates"},
		{"missing client cert", Config{CertFile: filepath.Join(dir, "c.pem"), KeyFile: filepath.Join(dir, "k.pem")}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr, err := Transport(c.cfg)
			if err == nil || !strings.Contains(err.Error(), c.want) || tr == nil {
				t.Errorf("err %v", err)
			}
			if tr.Proxy != nil || tr.TLSClientConfig.RootCAs != nil || tr.TLSClientConfig.GetClientCertificate != nil {
				t.Error("a broken setting was used")
			}
		})
	}
}

func TestProxyHintCases(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	for _, c := range []struct {
		base, noProxy string
		hint          bool
	}{
		{"https://os.example:9200", "", true},
		{"https://os.localhost:9200", "", false},
		{"https://[::1]:9200", "", false},
		{"::bad", "", false},
		{"http://os.example:9200", "", false}, // HTTP_PROXY not set
		{"https://os.example:9200", "os.example:9200", false},
		{"https://os.example:9200", "*.example", false},
		{"https://10.1.2.3:9200", "10.0.0.0/8", false},
		{"https://10.1.2.3:9200", "192.168.0.0/16, other.example", true},
	} {
		t.Setenv("NO_PROXY", c.noProxy)
		got := proxyHint(Config{}, c.base)
		if (got != "") != c.hint {
			t.Errorf("proxyHint(%s, NO_PROXY=%q) = %q", c.base, c.noProxy, got)
		}
	}
}

func TestReachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(green))
	defer ts.Close()
	c := New(Config{URL: ts.URL})
	if !c.reachable(&endpoint{base: ts.URL}) {
		t.Error("a listening server is unreachable")
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if c.reachable(&endpoint{base: "http://" + closed}) {
		t.Error("a closed port is reachable")
	}
	if !c.reachable(&endpoint{base: "::bad"}) || !c.reachable(&endpoint{base: "file:///x"}) {
		t.Error("an address without a host is reported unreachable")
	}
	p := New(Config{URL: ts.URL, Proxy: "http://127.0.0.1:1"})
	if !p.reachable(&endpoint{base: "http://" + closed}) {
		t.Error("through a proxy reachable must be true")
	}
}
