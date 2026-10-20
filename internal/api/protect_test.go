// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func withUI(s *Server) {
	s.UI = fstest.MapFS{
		"index.html":     {Data: []byte("<h1>app</h1>")},
		"app.js":         {Data: []byte("1")},
		"login.html":     {Data: []byte("<h1>sign in</h1>")},
		"assets/app.css": {Data: []byte("body{}")},
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	ts, _ := newTestServerWith(t, withUI)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/login"}, {"GET", "/assets/app.css"}, {"GET", "/assets/missing.css"},
		{"GET", "/api/health"}, {"POST", "/api/login"}, {"GET", "/nope"},
	} {
		resp := send(t, tc.method, ts.URL+tc.path, "{}", nil)
		csp := resp.Header.Get("Content-Security-Policy")
		for _, d := range []string{"default-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, d) {
				t.Errorf("%s %s (%d): CSP %q lacks %q", tc.method, tc.path, resp.StatusCode, csp, d)
			}
		}
		if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: headers %v", tc.method, tc.path, resp.Header)
		}
		// Plain HTTP with an http public_url: no HSTS.
		if resp.Header.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s %s: HSTS over plain HTTP", tc.method, tc.path)
		}
	}
}

func TestHSTSWhenServingHTTPS(t *testing.T) {
	hsts := func(resp *http.Response) bool {
		return strings.HasPrefix(resp.Header.Get("Strict-Transport-Security"), "max-age=")
	}
	byName := map[string]string{"Host": "siem.example.com:8080"}
	// Served over TLS by Signalith itself, to a host name.
	var srv *Server
	plain, _ := newTestServerWith(t, func(s *Server) { srv = s })
	plain.Close()
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	get := func(host string) *http.Response {
		req, _ := http.NewRequest("GET", ts.URL+"/login", nil)
		req.Host = host
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := get("siem.example.com:8080"); !hsts(resp) {
		t.Errorf("HSTS over TLS = %q", resp.Header.Get("Strict-Transport-Security"))
	}
	// Not for localhost or an IP address: it would force HTTPS on every
	// other port of that host, such as other local tools.
	for _, host := range []string{"localhost:8080", "LOCALHOST", "app.localhost:8080", "127.0.0.1:8080", "[::1]:8080", "192.168.1.20:8080", "localhost.:8080"} {
		if resp := get(host); resp.Header.Get("Strict-Transport-Security") != "" {
			t.Errorf("HSTS for %s", host)
		}
	}
	// An https public_url alone does not make a plain HTTP request
	// secure.
	byURL, _ := newTestServerWith(t, func(s *Server) {
		s.Config.Server.PublicURL = "https://siem.example.com"
		s.Config.Server.TLS = &config.ServerTLS{Mode: "auto"}
	})
	if resp, _ := plainSend(t, "GET", byURL.URL+"/api/health", "", byName); hsts(resp) {
		t.Error("HSTS over plain HTTP with an https public_url")
	}
	// Behind a TLS proxy: only one listed in server.trusted_proxies is
	// believed.
	xfp := map[string]string{"X-Forwarded-Proto": "https", "Host": "siem.example.com:8080"}
	if resp, _ := plainSend(t, "GET", byURL.URL+"/api/health", "", xfp); hsts(resp) {
		t.Error("HSTS from an untrusted X-Forwarded-Proto")
	}
	proxied, _ := newTestServerWith(t, func(s *Server) { s.Config.Server.TrustedProxies = []string{"127.0.0.0/8"} })
	if resp, _ := plainSend(t, "GET", proxied.URL+"/api/health", "", xfp); !hsts(resp) {
		t.Error("no HSTS behind a trusted proxy")
	}
	if resp, _ := plainSend(t, "GET", proxied.URL+"/api/health", "", map[string]string{"X-Forwarded-Proto": "http", "Host": "siem.example.com:8080"}); hsts(resp) {
		t.Error("HSTS for a proxy that says http")
	}
}

func TestAPIResponsesAreNotStored(t *testing.T) {
	ts, _ := newTestServerWith(t, withUI)
	code, body := do(t, ts, "POST", "/api/cases", `{"title":"Note: svc_backup password rotated"}`, true)
	if code != 201 {
		t.Fatalf("create case = %d %v", code, body)
	}
	id := body["case"].(map[string]any)["id"].(string)
	for _, path := range []string{"/api/cases/" + id, "/api/cases", "/api/agents/config?os=linux", "/api/lookups/assets.csv", "/api/health"} {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		req.SetBasicAuth("admin", "s3cret-pass")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s (%d): Cache-Control %q", path, resp.StatusCode, got)
		}
	}
	// Signed-out errors too.
	if got := send(t, "GET", ts.URL+"/api/cases/"+id, "", nil).Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("401: Cache-Control %q", got)
	}
	// The app's scripts may be cached but are always revalidated; public
	// assets are cached normally.
	req, _ := http.NewRequest("GET", ts.URL+"/app.js", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("app.js: Cache-Control %q", got)
	}
	if got := send(t, "GET", ts.URL+"/assets/app.css", "", nil).Header.Get("Cache-Control"); got != "" {
		t.Errorf("public asset: Cache-Control %q", got)
	}
}

func TestSignOutClearsTheBrowserCache(t *testing.T) {
	ts, _ := newTestServerWith(t, withUI)
	resp := send(t, "POST", ts.URL+"/api/logout", "", nil)
	if got := resp.Header.Get("Clear-Site-Data"); got != `"cache"` {
		t.Errorf("Clear-Site-Data = %q", got)
	}
	if got := send(t, "POST", ts.URL+"/api/login", "{}", nil).Header.Get("Clear-Site-Data"); got != "" {
		t.Errorf("sign-in clears data: %q", got)
	}
}

// shortBodyTimeouts shortens the body deadlines for one test.
func shortBodyTimeouts(t *testing.T, body, upload time.Duration) {
	oldBody, oldUpload := bodyTimeout, uploadTimeout
	bodyTimeout, uploadTimeout = body, upload
	t.Cleanup(func() { bodyTimeout, uploadTimeout = oldBody, oldUpload })
}

// rawRequest writes head and then body on a new connection to ts, pausing
// before the body, and returns the status line (or "" if the server
// closed the connection without one) and how long the reply took.
func rawRequest(t *testing.T, ts *httptest.Server, head, body string, pause time.Duration) (string, time.Duration) {
	t.Helper()
	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	c.SetReadDeadline(start.Add(10 * time.Second))
	io.WriteString(c, head)
	// Read while the body is still to come, so a reply sent before it
	// arrives is seen: once the server has closed the connection, writing
	// the body resets it, and Windows then drops what was received.
	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(c).ReadString('\n')
		lines <- strings.TrimSpace(line)
	}()
	if pause > 0 {
		time.Sleep(pause)
	}
	io.WriteString(c, body)
	line := <-lines
	return line, time.Since(start)
}

func TestSlowRequestBodyIsCutOff(t *testing.T) {
	shortBodyTimeouts(t, 300*time.Millisecond, 5*time.Second)
	ts, _ := newTestServer(t)
	// Headers for a sign-in, then only part of the body, never the rest.
	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"username\":")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	reply, _ := io.ReadAll(c) // until the server closes the connection
	if time.Since(start) > 3*time.Second || !strings.Contains(string(reply), "400 Bad Request") {
		t.Errorf("after %v: %q", time.Since(start), reply)
	}
}

func TestLongRequestOutlivesTheBodyDeadline(t *testing.T) {
	shortBodyTimeouts(t, 200*time.Millisecond, time.Second)
	errc := make(chan error, 2)
	ts := httptest.NewServer(limitBodies(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		// A long search after a small body.
		select {
		case <-time.After(4 * bodyTimeout):
			errc <- nil
		case <-r.Context().Done():
			errc <- fmt.Errorf("%s: request cancelled after %v", r.Method, 4*bodyTimeout)
		}
		io.WriteString(w, "done")
	})))
	defer ts.Close()
	for _, req := range []*http.Request{
		mustRequest("POST", ts.URL, `{"query":"*"}`),
		mustRequest("GET", ts.URL, ""),
	} {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err := <-errc; err != nil || string(b) != "done" {
			t.Errorf("%v %q", err, b)
		}
	}
}

func mustRequest(method, url, body string) *http.Request {
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if body == "" {
		req.Body = http.NoBody
	}
	return req
}

func TestAgentBatchesMayArriveSlowly(t *testing.T) {
	shortBodyTimeouts(t, 200*time.Millisecond, 5*time.Second)
	ts, _ := newTestServer(t)
	body := `[{"log":"Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 1 ssh2"}]`
	head := "POST /api/ingest HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer tok-0123456789abcdef\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n"
	if status, _ := rawRequest(t, ts, head, body, 600*time.Millisecond); !strings.Contains(status, "200") {
		t.Errorf("slow agent batch: %q", status)
	}
	// Without the token, the body is not waited for.
	bad := strings.Replace(head, "tok-0123456789abcdef", "wrong-token-000000", 1)
	if status, took := rawRequest(t, ts, bad, "", 0); !strings.Contains(status, "401") || took > 2*time.Second {
		t.Errorf("bad token: %q after %v", status, took)
	}
	// A signed-in user's slow JSON request is still cut off.
	slow := "POST /api/search HTTP/1.1\r\nHost: x\r\nAuthorization: Basic YWRtaW46czNjcmV0LXBhc3M=\r\nContent-Length: 15\r\n\r\n"
	if status, _ := rawRequest(t, ts, slow, `{"query":"*"} `, 600*time.Millisecond); !strings.Contains(status, "400") {
		t.Errorf("slow search body: %q", status)
	}
}

type failingBulk struct{}

func (failingBulk) Bulk(context.Context, []store.IndexedDoc) ([]store.BulkItemError, error) {
	return nil, errors.New("opensearch unreachable at http://10.20.30.40:9200: dial tcp: connection refused")
}

func TestIngestErrorsDoNotRevealOpenSearch(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Pipeline = &ingest.Pipeline{Store: failingBulk{}} })
	req, _ := http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(`[{"log":"x"}]`))
	req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 503 || strings.Contains(string(b), "10.20.30.40") || !strings.Contains(string(b), "try again") {
		t.Errorf("%d %s", resp.StatusCode, b)
	}
}

// failingSearch is OpenSearch failing every search the way the store
// says so, naming where it runs.
type failingSearch struct{ *fakeOS }

func (failingSearch) Search(context.Context, string, map[string]any) (map[string]any, error) {
	return nil, fmt.Errorf("opensearch unreachable at http://10.20.30.40:9200: %w",
		&url.Error{Op: "Post", URL: "http://10.20.30.40:9200/x/_search", Err: errors.New("dial tcp 10.20.30.40:9200: connect: connection refused")})
}

// failingFindings fails to read a finding with an error naming a file.
type failingFindings struct{ findings.Store }

func (failingFindings) Get(context.Context, string) (*findings.Finding, error) {
	return nil, &fs.PathError{Op: "open", Path: "/var/lib/signalith/secret/findings.json", Err: fs.ErrPermission}
}

// A failed search, or any failure on the server, says only that it
// failed, with a reference; where OpenSearch runs and file paths are in
// the server's log under that reference.
func TestServerErrorsDoNotRevealDetails(t *testing.T) {
	var logs logBuffer
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Log = slog.New(slog.NewTextHandler(&logs, nil))
		s.Engine.Store = failingSearch{s.Engine.Store.(*fakeOS)}
		s.Findings = failingFindings{s.Findings}
	})
	for _, c := range []struct{ method, path, body, detail string }{
		{"POST", "/api/search", `{"query":"* | head 5"}`, "10.20.30.40"},
		{"GET", "/api/findings/f-1", "", "/var/lib/signalith/secret"},
	} {
		code, out := do(t, ts, c.method, c.path, c.body, true)
		msg, _ := out["error"].(string)
		ref, _ := out["ref"].(string)
		if code != http.StatusBadGateway || ref == "" || !strings.Contains(msg, "(ref "+ref+")") || strings.Contains(msg, c.detail) {
			t.Errorf("%s %s = %d %v", c.method, c.path, code, out)
			continue
		}
		if line := auditLine(t, logs.String(), "ref="+ref); !strings.Contains(line, c.detail) || !strings.Contains(line, "status=502") {
			t.Errorf("%s %s: the log line lacks the details: %s", c.method, c.path, line)
		}
	}
}

// writeError hides a 5xx error from below, but shows messages written for
// the person who sees them.
func TestWriteErrorFiveHundreds(t *testing.T) {
	pathErr := &fs.PathError{Op: "open", Path: "/srv/signalith/state/keys/master.key", Err: fs.ErrPermission}
	netErr := fmt.Errorf("opensearch unreachable at https://os.internal:9200: %w", &net.OpError{Op: "dial", Err: errors.New("refused")})
	for _, c := range []struct {
		name   string
		status int
		err    error
		want   string // in the message
		hidden string // not in it
	}{
		{"raw 500", 500, pathErr, "Something went wrong on the server (ref ", "master.key"},
		{"raw 502", 502, netErr, "could not reach a service it uses", "os.internal"},
		{"503 from below", 503, netErr, "(ref ", "os.internal"},
		{"503 of our own", 503, errDetectionsOff, errDetectionsOff.Error(), "ref"},
		{"500 of our own", 500, errUser("this server cannot read its own program"), "this server cannot read its own program", "ref"},
		{"context kept", 500, errHidden("could not save the settings file", pathErr), "could not save the settings file (ref ", "master.key"},
		{"busy", 503, fmt.Errorf("search: %w", search.ErrBusy), search.ErrBusy.Error(), "ref"},
		{"the AI model's answer", 502, &assistant.APIError{Status: 401, StatusText: "401 Unauthorized", Message: "bad key", Parsed: true}, "the AI model returned 401 Unauthorized: bad key", "ref"},
		{"a page in its place", 502, &assistant.APIError{Status: 502, StatusText: "502 Bad Gateway", Message: "<html>proxy.internal.example</html>"}, "(ref ", "proxy.internal"},
		{"a 4xx is shown", 400, errors.New("title is required"), "title is required", "ref"},
	} {
		var logs logBuffer
		s := &Server{Log: slog.New(slog.NewTextHandler(&logs, nil))}
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/x", nil)
		writeError(s.withErrorLog(rec, r), c.status, c.err)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		msg, _ := out["error"].(string)
		if rec.Code != c.status || !strings.Contains(msg, c.want) || strings.Contains(msg, c.hidden) {
			t.Errorf("%s: %d %q", c.name, rec.Code, msg)
		}
		if ref, _ := out["ref"].(string); ref != "" && !strings.Contains(logs.String(), "ref="+ref) {
			t.Errorf("%s: not logged with its reference: %s", c.name, logs.String())
		}
	}

	// What is logged has its secrets hidden.
	var logs logBuffer
	s := &Server{Log: slog.New(slog.NewTextHandler(&logs, nil))}
	err := fmt.Errorf("saving password=Hunter22 for https://svc:Pa55@db.internal/x: %w", pathErr)
	writeError(s.withErrorLog(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/x", nil)), 500, err)
	if l := logs.String(); strings.Contains(l, "Hunter22") || strings.Contains(l, "Pa55") || !strings.Contains(l, "db.internal") || !strings.Contains(l, "master.key") {
		t.Errorf("logged %s", l)
	}
}

func TestHealthHidesSecretsAndShowsWarnings(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Config.OpenSearch.URL = "https://admin:OsAdm1nPass@os.internal:9200/?api_key=K3Y"
		s.Config.OpenSearch.TLSSkipVerify = true
	})
	_, body := do(t, ts, "GET", "/api/health", "", true)
	os := body["opensearch"].(map[string]any)
	if os["url"] != "https://***@os.internal:9200/?api_key=***" {
		t.Errorf("url = %v", os["url"])
	}
	if w := fmt.Sprint(body["warnings"]); !strings.Contains(w, "tls_skip_verify") {
		t.Errorf("warnings = %v", w)
	}
}
