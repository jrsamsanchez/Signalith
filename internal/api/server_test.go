package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/syslog"
)

type fakeOS struct {
	bulk []store.IndexedDoc
	// healthErr, when set, is what Health fails with.
	healthErr error

	mu      sync.Mutex
	indices []string // every index pattern searched or mapped
}

func (f *fakeOS) searched(index string) {
	f.mu.Lock()
	f.indices = append(f.indices, index)
	f.mu.Unlock()
}

func (f *fakeOS) Search(_ context.Context, index string, body map[string]any) (map[string]any, error) {
	f.searched(index)
	var out map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"hits":{"total":{"value":2}},"aggregations":{"groups":{"buckets":[
		{"key":{"k0":"10.0.0.9"},"doc_count":25},{"key":{"k0":"10.0.0.7"},"doc_count":3}]}}}`))
	dec.UseNumber()
	_ = dec.Decode(&out)
	return out, nil
}
func (f *fakeOS) Bulk(_ context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	f.bulk = append(f.bulk, docs...)
	return nil, nil
}
func (f *fakeOS) Health(context.Context) (string, error) {
	if f.healthErr != nil {
		return "", f.healthErr
	}
	return "green", nil
}
func (f *fakeOS) Mapping(_ context.Context, pattern string) (map[string]string, error) {
	f.searched(pattern)
	return map[string]string{"user": "keyword", "custom_score": "long"}, nil
}

func newTestServer(t *testing.T) (*httptest.Server, *fakeOS) {
	t.Helper()
	return newTestServerWith(t, nil)
}

// newTestServerWith lets a test change the server before it starts.
func newTestServerWith(t *testing.T, change func(*Server)) (*httptest.Server, *fakeOS) {
	t.Helper()
	cfg := config.Default()
	h, _ := config.HashPassword("s3cret-pass")
	cfg.Auth.AdminPasswordHash = h
	cfg.Ingest.Tokens = []string{"tok-0123456789abcdef"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	fos := &fakeOS{}
	lib, _, err := detect.NewLibrary(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lists, _ := assets.NewStore(t.TempDir())
	eng := &search.Engine{Store: fos, Assets: lists}
	fs := findings.NewMemory()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	boards, err := dashboards.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Config:     cfg,
		Engine:     eng,
		Pipeline:   &ingest.Pipeline{Store: fos},
		Backend:    fos,
		Detections: lib,
		Scheduler:  &detect.Scheduler{Library: lib, Engine: eng, Findings: fs, Log: logger},
		Findings:   fs,
		Assets:     lists,
		Dashboards: boards,
		Cases:      cases.NewMemory(),
		Log:        logger,
		Version:    "test",
	}
	if change != nil {
		change(s)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, fos
}

func do(t *testing.T, ts *httptest.Server, method, path, body string, auth bool) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if auth {
		req.SetBasicAuth("admin", "s3cret-pass")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 && raw[0] == '{' {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

func TestAuthRequired(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _ := do(t, ts, "GET", "/api/health", "", false); code != 401 {
		t.Errorf("unauthenticated health = %d", code)
	}
	if code, body := do(t, ts, "GET", "/api/health", "", true); code != 200 || body["opensearch"].(map[string]any)["status"] != "green" {
		t.Errorf("health = %d %v", code, body)
	} else if sl, _ := body["syslog"].(map[string]any); sl == nil || sl["enabled"] != false {
		t.Errorf("syslog off: %v", body["syslog"])
	}
}

func TestHealthShowsSyslog(t *testing.T) {
	var rcv *syslog.Receiver
	ts, _ := newTestServerWith(t, func(s *Server) {
		rcv = syslog.New(syslog.Config{UDP: "127.0.0.1:0", PublicPort: 514}, s.Pipeline, s.Log)
		ctx, cancel := context.WithCancel(context.Background())
		if err := rcv.Start(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cancel(); rcv.Wait() })
		s.Syslog = rcv
		s.Runtime = &Runtime{OS: "linux", Systemd: true, Exe: "/usr/local/bin/signalith", Addresses: []string{"192.0.2.20"}}
	})
	addr := rcv.Stats().Listeners[0].Address
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, "<13>Oct 12 13:00:00 fw1 app: hello")
	c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for rcv.Stats().Received == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	_, body := do(t, ts, "GET", "/api/health", "", true)
	sl, _ := body["syslog"].(map[string]any)
	if sl == nil || sl["enabled"] != true || sl["received"] != float64(1) {
		t.Fatalf("syslog = %v", body["syslog"])
	}
	listeners, _ := sl["listeners"].([]any)
	senders, _ := sl["senders"].([]any)
	if len(listeners) != 1 || listeners[0].(map[string]any)["address"] != addr || listeners[0].(map[string]any)["port"] != float64(514) ||
		len(senders) != 1 || senders[0].(map[string]any)["host"] != "fw1" {
		t.Errorf("listeners %v senders %v", listeners, senders)
	}
	if allow, ok := sl["allow"].([]any); !ok || len(allow) != 0 {
		t.Errorf("allow = %v, want [] (any sender)", sl["allow"])
	}
	// Add data words the steps for this system.
	rt, _ := body["runtime"].(map[string]any)
	if rt == nil || rt["os"] != "linux" || rt["systemd"] != true || rt["low_ports"] != false || rt["exe"] != "/usr/local/bin/signalith" ||
		len(rt["addresses"].([]any)) != 1 {
		t.Errorf("runtime = %v", body["runtime"])
	}
}

func TestSearchAndErrors(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := do(t, ts, "POST", "/api/search", `{"query":"datamodel=Authentication action=failure | stats count by src | where count > 10","earliest":"-24h"}`, true)
	if code != 200 {
		t.Fatalf("search = %d %v", code, body)
	}
	rows := body["rows"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["src"] != "10.0.0.9" {
		t.Errorf("rows = %v", rows)
	}
	code, body = do(t, ts, "POST", "/api/search", `{"query":"a=1 | stats avg"}`, true)
	if code != 400 || body["pos"] == nil {
		t.Errorf("parse error = %d %v", code, body)
	}
}

func TestBuildParseExplain(t *testing.T) {
	ts, _ := newTestServer(t)
	spec, _ := json.Marshal(query.Spec{Datamodel: "Authentication", Mode: "stats", AggFunc: "count", By: []string{"user"}, Filters: []query.Filter{{Field: "action", Op: "=", Value: "failure"}}})
	_, body := do(t, ts, "POST", "/api/build", string(spec), true)
	q := body["query"].(string)
	if q != "datamodel=Authentication action=failure\n| stats count by user" {
		t.Errorf("built %q", q)
	}
	b, _ := json.Marshal(map[string]string{"query": q})
	_, body = do(t, ts, "POST", "/api/parse", string(b), true)
	if body["builder_ok"] != true {
		t.Errorf("parse = %v", body)
	}
	_, body = do(t, ts, "POST", "/api/explain", `{"query":"datamodel=Authentication action=failure earliest=-24h | stats dc(user) as users by src | sort -users"}`, true)
	steps := body["steps"].([]any)
	if len(steps) != 3 || !strings.Contains(steps[0].(string), "24 hours ago") || !strings.Contains(steps[1].(string), "distinct user") {
		t.Errorf("steps = %v", steps)
	}
	if body["index"] != "signalith-authentication-*" {
		t.Errorf("index = %v", body["index"])
	}
}

func TestIngestNeedsToken(t *testing.T) {
	ts, fos := newTestServer(t)
	line := `[{"log":"Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 1 ssh2"}]`
	if code, _ := do(t, ts, "POST", "/api/ingest", line, false); code != 401 {
		t.Errorf("ingest without token = %d", code)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(line))
	req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
	req.Header.Set("X-Signalith-Tag", "linux.auth")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("ingest = %v %v", resp.StatusCode, err)
	}
	if len(fos.bulk) != 1 || fos.bulk[0].Doc["user"] != "bob" {
		t.Errorf("bulk = %v", fos.bulk)
	}
}

// TestIngestDropsSampleMarker: an agent cannot mark its own events as
// sample data, which would hide them from live detections and have them
// deleted with the sample. The event is stored, without the marker.
func TestIngestDropsSampleMarker(t *testing.T) {
	ts, fos := newTestServer(t)
	batch := `[{"user":"svc-backup","action":"failure","app":"vpn","src":"203.0.113.9","signalith_sample":"x"}]`
	req, _ := http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(batch))
	req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
	req.Header.Set("X-Signalith-Tag", "app.vpn")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var res map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if resp.StatusCode != 200 || res["indexed"] != float64(1) || res["fields_dropped"] != float64(1) {
		t.Fatalf("ingest = %d %v", resp.StatusCode, res)
	}
	if len(fos.bulk) != 1 {
		t.Fatalf("bulk = %v", fos.bulk)
	}
	doc := fos.bulk[0].Doc
	if _, ok := doc[ingest.SampleField]; ok || doc["user"] != "svc-backup" {
		t.Errorf("stored %v, want the event without the sample marker", doc)
	}
}

func TestFieldsMergeDiscovered(t *testing.T) {
	ts, _ := newTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/fields?datamodel=Authentication", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, _ := http.DefaultClient.Do(req)
	var fields []map[string]any
	json.NewDecoder(resp.Body).Decode(&fields)
	var sawCustom, userIndexed bool
	for _, f := range fields {
		if f["name"] == "custom_score" && f["type"] == "number" {
			sawCustom = true
		}
		if f["name"] == "user" && f["indexed"] == true {
			userIndexed = true
		}
	}
	if !sawCustom || !userIndexed || fields[0]["name"] != "_time" {
		t.Errorf("fields = %v", fields)
	}
}

func TestAgentConfig(t *testing.T) {
	ts, _ := newTestServer(t)
	_, body := do(t, ts, "GET", "/api/agents/config?os=windows&sysmon=true", "", true)
	cfg := body["config"].(string)
	for _, want := range []string{"winevtlog", "Microsoft-Windows-Sysmon/Operational", "Bearer @@AGENT_TOKEN@@", "Port                 8080", "Header_Tag"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("windows config missing %q:\n%s", want, cfg)
		}
	}
}

func TestAgentConfigServerAddress(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.TLS = newCertManager(t) })
	// The default public_url is https://127.0.0.1:8080, which only this
	// machine can reach; the response says so.
	_, body := do(t, ts, "GET", "/api/agents/config?os=linux", "", true)
	if body["server_url"] != "https://127.0.0.1:8080" || body["server_loopback"] != true {
		t.Errorf("default address: server_url = %v, server_loopback = %v", body["server_url"], body["server_loopback"])
	}

	q := url.Values{"os": {"linux"}, "server": {"https://192.168.1.20:9000"}}
	code, body := do(t, ts, "GET", "/api/agents/config?"+q.Encode(), "", true)
	cfg, _ := body["config"].(string)
	if code != http.StatusOK || !strings.Contains(cfg, "Host                 192.168.1.20\n") || !strings.Contains(cfg, "Port                 9000\n") {
		t.Fatalf("override: %d %v", code, body)
	}
	if body["server_url"] != "https://192.168.1.20:9000" || body["server_loopback"] != false {
		t.Errorf("override: server_url = %v, server_loopback = %v", body["server_url"], body["server_loopback"])
	}
	// Plain http is refused while Signalith serves HTTPS.
	q.Set("server", "http://192.168.1.20:9000")
	if code, body := do(t, ts, "GET", "/api/agents/config?"+q.Encode(), "", true); code != http.StatusBadRequest || body["field"] != "server" ||
		!strings.Contains(body["error"].(string), "https://192.168.1.20:9000") {
		t.Errorf("http override: %d %v", code, body)
	}

	for _, bad := range []string{
		"http://192.168.1.20:8080\n[OUTPUT]\n    Name stdout\n    Match *",
		"http://192.168.1.20:8080\r\n    Header X-Evil 1",
		"http://192.168.1.20%0A:8080",
		" http://192.168.1.20:8080",
		"192.168.1.20:8080",
		"ftp://192.168.1.20",
		"http://admin:pw@192.168.1.20:8080",
		"http://192.168.1.20:8080/api",
		"http://192.168.1.20:8080?x=1",
		"http://192.168.1.20:70000",
		"http://" + strings.Repeat("a", 5000) + ":8080",
	} {
		q := url.Values{"os": {"windows"}, "server": {bad}}
		code, body := do(t, ts, "GET", "/api/agents/config?"+q.Encode(), "", true)
		msg, _ := body["error"].(string)
		if code != http.StatusBadRequest || msg == "" || body["field"] != "server" || body["config"] != nil {
			t.Errorf("server=%q: %d %v", bad, code, body)
		}
		if strings.ContainsAny(msg, "\r\n") {
			t.Errorf("server=%q: error has a line break: %q", bad, msg)
		}
	}
}
