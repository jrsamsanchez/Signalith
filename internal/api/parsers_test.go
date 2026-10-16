package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/onboard"
)

// syncBuf is a log the handlers write to while the test reads it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func newParsersServer(t *testing.T, change func(*Server)) (*httptest.Server, *fakeOS, *syncBuf) {
	t.Helper()
	log := &syncBuf{}
	ts, fos := newTestServerWith(t, func(s *Server) {
		s.Log = slog.New(slog.NewTextHandler(log, nil))
		reg := onboard.NewRegistry(onboard.NewFileStore(filepath.Join(t.TempDir(), onboard.File)))
		s.Parsers = reg
		s.Pipeline.Custom = reg
		if change != nil {
			change(s)
		}
	})
	return ts, fos, log
}

const kvSample = `date=2026-10-16 time=14:05:09 devname="fw01" srcip=10.0.1.15 dstip=203.0.113.9 dstport=443 proto=6 action="deny"
date=2026-10-16 time=14:05:10 devname="fw01" srcip=10.0.1.16 dstip=203.0.113.9 dstport=22 proto=6 action="accept"`

func jsonBody(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestCustomParserFlow(t *testing.T) {
	ts, fos, log := newParsersServer(t, nil)

	code, info := do(t, ts, "GET", "/api/parsers", "", true)
	if code != 200 || len(info["models"].([]any)) < 5 || info["ai"] != nil {
		t.Fatalf("list = %d %v", code, info)
	}
	if code, _ := do(t, ts, "GET", "/api/parsers", "", false); code != 401 {
		t.Errorf("list signed out = %d", code)
	}

	// A sample gets a suggestion, a preview and its detections.
	code, ans := do(t, ts, "POST", "/api/parsers/analyze", jsonBody(map[string]string{"sample": kvSample}), true)
	if code != 200 {
		t.Fatalf("analyze = %d %v", code, ans)
	}
	p := ans["parser"].(map[string]any)
	pv := ans["preview"].(map[string]any)
	if p["format"] != "kv" || p["model"] != "Network_Traffic" || pv["parsed"] != float64(2) || ans["tag"] != "custom."+p["name"].(string) || ans["coverage"] == nil {
		t.Fatalf("analyze = %v", ans)
	}
	if _, ok := pv["docs"]; ok {
		t.Error("the preview sends every document")
	}
	if code, out := do(t, ts, "POST", "/api/parsers/analyze", `{"sample":"   \n "}`, true); code != 400 {
		t.Errorf("empty sample = %d %v", code, out)
	}
	// An edited parser that does not compile says why.
	bad := map[string]any{"sample": kvSample, "parser": map[string]any{"name": "x1", "sourcetype": "x", "model": "Other", "format": "regex", "pattern": "(?P<a"}}
	if code, out := do(t, ts, "POST", "/api/parsers/analyze", jsonBody(bad), true); code != 400 || !strings.Contains(out["error"].(string), "compile") {
		t.Errorf("bad pattern = %d %v", code, out)
	}

	// Saved, it reads what agents send under its tag.
	p["name"] = "fw"
	if code, out := do(t, ts, "PUT", "/api/parsers/fw", jsonBody(p), true); code != 200 || out["updated_by"] != "admin" {
		t.Fatalf("save = %d %v", code, out)
	}
	if !strings.Contains(log.String(), `msg="custom parser added"`) || !strings.Contains(log.String(), "parser=fw") || !strings.Contains(log.String(), "mappings=") {
		t.Errorf("not audited: %s", log)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(jsonBody([]map[string]string{{"log": strings.Split(kvSample, "\n")[0]}})))
	req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
	req.Header.Set("X-Signalith-Tag", "custom.fw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("ingest = %v %v", resp, err)
	}
	resp.Body.Close()
	if len(fos.bulk) != 1 {
		t.Fatalf("bulk = %v", fos.bulk)
	}
	doc := fos.bulk[0].Doc
	if doc["src"] != "10.0.1.15" || doc["action"] != "blocked" || doc["datamodel"] != "Network_Traffic" || doc["sourcetype"] != p["sourcetype"] {
		t.Errorf("stored %v", doc)
	}

	// A new suggestion does not take a saved parser's name.
	_, ans = do(t, ts, "POST", "/api/parsers/analyze", jsonBody(map[string]string{"sample": kvSample}), true)
	p2 := ans["parser"].(map[string]any)
	if code, _ := do(t, ts, "PUT", "/api/parsers/"+p2["name"].(string), jsonBody(p2), true); code != 200 {
		t.Fatal(code)
	}
	_, ans = do(t, ts, "POST", "/api/parsers/analyze", jsonBody(map[string]string{"sample": kvSample}), true)
	if n := ans["parser"].(map[string]any)["name"]; n != p2["name"].(string)+"-2" {
		t.Errorf("suggested name %v after saving %v", n, p2["name"])
	}

	// Changes are checked.
	p["model"] = "Risk"
	if code, out := do(t, ts, "PUT", "/api/parsers/fw", jsonBody(p), true); code != 400 || !strings.Contains(out["error"].(string), "data models") {
		t.Errorf("risk model = %d %v", code, out)
	}
	if code, _ := do(t, ts, "PUT", "/api/parsers/Bad%20Name", jsonBody(p), true); code != 400 {
		t.Errorf("bad name = %d", code)
	}

	// The agent input for its log files.
	q := url.Values{"os": {"linux"}, "paths": {"/var/log/fw/*.log\n/var/log/fw.log"}}
	if code, out := do(t, ts, "GET", "/api/parsers/fw/input?"+q.Encode(), "", true); code != 200 || !strings.Contains(out["input"].(string), "custom.fw") {
		t.Errorf("input = %d %v", code, out)
	}
	q.Set("paths", "/var/log/a.log\n[OUTPUT]")
	if code, _ := do(t, ts, "GET", "/api/parsers/fw/input?"+q.Encode(), "", true); code != 400 {
		t.Errorf("input with a crafted path = %d", code)
	}

	if code, _ := do(t, ts, "DELETE", "/api/parsers/fw", "", true); code != 204 {
		t.Errorf("delete = %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/parsers/fw", "", true); code != 404 {
		t.Errorf("delete again = %d", code)
	}
	if !strings.Contains(log.String(), `msg="custom parser deleted"`) {
		t.Errorf("delete not audited")
	}
}

// TestCustomParsersAdminOnly: a parser changes how events are stored, so
// analysts can neither read samples through it nor save one.
func TestCustomParsersAdminOnly(t *testing.T) {
	ts, _ := newUsersServer(t, nil)
	if code, _, _ := call(t, ts, "POST", "/api/users", `{"username":"ana","role":"analyst","password":"a-fine-pass-here","must_change_password":false}`, "admin", adminPass, nil); code != 201 {
		t.Fatal(code)
	}
	for _, r := range [][2]string{{"GET", "/api/parsers"}, {"POST", "/api/parsers/analyze"}, {"PUT", "/api/parsers/x1"}, {"DELETE", "/api/parsers/x1"}, {"POST", "/api/parsers/refine"}} {
		if code, _ := doAs(t, ts, "ana", "a-fine-pass-here", r[0], r[1], `{"sample":"a=1"}`); code != 403 {
			t.Errorf("analyst %s %s = %d", r[0], r[1], code)
		}
	}
}

// TestRefineParser: the AI model gets only the sample's first lines, and
// sending them is audited with where they went.
func TestRefineParser(t *testing.T) {
	var asked string
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		asked = string(b)
		reply := `{"sourcetype":"acme:fw","model":"Network_Traffic","format":"kv","kv_separator":"=","delimiter":"","time_field":"date+time","mappings":[{"from":"srcip","to":"src"},{"from":"dstip","to":"dest"}],"explanation":"Mapped the addresses."}`
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": reply}}}})
	}))
	defer model.Close()
	ts, _, log := newParsersServer(t, func(s *Server) { s.Assistant = assistant.New(assistant.OpenAI, model.URL, "m", "") })

	_, info := do(t, ts, "GET", "/api/parsers", "", true)
	if ai, _ := info["ai"].(map[string]any); ai == nil || ai["sent_to"] == "" {
		t.Fatalf("ai = %v", info["ai"])
	}
	var lines []string
	for i := 0; i < 60; i++ {
		lines = append(lines, strings.Split(kvSample, "\n")[i%2]+" seq="+strings.Repeat("9", i+1))
	}
	_, ans := do(t, ts, "POST", "/api/parsers/analyze", jsonBody(map[string]string{"sample": strings.Join(lines, "\n")}), true)
	code, out := do(t, ts, "POST", "/api/parsers/refine", jsonBody(map[string]any{"sample": strings.Join(lines, "\n"), "parser": ans["parser"]}), true)
	if code != 200 || out["explanation"] != "Mapped the addresses." || out["parser"].(map[string]any)["sourcetype"] != "acme:fw" {
		t.Fatalf("refine = %d %v", code, out)
	}
	if strings.Contains(asked, "seq="+strings.Repeat("9", onboard.AILines+1)) || !strings.Contains(asked, "seq="+strings.Repeat("9", onboard.AILines)) {
		t.Errorf("sent other than the first %d lines", onboard.AILines)
	}
	if !strings.Contains(log.String(), `msg="log sample sent to the AI model"`) || !strings.Contains(log.String(), "lines=20") {
		t.Errorf("not audited: %s", log)
	}
}

func TestRefineNeedsModel(t *testing.T) {
	ts, _, _ := newParsersServer(t, nil)
	if code, _ := do(t, ts, "POST", "/api/parsers/refine", `{"sample":"a=1","parser":{}}`, true); code != 409 {
		t.Errorf("refine without a model = %d", code)
	}
}
