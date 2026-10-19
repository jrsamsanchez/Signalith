package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakeAPI is a Signalith API stand-in that answers each path from a table
// and records the query strings it was sent.
type fakeAPI struct {
	mu      sync.Mutex
	answers map[string]func(w http.ResponseWriter, r *http.Request)
	seen    map[string]url.Values
	bodies  map[string]string
}

func newFakeAPI(t *testing.T) (*fakeAPI, *Server) {
	t.Helper()
	f := &fakeAPI{answers: map[string]func(http.ResponseWriter, *http.Request){}, seen: map[string]url.Values{}, bodies: map[string]string{}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.seen[r.URL.Path] = r.URL.Query()
		f.bodies[r.URL.Path] = string(b)
		h := f.answers[r.URL.Path]
		f.mu.Unlock()
		if h == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"no such route"}`)
			return
		}
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	return f, NewServer(&Client{BaseURL: u, Token: "test-token", UserAgent: "mcp-test"}, "v-test")
}

func (f *fakeAPI) json(path, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[path] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}
}

func (f *fakeAPI) status(path string, code int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[path] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		io.WriteString(w, body)
	}
}

func (f *fakeAPI) query(path string) url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[path]
}

func (f *fakeAPI) body(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[path]
}

func call(t *testing.T, s *Server, name, args string) (any, error) {
	t.Helper()
	for _, tl := range s.Tools {
		if tl.Name == name {
			if args == "" {
				args = "{}"
			}
			return tl.Call(context.Background(), json.RawMessage(args))
		}
	}
	t.Fatalf("no tool %s", name)
	return nil, nil
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	return m
}

func TestNewServerTools(t *testing.T) {
	_, s := newFakeAPI(t)
	if s.Name != "signalith" || s.Version != "v-test" || s.Instructions != Instructions {
		t.Errorf("server = %+v", s)
	}
	names := map[string]bool{}
	for _, tl := range s.Tools {
		if tl.Call == nil || tl.Schema["type"] != "object" || tl.Description == "" {
			t.Errorf("tool %s is incomplete", tl.Name)
		}
		names[tl.Name] = true
	}
	for _, n := range []string{"whoami", "query_help", "check_query", "search", "list_findings", "get_finding",
		"findings_summary", "list_cases", "get_case", "list_detections", "get_detection", "list_assets",
		"lookup_entity", "risk_objects", "risk_object", "intel_lookup"} {
		if !names[n] {
			t.Errorf("missing tool %s", n)
		}
	}
}

func TestWhoami(t *testing.T) {
	f, s := newFakeAPI(t)
	f.json("/api/me", `{"username":"vera","name":"Vera","role":"analyst","source":"local","password_hash":"x"}`)
	out, err := call(t, s, "whoami", "")
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, out)
	if m["username"] != "vera" || m["role"] != "analyst" || m["server"] == "" {
		t.Errorf("whoami = %v", m)
	}
	if _, ok := m["password_hash"]; ok {
		t.Error("whoami passed through fields it should not")
	}
	f.status("/api/me", 500, `{"error":"boom"}`)
	if _, err := call(t, s, "whoami", ""); err == nil || err.Error() != "boom" {
		t.Errorf("error = %v", err)
	}
}

func TestQueryHelp(t *testing.T) {
	f, s := newFakeAPI(t)
	f.json("/api/language", `{"commands":["stats"]}`)
	f.json("/api/datamodels", `[{"name":"Authentication","description":"logons","fields":[{"name":"user"},{"name":"src"}]}]`)
	f.json("/api/fields", `{"fields":["user"]}`)
	out, err := call(t, s, "query_help", "")
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, out)
	dms := m["datamodels"].([]any)
	if len(dms) != 1 || dms[0].(map[string]any)["name"] != "Authentication" ||
		len(dms[0].(map[string]any)["fields"].([]any)) != 2 || m["guide"] == "" || m["language"] == nil {
		t.Errorf("query_help = %v", m)
	}
	out, err = call(t, s, "query_help", `{"datamodel":"Authentication"}`)
	if err != nil {
		t.Fatal(err)
	}
	if f.query("/api/fields").Get("datamodel") != "Authentication" || asMap(t, out)["fields"] == nil {
		t.Errorf("fields = %v", out)
	}
	if _, err := call(t, s, "query_help", `{"datamodel":5}`); err == nil || !strings.HasPrefix(err.Error(), "arguments:") {
		t.Errorf("bad args = %v", err)
	}
	f.status("/api/datamodels", 500, `{}`)
	if _, err := call(t, s, "query_help", ""); err == nil {
		t.Error("datamodels error not returned")
	}
	f.status("/api/language", 500, `{}`)
	if _, err := call(t, s, "query_help", ""); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("language error = %v", err)
	}
}

func TestCheckQuery(t *testing.T) {
	f, s := newFakeAPI(t)
	f.json("/api/parse", `{"canonical":"search user=x"}`)
	out, err := call(t, s, "check_query", `{"query":"user=x"}`)
	if err != nil {
		t.Fatal(err)
	}
	if m := asMap(t, out); m["valid"] != true || m["query"] != "search user=x" {
		t.Errorf("valid = %v", m)
	}
	if !strings.Contains(f.body("/api/parse"), `"user=x"`) {
		t.Errorf("body = %s", f.body("/api/parse"))
	}
	f.status("/api/parse", 400, `{"error":"unexpected |"}`)
	out, err = call(t, s, "check_query", `{"query":"|"}`)
	if err != nil {
		t.Fatal(err)
	}
	if m := asMap(t, out); m["valid"] != false || m["error"] != "unexpected |" {
		t.Errorf("invalid = %v", m)
	}
	f.status("/api/parse", 503, `{}`)
	if _, err := call(t, s, "check_query", `{"query":"x"}`); err == nil {
		t.Error("server error not returned")
	}
	if _, err := call(t, s, "check_query", `{"query":"  "}`); err == nil || err.Error() != "query is required" {
		t.Errorf("empty = %v", err)
	}
	if _, err := call(t, s, "check_query", `[]`); err == nil {
		t.Error("bad args accepted")
	}
}

func TestSearch(t *testing.T) {
	f, s := newFakeAPI(t)
	rows := make([]string, 5)
	for i := range rows {
		rows[i] = `{"user":"u` + string(rune('a'+i)) + `"}`
	}
	f.json("/api/search", `{"kind":"stats","columns":["user"],"rows":[`+strings.Join(rows, ",")+`],"matched":42,"took_ms":3}`)
	out, err := call(t, s, "search", `{"query":"* | stats count by user","max_rows":2}`)
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, out)
	if len(m["rows"].([]any)) != 2 || !strings.Contains(m["note"].(string), "Showing 2 of 5") || m["matched_events"] != float64(42) {
		t.Errorf("search = %v", m)
	}
	var req map[string]string
	_ = json.Unmarshal([]byte(f.body("/api/search")), &req)
	if req["earliest"] != "-24h" || req["query"] != "* | stats count by user" {
		t.Errorf("request = %v", req)
	}

	f.json("/api/search", `{"kind":"events","rows":[{"a":1}],"truncated":true}`)
	out, err = call(t, s, "search", `{"query":"*","earliest":"-7d","latest":"now"}`)
	if err != nil {
		t.Fatal(err)
	}
	if m := asMap(t, out); !strings.Contains(m["note"].(string), "cut the results short") || len(m["rows"].([]any)) != 1 {
		t.Errorf("truncated = %v", m)
	}
	_ = json.Unmarshal([]byte(f.body("/api/search")), &req)
	if req["earliest"] != "-7d" || req["latest"] != "now" {
		t.Errorf("request = %v", req)
	}

	f.json("/api/search", `{"kind":"events","rows":[]}`)
	out, _ = call(t, s, "search", `{"query":"*"}`)
	if _, ok := asMap(t, out)["note"]; ok {
		t.Errorf("note on a small answer: %v", out)
	}

	if _, err := call(t, s, "search", `{"query":"*","max_rows":9999}`); err == nil || !strings.HasPrefix(err.Error(), "max_rows must be 1-") {
		t.Errorf("max_rows = %v", err)
	}
	if _, err := call(t, s, "search", `{}`); err == nil {
		t.Error("missing query accepted")
	}
	if _, err := call(t, s, "search", `{"query":1}`); err == nil {
		t.Error("bad args accepted")
	}
	f.status("/api/search", 400, `{"error":"bad query"}`)
	if _, err := call(t, s, "search", `{"query":"*"}`); err == nil || err.Error() != "bad query" {
		t.Errorf("api error = %v", err)
	}
}

func TestListFindingsAndCases(t *testing.T) {
	f, s := newFakeAPI(t)
	f.json("/api/findings", `{"findings":[{"id":"f1"}]}`)
	out, err := call(t, s, "list_findings", `{"status":"new","severity":"high","urgency":"critical","owner":"vera","detection":"d1","text":" brute ","since":"24h"}`)
	if err != nil {
		t.Fatal(err)
	}
	q := f.query("/api/findings")
	if q.Get("limit") != "25" || q.Get("status") != "new" || q.Get("severity") != "high" || q.Get("urgency") != "critical" ||
		q.Get("owner") != "vera" || q.Get("detection") != "d1" || q.Get("q") != "brute" || q.Get("since") != "24h" {
		t.Errorf("query = %v", q)
	}
	if asMap(t, out)["findings"] == nil {
		t.Errorf("out = %v", out)
	}
	if _, err := call(t, s, "list_findings", `{"limit":10}`); err != nil {
		t.Fatal(err)
	}
	if q := f.query("/api/findings"); q.Get("limit") != "10" || q.Has("status") {
		t.Errorf("query = %v", q)
	}
	if _, err := call(t, s, "list_findings", `{"limit":-1}`); err == nil {
		t.Error("negative limit accepted")
	}
	if _, err := call(t, s, "list_findings", `"x"`); err == nil {
		t.Error("bad args accepted")
	}

	f.json("/api/cases", `{"cases":[]}`)
	if _, err := call(t, s, "list_cases", `{"status":"open","owner":"o","text":"t","finding":"f1","limit":3}`); err != nil {
		t.Fatal(err)
	}
	q = f.query("/api/cases")
	if q.Get("limit") != "3" || q.Get("status") != "open" || q.Get("owner") != "o" || q.Get("q") != "t" || q.Get("finding") != "f1" {
		t.Errorf("cases query = %v", q)
	}
	if _, err := call(t, s, "list_cases", `{"limit":100000}`); err == nil {
		t.Error("large limit accepted")
	}
	if _, err := call(t, s, "list_cases", `1`); err == nil {
		t.Error("bad args accepted")
	}

	f.json("/api/findings/summary", `{"by_status":{"new":2}}`)
	if out, err := call(t, s, "findings_summary", ""); err != nil || asMap(t, out)["by_status"] == nil {
		t.Errorf("summary = %v, %v", out, err)
	}
	f.status("/api/findings/summary", 500, `{}`)
	if _, err := call(t, s, "findings_summary", ""); err == nil {
		t.Error("summary error not returned")
	}
}

func TestByID(t *testing.T) {
	f, s := newFakeAPI(t)
	f.json("/api/findings/f 1", `{"id":"f 1"}`)
	f.json("/api/cases/c1", `{"id":"c1"}`)
	f.json("/api/detections/d1", `{"id":"d1"}`)
	for tool, id := range map[string]string{"get_finding": "f 1", "get_case": "c1", "get_detection": "d1"} {
		out, err := call(t, s, tool, `{"id":"`+id+`"}`)
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if asMap(t, out)["id"] != id {
			t.Errorf("%s = %v", tool, out)
		}
		if _, err := call(t, s, tool, `{"id":""}`); err == nil || err.Error() != "id is required" {
			t.Errorf("%s empty id = %v", tool, err)
		}
		if _, err := call(t, s, tool, `{"id":3}`); err == nil {
			t.Errorf("%s bad args accepted", tool)
		}
	}
	if _, err := call(t, s, "get_case", `{"id":"missing"}`); err == nil {
		t.Error("404 not returned")
	}
}

func TestListDetections(t *testing.T) {
	f, s := newFakeAPI(t)
	f.json("/api/detections", `{"detections":[
		{"id":"brute","name":"Brute force","severity":"high","mitre":["T1110.001"],"enabled":true,"source":"builtin","schedule":"5m","state":{"last_run":"now"}},
		{"id":"dns","title":"Odd DNS","description":"tunnel","severity":"low","tags":["attack.t1071"],"enabled":false,"source":"custom"},
		{"id":"ps","name":"PowerShell","severity":"medium","enabled":true,"source":"pack","state":{"last_error":"bad"}}
	]}`)
	get := func(args string) map[string]any {
		t.Helper()
		out, err := call(t, s, "list_detections", args)
		if err != nil {
			t.Fatal(err)
		}
		return asMap(t, out)
	}
	m := get("")
	if m["total"] != float64(3) || m["enabled"] != float64(2) || m["matched"] != float64(3) {
		t.Errorf("all = %v", m)
	}
	ids := func(m map[string]any) []string {
		var out []string
		for _, d := range m["detections"].([]any) {
			out = append(out, d.(map[string]any)["id"].(string))
		}
		return out
	}
	cases := map[string]string{
		`{"enabled":false}`:           "dns",
		`{"severity":"HIGH, medium"}`: "brute,ps",
		`{"source":"pack"}`:           "ps",
		`{"mitre":"t1110"}`:           "brute",
		`{"mitre":"T1071"}`:           "dns",
		`{"text":"tunnel"}`:           "dns",
		`{"text":"odd dns"}`:          "dns",
		`{"text":"nothing"}`:          "",
	}
	for args, want := range cases {
		if got := strings.Join(ids(get(args)), ","); got != want {
			t.Errorf("%s = %q, want %q", args, got, want)
		}
	}
	m = get(`{"limit":1}`)
	if m["matched"] != float64(3) || len(m["detections"].([]any)) != 1 {
		t.Errorf("limit = %v", m)
	}
	if d := get(`{"text":"odd"}`)["detections"].([]any)[0].(map[string]any); d["name"] != "Odd DNS" {
		t.Errorf("name falls back to title: %v", d)
	}
	if _, err := call(t, s, "list_detections", `{"limit":1000}`); err == nil {
		t.Error("large limit accepted")
	}
	if _, err := call(t, s, "list_detections", `{"enabled":"yes"}`); err == nil {
		t.Error("bad args accepted")
	}
	f.status("/api/detections", 403, `{"error":"forbidden"}`)
	if _, err := call(t, s, "list_detections", ""); err == nil || err.Error() != "forbidden" {
		t.Errorf("api error = %v", err)
	}
}

func TestListAssets(t *testing.T) {
	f, s := newFakeAPI(t)
	f.json("/api/lookups/assets", `{"count":5,"items":[{"host":"web1","owner":"ops"},{"host":"db1","owner":"dba"},{"host":"web2"}]}`)
	out, err := call(t, s, "list_assets", `{"kind":"assets","text":"WEB","limit":1}`)
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(t, out)
	if m["total"] != float64(5) || m["matched"] != float64(2) || len(m["items"].([]any)) != 1 ||
		!strings.Contains(m["note"].(string), "first 3 of 5") {
		t.Errorf("assets = %v", m)
	}
	f.json("/api/lookups/identities", `{"count":1,"items":[{"user":"vera"}]}`)
	out, err = call(t, s, "list_assets", `{"kind":"identities"}`)
	if err != nil {
		t.Fatal(err)
	}
	if m := asMap(t, out); m["matched"] != float64(1) || m["note"] != nil {
		t.Errorf("identities = %v", m)
	}
	if _, err := call(t, s, "list_assets", `{"kind":"hosts"}`); err == nil || !strings.Contains(err.Error(), "kind must be") {
		t.Errorf("bad kind = %v", err)
	}
	if _, err := call(t, s, "list_assets", `{"kind":"assets","limit":999}`); err == nil {
		t.Error("large limit accepted")
	}
	if _, err := call(t, s, "list_assets", `[1]`); err == nil {
		t.Error("bad args accepted")
	}
	f.status("/api/lookups/assets", 500, `{}`)
	if _, err := call(t, s, "list_assets", `{"kind":"assets"}`); err == nil {
		t.Error("api error not returned")
	}
}

func TestLookupEntity(t *testing.T) {
	f, s := newFakeAPI(t)
	f.json("/api/lookups/context", `{"priority":"high"}`)
	out, err := call(t, s, "lookup_entity", `{"kind":"system","value":"10.0.0.1"}`)
	if err != nil {
		t.Fatal(err)
	}
	if q := f.query("/api/lookups/context"); q.Get("field") != "dest" || q.Get("value") != "10.0.0.1" || asMap(t, out)["priority"] != "high" {
		t.Errorf("system = %v %v", q, out)
	}
	if _, err := call(t, s, "lookup_entity", `{"kind":"user","value":"vera"}`); err != nil || f.query("/api/lookups/context").Get("field") != "user" {
		t.Errorf("user lookup: %v", err)
	}
	f.status("/api/lookups/context", 404, `{"error":"not found"}`)
	out, err = call(t, s, "lookup_entity", `{"kind":"user","value":"ghost"}`)
	if err != nil {
		t.Fatal(err)
	}
	if m := asMap(t, out); m["found"] != false || !strings.Contains(m["note"].(string), "ghost") {
		t.Errorf("not found = %v", m)
	}
	f.status("/api/lookups/context", 500, `{"error":"down"}`)
	if _, err := call(t, s, "lookup_entity", `{"kind":"user","value":"x"}`); err == nil || err.Error() != "down" {
		t.Errorf("server error = %v", err)
	}
	if _, err := call(t, s, "lookup_entity", `{"kind":"group","value":"x"}`); err == nil {
		t.Error("bad kind accepted")
	}
	if _, err := call(t, s, "lookup_entity", `{"kind":"user"}`); err == nil {
		t.Error("missing value accepted")
	}
	if _, err := call(t, s, "lookup_entity", `5`); err == nil {
		t.Error("bad args accepted")
	}
}

func TestRiskAndIntel(t *testing.T) {
	f, s := newFakeAPI(t)
	f.json("/api/risk", `{"objects":[]}`)
	f.json("/api/risk/object", `{"events":[]}`)
	f.json("/api/intel/lookup", `{"match":true}`)
	if _, err := call(t, s, "risk_objects", `{"since":"7d","type":"user"}`); err != nil {
		t.Fatal(err)
	}
	if q := f.query("/api/risk"); q.Get("since") != "7d" || q.Get("type") != "user" {
		t.Errorf("risk query = %v", q)
	}
	if _, err := call(t, s, "risk_objects", ""); err != nil || len(f.query("/api/risk")) != 0 {
		t.Errorf("risk defaults: %v %v", err, f.query("/api/risk"))
	}
	if _, err := call(t, s, "risk_object", `{"object":"vera","type":"user","since":"1d"}`); err != nil {
		t.Fatal(err)
	}
	if q := f.query("/api/risk/object"); q.Get("object") != "vera" || q.Get("type") != "user" || q.Get("since") != "1d" {
		t.Errorf("risk object query = %v", q)
	}
	if _, err := call(t, s, "risk_object", `{"type":"user"}`); err == nil {
		t.Error("missing object accepted")
	}
	out, err := call(t, s, "intel_lookup", `{"value":"evil.example"}`)
	if err != nil || asMap(t, out)["match"] != true || f.query("/api/intel/lookup").Get("value") != "evil.example" {
		t.Errorf("intel = %v %v", out, err)
	}
	if _, err := call(t, s, "intel_lookup", `{}`); err == nil {
		t.Error("missing value accepted")
	}
	for _, tool := range []string{"risk_objects", "risk_object", "intel_lookup"} {
		if _, err := call(t, s, tool, `"x"`); err == nil {
			t.Errorf("%s bad args accepted", tool)
		}
	}
}

func TestClientErrors(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/html":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<html>")
		case "/api/badjson":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, "{")
		case "/api/pwchange":
			w.WriteHeader(403)
			io.WriteString(w, `{"code":"password_change_required"}`)
		case "/api/empty":
			w.WriteHeader(502)
		case "/api/agent":
			io.WriteString(w, `{"ua":"`+r.UserAgent()+`","ct":"`+r.Header.Get("Content-Type")+`"}`)
		}
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	c := &Client{BaseURL: u, User: "u", Password: "p", HTTP: ts.Client(), UserAgent: "signalith-mcp/test"}
	var out map[string]any
	if err := c.Get(ctx, "/api/html", nil, &out); err == nil || !strings.Contains(err.Error(), "did not answer like a Signalith server") {
		t.Errorf("html = %v", err)
	}
	if err := c.Get(ctx, "/api/badjson", nil, &out); err == nil || !strings.Contains(err.Error(), "reading Signalith's answer") {
		t.Errorf("bad json = %v", err)
	}
	var ae *APIError
	if err := c.Get(ctx, "/api/pwchange", nil, nil); !errors.As(err, &ae) || ae.Code != "password_change_required" || !strings.Contains(ae.Error(), "new password") {
		t.Errorf("password change = %v", err)
	}
	if err := c.Get(ctx, "/api/empty", nil, nil); !errors.As(err, &ae) || ae.Msg != "Signalith answered 502 Bad Gateway" {
		t.Errorf("empty = %v", err)
	}
	if err := c.Get(ctx, "/api/agent", nil, &out); err != nil || out["ua"] != "signalith-mcp/test" || out["ct"] != "" {
		t.Errorf("agent = %v %v", out, err)
	}
	if err := c.Post(ctx, "/api/search", func() {}, nil); err == nil {
		t.Error("unmarshalable body accepted")
	}
	if err := c.Get(ctx, "login", nil, nil); err == nil {
		t.Error("non-API path accepted")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.Get(cctx, "/api/agent", nil, nil); err == nil || !strings.Contains(err.Error(), "could not reach Signalith") {
		t.Errorf("cancelled = %v", err)
	}
}
