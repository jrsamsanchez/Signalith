package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/users"
	"gopkg.in/yaml.v3"
)

// logBuffer collects log lines from request goroutines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeRestarter records restarts instead of doing them.
type fakeRestarter struct {
	mu        sync.Mutex
	calls     []string
	localOnly []bool
	busy      bool
	awaiting  bool
	confirms  int
}

func (f *fakeRestarter) Restart(by, client string, localOnly bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.busy {
		return ErrRestarting
	}
	if f.awaiting {
		return ErrAwaitingMove
	}
	f.calls = append(f.calls, by)
	f.localOnly = append(f.localOnly, localOnly)
	return nil
}

func (f *fakeRestarter) RestartStatus() RestartStatus {
	return RestartStatus{Last: &RestartResult{OK: false, Error: "OpenSearch did not answer", Keys: []string{"opensearch.url"}}}
}

func (f *fakeRestarter) Confirm(*http.Request) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confirms++
	return false
}

// newSettingsServer starts a server whose config is loaded from a
// signalith.yaml in a temporary folder, with extra YAML in it.
func newSettingsServer(t *testing.T, extra string, change func(*Server)) (*httptest.Server, *Server, *logBuffer) {
	t.Helper()
	dir := t.TempDir()
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "signalith.yaml")
	body := "auth:\n  admin_password_hash: " + h + "\ningest:\n  tokens: [tok-0123456789abcdef]\n" + extra
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	logs := &logBuffer{}
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Config = cfg
		s.Engine.Opt.DefaultEarliest, s.Engine.Opt.MaxEvents = cfg.Search.DefaultEarliest, cfg.Search.MaxEvents
		s.Log = slog.New(slog.NewTextHandler(logs, nil))
		s.Users = users.NewMemory()
		s.Users.Create(context.Background(), users.NewUser{Username: "andy", Role: users.Analyst, Password: "role-password"})
		srv = s
		if change != nil {
			change(s)
		}
	})
	return ts, srv, logs
}

// field finds a setting in GET /api/settings.
func field(t *testing.T, view map[string]any, key string) map[string]any {
	t.Helper()
	for _, sec := range view["sections"].([]any) {
		for _, f := range sec.(map[string]any)["fields"].([]any) {
			if fm := f.(map[string]any); fm["key"] == key {
				return fm
			}
		}
	}
	t.Fatalf("no field %s", key)
	return nil
}

func TestSettingsRoutesAreAdminOnly(t *testing.T) {
	ts, _, _ := newSettingsServer(t, "", nil)
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/settings"}, {"PUT", "/api/settings"}, {"POST", "/api/settings/test/opensearch"},
		{"POST", "/api/settings/test/assistant"}, {"POST", "/api/settings/restart"}, {"POST", "/api/settings/restart/confirm"},
		{"GET", "/api/settings/export"},
	} {
		if code, out := doAs(t, ts, "andy", "role-password", rt.method, rt.path, "{}"); code != 403 || out["code"] != "forbidden" {
			t.Errorf("analyst %s %s: %d %v", rt.method, rt.path, code, out)
		}
		if code, _ := do(t, ts, rt.method, rt.path, "{}", false); code != 401 {
			t.Errorf("signed out %s %s: %d", rt.method, rt.path, code)
		}
	}
	// A browser on another site cannot save.
	req, _ := http.NewRequest("PUT", ts.URL+"/api/settings", strings.NewReader(`{"values":{"search.max_events":5}}`))
	req.SetBasicAuth("admin", "s3cret-pass")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("cross-site save: %d", resp.StatusCode)
	}
}

func TestGetSettings(t *testing.T) {
	t.Setenv("SIGNALITH_LISTEN", "127.0.0.1:8099")
	ts, _, _ := newSettingsServer(t, "opensearch:\n  url: https://os.example:9200\n  password: hunter2-secret\nsearch:\n  max_events: 777\n", nil)
	code, view, raw := call(t, ts, "GET", "/api/settings", "", "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("%d %s", code, raw)
	}
	if strings.Contains(raw, "hunter2-secret") {
		t.Fatal("GET /api/settings returned a secret")
	}
	if n := len(view["sections"].([]any)); n != 10 {
		t.Errorf("sections %d", n)
	}
	pw := field(t, view, "opensearch.password")
	if pw["value"] != nil || pw["set"] != true || pw["sent_to"] != "https://os.example:9200" || pw["type"] != "secret" {
		t.Errorf("password field %v", pw)
	}
	listen := field(t, view, "server.listen")
	if listen["locked"] != true || !strings.Contains(listen["locked_reason"].(string), "SIGNALITH_LISTEN") ||
		listen["source"].(map[string]any)["env"] != "SIGNALITH_LISTEN" || listen["apply"] != "restart" || listen["dangerous"] != true {
		t.Errorf("listen field %v", listen)
	}
	if f := field(t, view, "search.max_events"); f["value"] != float64(777) || f["source"].(map[string]any)["kind"] != "file" || f["apply"] != "live" {
		t.Errorf("max events %v", f)
	}
	if f := field(t, view, "search.default_earliest"); f["source"].(map[string]any)["kind"] != "default" || len(f["choices"].([]any)) == 0 {
		t.Errorf("earliest %v", f)
	}
	if f := field(t, view, "opensearch.tls_skip_verify"); f["confirm_when"] != "on" || f["confirm"] == "" {
		t.Errorf("skip verify %v", f)
	}
	about := view["about"].(map[string]any)
	if about["ingest_tokens"] != float64(1) || len(about["paths"].([]any)) != 11 {
		t.Errorf("about %v", about)
	}
	restart := view["restart"].(map[string]any)
	if restart["available"] != false || restart["unavailable"] == nil || restart["needed"] != false {
		t.Errorf("restart %v", restart)
	}
	if len(view["pending"].([]any)) != 0 || view["editable"] != true {
		t.Errorf("pending %v editable %v", view["pending"], view["editable"])
	}
}

func TestSaveSettings(t *testing.T) {
	ts, srv, logs := newSettingsServer(t, "server:\n  listen: 127.0.0.1:8080\n  tls:\n    mode: off\n", nil)
	put := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "PUT", "/api/settings", body, "admin", "s3cret-pass", nil)
		return code, out
	}
	// Problems come back by field, and nothing is written.
	code, out := put(`{"values":{"search.max_events":0,"server.listen":"nowhere","server.tls.mode":"files"}}`)
	fields, _ := out["fields"].(map[string]any)
	if code != 400 || len(fields) < 3 || !strings.Contains(fields["server.tls_cert"].(string), "certificate file") {
		t.Fatalf("bad save %d %v", code, out)
	}
	file := srv.Config.SettingsFile()
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("a bad save wrote %s", file)
	}
	// Live settings apply at once; the others wait for a restart.
	code, out = put(`{"values":{"auth.session_timeout":"30m","search.max_events":1234,"search.default_earliest":"-7d",
		"server.public_url":"https://siem.example.com:8443","detections.max_findings_per_run":7}}`)
	if code != 200 {
		t.Fatalf("save %d %v", code, out)
	}
	if got := out["applied"].([]any); len(got) != 5 || len(out["after_restart"].([]any)) != 0 {
		t.Errorf("applied %v after restart %v", got, out["after_restart"])
	}
	if srv.Sessions.Idle != 30*time.Minute || srv.Engine.Opt.MaxEvents != 1234 || srv.Engine.Opt.DefaultEarliest != "-7d" ||
		srv.Scheduler.MaxFindingsPerRun != 7 || srv.conf().Server.PublicURL != "https://siem.example.com:8443" {
		t.Errorf("not live: idle %v engine %+v cap %d url %s", srv.Sessions.Idle, srv.Engine.Opt, srv.Scheduler.MaxFindingsPerRun, srv.conf().Server.PublicURL)
	}
	// The agent setup uses the new public address right away.
	if code, cfg := do(t, ts, "GET", "/api/agents/config?os=linux", "", true); code != 200 || !strings.Contains(cfg["config"].(string), "siem.example.com") {
		t.Errorf("agent config %d %v", code, cfg["config"])
	}
	code, out = put(`{"values":{"server.listen":"0.0.0.0:9090","opensearch.index_prefix":"siem2"}}`)
	if code != 200 {
		t.Fatalf("save %d %v", code, out)
	}
	if got := out["after_restart"].([]any); len(got) != 2 || len(out["applied"].([]any)) != 0 {
		t.Errorf("after restart %v applied %v", got, out["applied"])
	}
	if srv.conf().Server.Listen != "127.0.0.1:8080" || srv.conf().OpenSearch.IndexPrefix != "signalith" {
		t.Errorf("restart settings applied early: %s %s", srv.conf().Server.Listen, srv.conf().OpenSearch.IndexPrefix)
	}
	// With a new listen address waiting for the restart, a new public
	// address waits too: agents set up now would otherwise be pointed at
	// an address nothing answers yet.
	code, out = put(`{"values":{"server.public_url":"https://siem2.example.com:9090"}}`)
	if code != 200 || len(out["after_restart"].([]any)) != 1 || srv.conf().Server.PublicURL != "https://siem.example.com:8443" {
		t.Errorf("public address with a pending listen %d %v %s", code, out["after_restart"], srv.conf().Server.PublicURL)
	}
	pending := out["pending"].([]any)
	if len(pending) != 3 {
		t.Fatalf("pending %v", pending)
	}
	if p := pending[1].(map[string]any); p["key"] != "server.listen" || p["old"] != "127.0.0.1:8080" || p["new"] != "0.0.0.0:9090" {
		t.Errorf("pending %v", p)
	}
	if f := field(t, out, "server.listen"); f["pending"] != true || f["source"].(map[string]any)["kind"] != "page" ||
		f["source"].(map[string]any)["by"] != "admin" || f["reset_to"].(map[string]any)["value"] != "127.0.0.1:8080" ||
		f["reset_to"].(map[string]any)["source"] != "file" {
		t.Errorf("listen after save %v", f)
	}
	if fi, err := os.Stat(file); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("settings file %v %v", fi, err)
	}
	if l := logs.String(); !strings.Contains(l, `msg="settings saved"`) || !strings.Contains(l, "search.max_events=1234") || !strings.Contains(l, "by=admin") {
		t.Errorf("audit log:\n%s", l)
	}
	// Reset goes back to signalith.yaml.
	code, out = put(`{"reset":["server.listen","auth.session_timeout"]}`)
	if code != 200 || field(t, out, "server.listen")["source"].(map[string]any)["kind"] != "file" || srv.Sessions.Idle != 12*time.Hour {
		t.Errorf("reset %d %v idle %v", code, field(t, out, "server.listen"), srv.Sessions.Idle)
	}
	// The listen address is back to the one in use, so it needs no restart.
	if got := out["after_restart"].([]any); len(got) != 0 || out["applied"].([]any)[0] != "auth.session_timeout" {
		t.Errorf("after a reset: after restart %v applied %v", got, out["applied"])
	}
	// The public address worked out from the listen address waits for the
	// restart that moves the listener.
	_, out = put(`{"reset":["server.public_url"],"values":{"server.listen":"127.0.0.1:9191"}}`)
	if srv.conf().Server.PublicURL != "https://siem.example.com:8443" {
		t.Errorf("public url changed before the restart: %s", srv.conf().Server.PublicURL)
	}
	// The page shows it empty, with what it works out to.
	if f := field(t, out, "server.public_url"); f["value"] != "" || f["empty_means"] != "http://127.0.0.1:9191, worked out from the listen address" {
		t.Errorf("worked-out public url %v", f)
	}
	// Reset all removes the file.
	if code, _ := put(`{"reset_all":true}`); code != 200 {
		t.Errorf("reset all %d", code)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("reset all left %s", file)
	}
}

func TestSaveSettingsSecrets(t *testing.T) {
	ts, srv, logs := newSettingsServer(t, "opensearch:\n  url: https://os1.example:9200\n  password: file-secret\n", nil)
	put := func(body string) (int, map[string]any, string) {
		t.Helper()
		return call(t, ts, "PUT", "/api/settings", body, "admin", "s3cret-pass", nil)
	}
	code, out, _ := put(`{"values":{"opensearch.url":"https://os2.example:9200"}}`)
	if code != 400 || !strings.Contains(out["fields"].(map[string]any)["opensearch.password"].(string), "Enter the password again") {
		t.Fatalf("moved without password: %d %v", code, out)
	}
	code, _, raw := put(`{"values":{"opensearch.url":"https://os2.example:9200","opensearch.password":"page-secret"}}`)
	if code != 200 || strings.Contains(raw, "page-secret") {
		t.Fatalf("save %d (secret in answer: %v)", code, strings.Contains(raw, "page-secret"))
	}
	if strings.Contains(logs.String(), "page-secret") || !strings.Contains(logs.String(), "opensearch.password=(changed)") {
		t.Errorf("log:\n%s", logs.String())
	}
	saved, _ := config.Load(srv.Config.Path())
	if saved.OpenSearch.Password != "page-secret" {
		t.Errorf("saved %q", saved.OpenSearch.Password)
	}
	data, _ := os.ReadFile(saved.SettingsFile())
	if !strings.Contains(string(data), "sent_to: https://os2.example:9200") {
		t.Errorf("file:\n%s", data)
	}
	// Clearing it removes it.
	code, out, _ = put(`{"clear":["opensearch.password"]}`)
	if f := field(t, out, "opensearch.password"); code != 200 || f["set"] != false {
		t.Errorf("clear %d %v", code, f)
	}
}

// fakeOpenSearch answers the calls a connection test makes.
func fakeOpenSearch(t *testing.T, user, pass string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != user || p != pass {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":{"type":"security_exception","reason":"unauthorized"}}`))
			return
		}
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`{"name":"node-1","cluster_name":"soc","version":{"number":"2.17.1","distribution":"opensearch"}}`))
		case "/_cluster/health":
			w.Write([]byte(`{"status":"yellow"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestTestOpenSearch(t *testing.T) {
	os1 := fakeOpenSearch(t, "signalith", "right")
	ts, _, logs := newSettingsServer(t, "opensearch:\n  url: "+os1.URL+"\n  username: signalith\n  password: right\n", nil)
	test := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "POST", "/api/settings/test/opensearch", body, "admin", "s3cret-pass", nil)
		return code, out
	}
	// The saved settings, password included, for the saved server.
	if code, out := test(`{}`); code != 200 || out["ok"] != true || out["cluster_name"] != "soc" || out["version"] != "2.17.1" || out["health"] != "yellow" {
		t.Errorf("saved %d %v", code, out)
	}
	// Form values, saved or not.
	if code, out := test(`{"values":{"opensearch.password":"wrong"}}`); code != 200 || out["ok"] != false || out["problem"] != "auth" {
		t.Errorf("wrong password %d %v", code, out)
	}
	if code, out := test(`{"clear":["opensearch.password"],"values":{"opensearch.username":""}}`); code != 200 || out["problem"] != "auth" || !strings.Contains(out["message"].(string), "asks for a username") {
		t.Errorf("no password %d %v", code, out)
	}
	// Nothing listening.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := "http://" + ln.Addr().String()
	ln.Close()
	if code, out := test(`{"values":{"opensearch.url":"` + closed + `","opensearch.password":"x"}}`); code != 200 || out["problem"] != "unreachable" || out["reached"] != false {
		t.Errorf("closed port %d %v", code, out)
	}
	// HTTPS against a plain HTTP server.
	if code, out := test(`{"values":{"opensearch.url":"` + strings.Replace(os1.URL, "http:", "https:", 1) + `","opensearch.password":"right"}}`); code != 200 || out["problem"] != "http" {
		t.Errorf("https to http %d %v", code, out)
	}
	// The saved password is never sent to another server.
	os2 := fakeOpenSearch(t, "signalith", "right")
	code, out := test(`{"values":{"opensearch.url":"` + os2.URL + `"}}`)
	if code != 400 || !strings.Contains(out["fields"].(map[string]any)["opensearch.password"].(string), "Enter the password again") {
		t.Errorf("other server %d %v", code, out)
	}
	if !strings.Contains(logs.String(), `msg="settings tested" audit=true by=admin`) || strings.Contains(logs.String(), "right") {
		t.Errorf("log:\n%s", logs.String())
	}
}

func TestTestAssistant(t *testing.T) {
	var gotKey string
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		if gotKey != "good-key" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":{"message":"invalid x-api-key"}}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "text", "text": "datamodel=Authentication action=failure earliest=-24h"}}})
	}))
	defer model.Close()
	ts, _, _ := newSettingsServer(t, "", nil)
	test := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "POST", "/api/settings/test/assistant", body, "admin", "s3cret-pass", nil)
		return code, out
	}
	if code, out := test(`{}`); code != 400 || out["fields"].(map[string]any)["assistant.provider"] == nil {
		t.Errorf("off %d %v", code, out)
	}
	body := `{"values":{"assistant.provider":"anthropic","assistant.url":"` + model.URL + `","assistant.api_key":"good-key"}}`
	if code, out := test(body); code != 200 || out["ok"] != true || out["query"] != "datamodel=Authentication action=failure earliest=-24h" || out["question"] != assistantQuestion {
		t.Errorf("good %d %v", code, out)
	}
	body = strings.Replace(body, "good-key", "bad-key", 1)
	if code, out := test(body); code != 200 || out["ok"] != false || !strings.Contains(out["message"].(string), "refused the API key") {
		t.Errorf("bad key %d %v", code, out)
	}
}

func TestRestartRoute(t *testing.T) {
	ts, srv, _ := newSettingsServer(t, "server:\n  listen: 0.0.0.0:8080\n", nil)
	if code, out := do(t, ts, "POST", "/api/settings/restart", "", true); code != 503 || out["code"] != "restart_unavailable" {
		t.Errorf("no restarter %d %v", code, out)
	}
	r := &fakeRestarter{}
	srv.Restarter = r
	call(t, ts, "PUT", "/api/settings", `{"values":{"server.listen":"0.0.0.0:9443"}}`, "admin", "s3cret-pass", nil)
	code, out := do(t, ts, "POST", "/api/settings/restart", "", true)
	if code != 202 || out["listen_changed"] != true || out["new_listen"] != "0.0.0.0:9443" || !strings.HasSuffix(out["go_to"].(string), ":9443/") || len(r.calls) != 1 {
		t.Errorf("restart %d %v %v", code, out, r.calls)
	}
	_, view := do(t, ts, "GET", "/api/settings", "", true)
	if last := view["restart"].(map[string]any)["last"].(map[string]any); last["ok"] != false || last["error"] == "" {
		t.Errorf("last restart %v", last)
	}
	r.busy = true
	if code, out := do(t, ts, "POST", "/api/settings/restart", "", true); code != 409 || out["code"] != "restarting" {
		t.Errorf("busy %d %v", code, out)
	}
	r.busy = false
	// Settings that do not work together cannot be applied.
	os.WriteFile(srv.Config.SettingsFile(), []byte("settings:\n  search.max_events:\n    value: 0\n"), 0o600)
	if code, out := do(t, ts, "POST", "/api/settings/restart", "", true); code != 409 || out["code"] != "settings_invalid" {
		t.Errorf("invalid %d %v", code, out)
	}
	_, view = do(t, ts, "GET", "/api/settings", "", true)
	if f := field(t, view, "search.max_events"); !strings.Contains(f["problem"].(string), "between 1 and 100000") {
		t.Errorf("problem %v", f)
	}
}

func TestNewAddress(t *testing.T) {
	cfg := func(listen, cert string) *config.Config {
		c := config.Default()
		c.Server.Listen, c.Server.TLSCert, c.Server.TLSKey = listen, cert, cert
		// HTTPS with the certificate, plain HTTP without.
		c.Server.TLS = &config.ServerTLS{Mode: config.TLSOff}
		if cert != "" {
			c.Server.TLS.Mode = config.TLSFiles
		}
		return c
	}
	r := httptest.NewRequest("GET", "http://10.0.0.5:8080/", nil)
	for _, c := range []struct {
		from, to *config.Config
		want     string
	}{
		{cfg("0.0.0.0:8080", ""), cfg("0.0.0.0:8080", ""), ""},
		{cfg("0.0.0.0:8080", ""), cfg("0.0.0.0:9090", ""), "http://10.0.0.5:9090/"},
		{cfg("0.0.0.0:8080", ""), cfg("0.0.0.0:8080", "x.pem"), "https://10.0.0.5:8080/"},
		{cfg("0.0.0.0:8080", ""), cfg("192.0.2.7:8080", ""), "http://192.0.2.7:8080/"},
		{cfg("0.0.0.0:8080", ""), cfg("[::]:8443", "x.pem"), "https://10.0.0.5:8443/"},
	} {
		if got := newAddress(r, c.from, c.to, false); got != c.want {
			t.Errorf("%s -> %s: %q, want %q", c.from.Server.Listen, c.to.Server.Listen, got, c.want)
		}
	}
	// Through a trusted reverse proxy, HTTPS turned on or off leaves the
	// proxy's address as it is; another port is still a move.
	if got := newAddress(r, cfg("127.0.0.1:8080", ""), cfg("127.0.0.1:8080", "x.pem"), true); got != "" {
		t.Errorf("HTTPS on behind a proxy: %q", got)
	}
	if got := newAddress(r, cfg("127.0.0.1:8080", ""), cfg("127.0.0.1:9090", ""), true); got != "http://127.0.0.1:9090/" {
		t.Errorf("another port behind a proxy: %q", got)
	}
}

func TestExportSettings(t *testing.T) {
	ts, _, _ := newSettingsServer(t, "opensearch:\n  password: never-exported\nsyslog:\n  udp: 0.0.0.0:514\n  allow: [10.0.0.0/8]\nassistant:\n  provider: anthropic\n  api_key: sk-never\n", nil)
	code, out, raw := call(t, ts, "GET", "/api/settings/export", "", "admin", "s3cret-pass", nil)
	if code != 200 || strings.Contains(raw, "never-exported") || strings.Contains(raw, "sk-never") {
		t.Fatalf("%d %s", code, raw)
	}
	text := out["yaml"].(string)
	// Settings that belong to this server are marked, so a copy does not,
	// for one, turn on a second job runner; shared ones are not. The
	// public address is marked too: another server set up on its own has
	// its own.
	for _, want := range []string{"syslog:\n", "  udp: 0.0.0.0:514  # this server's own address\n", "  allow: [10.0.0.0/8]\n", "  # password: left out; set it here or with SIGNALITH_OPENSEARCH_PASSWORD\n", "  listen: 127.0.0.1:8080  # this server's own address\n",
		"  public_url: \"\"  # this server's own address\n", "  scheduler: true  # this server only\n", "  ca_file: \"\"  # a file on this server\n", "  max_events: 10000\n",
		"    mode: auto  # this server only\n", "  trusted_proxies: []\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("export lacks %q:\n%s", want, text)
		}
	}
	// It is a valid signalith.yaml.
	var c config.Config
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil || c.Syslog.UDP != "0.0.0.0:514" || c.Assistant.Provider != "anthropic" {
		t.Errorf("does not load: %v %+v", err, c.Syslog)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/settings/export?download=1", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Disposition"), "signalith-settings.yaml") || string(body) != text {
		t.Errorf("download %v", resp.Header)
	}
}

// recordingPages is a PageStore that counts what the Settings page does
// with it.
type recordingPages struct {
	config.PageStore
	reads, writes, checks int
}

func (p *recordingPages) Read() (*config.PageSettings, error) { p.reads++; return p.PageStore.Read() }
func (p *recordingPages) Write(ps *config.PageSettings) error {
	p.writes++
	return p.PageStore.Write(ps)
}
func (p *recordingPages) CheckEdit(e config.Edit) (*config.EditResult, error) {
	p.checks++
	return p.PageStore.CheckEdit(e)
}

// TestSettingsPageUsesItsPageStore checks that saves go through Pages, so
// the settings can be kept somewhere other than the file.
func TestSettingsPageUsesItsPageStore(t *testing.T) {
	var pages *recordingPages
	ts, srv, _ := newSettingsServer(t, "", func(s *Server) {
		pages = &recordingPages{PageStore: config.PageFile{Config: s.Config.Path()}}
		s.Pages = pages
	})
	code, out, _ := call(t, ts, "PUT", "/api/settings", `{"values":{"search.max_events":321}}`, "admin", "s3cret-pass", nil)
	if code != 200 || pages.checks != 1 || pages.writes != 1 {
		t.Fatalf("save %d %v: %+v", code, out, pages)
	}
	if srv.conf().Search.MaxEvents != 321 {
		t.Errorf("not applied: %d", srv.conf().Search.MaxEvents)
	}
	if p, err := (config.PageFile{Config: srv.Config.Path()}).Read(); err != nil || strings.Join(p.Keys(), ",") != "search.max_events" {
		t.Errorf("file: %v %v", p, err)
	}
	// A check-only save writes nothing.
	call(t, ts, "PUT", "/api/settings", `{"values":{"search.max_events":322},"check_only":true}`, "admin", "s3cret-pass", nil)
	if pages.checks != 2 || pages.writes != 1 {
		t.Errorf("check only: %+v", pages)
	}
}

// TestApplyLiveComparesTwoConfigs checks applyLive(old, new) on its own,
// as a change that did not come from this server's page would use it: only
// what differs and applies at once is put into use.
func TestApplyLiveComparesTwoConfigs(t *testing.T) {
	_, srv, _ := newSettingsServer(t, "", nil)
	old := srv.conf()
	next := *old
	next.Search.MaxEvents = 777
	next.Server.Listen = "0.0.0.0:9999" // waits for a restart
	next.Detections.MaxFindingsPerRun = 9
	next.Detections.CatchUp = "0"
	applied := srv.applyLive(old, &next)
	if strings.Join(applied, ",") != "search.max_events,detections.max_findings_per_run,detections.catch_up" {
		t.Errorf("applied %v", applied)
	}
	if srv.Scheduler.CatchUpLimit() != 0 {
		t.Errorf("catching up still goes back %v", srv.Scheduler.CatchUpLimit())
	}
	if srv.conf().Search.MaxEvents != 777 || srv.Engine.Opt.MaxEvents != 777 || srv.Scheduler.MaxFindingsPerRun != 9 {
		t.Errorf("not live: %d %d %d", srv.conf().Search.MaxEvents, srv.Engine.Opt.MaxEvents, srv.Scheduler.MaxFindingsPerRun)
	}
	if srv.conf().Server.Listen == "0.0.0.0:9999" {
		t.Error("a restart setting applied at once")
	}
	// Nothing changed: nothing applies.
	if applied := srv.applyLive(&next, &next); applied != nil {
		t.Errorf("no change applied %v", applied)
	}
}

// eventAge records what the server passes to EventAge.
type eventAge struct{ got []string }

func (e *eventAge) Use(c *config.Config) { e.got = append(e.got, c.Ingest.MaxEventAge) }

// TestMaxEventAgeAppliesAtOnce: ingest.max_event_age is put into use
// without a restart, through EventAge.
func TestMaxEventAgeAppliesAtOnce(t *testing.T) {
	ages := &eventAge{}
	ts, srv, _ := newSettingsServer(t, "", func(s *Server) { s.EventAge = ages })
	code, out, _ := call(t, ts, "PUT", "/api/settings", `{"values":{"ingest.max_event_age":"30d"}}`, "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("save %d %v", code, out)
	}
	if srv.conf().Ingest.MaxEventAge != "30d" || strings.Join(ages.got, ",") != "30d" {
		t.Errorf("not applied: %q %v", srv.conf().Ingest.MaxEventAge, ages.got)
	}
	if pending, _ := out["pending"].([]any); len(pending) != 0 {
		t.Errorf("waits for a restart: %v", out["pending"])
	}
}

func TestAssistantChangesApplyAtOnce(t *testing.T) {
	ts, srv, _ := newSettingsServer(t, "", nil)
	if code, info := do(t, ts, "GET", "/api/ask", "", true); code != 200 || info["ai_available"] != false {
		t.Fatalf("before %d %v", code, info)
	}
	code, out, _ := call(t, ts, "PUT", "/api/settings", `{"values":{"assistant.provider":"openai","assistant.url":"http://127.0.0.1:11434/v1","assistant.model":"llama3.1"}}`, "admin", "s3cret-pass", nil)
	if code != 200 {
		t.Fatalf("save %d %v", code, out)
	}
	if code, info := do(t, ts, "GET", "/api/ask", "", true); info["ai_available"] != true || info["ai_model"] != "llama3.1" {
		t.Errorf("after %d %v", code, info)
	}
	if m := srv.model(); m == nil || m.Provider != assistant.OpenAI {
		t.Errorf("model %+v", m)
	}
	call(t, ts, "PUT", "/api/settings", `{"values":{"assistant.provider":""}}`, "admin", "s3cret-pass", nil)
	if srv.model() != nil {
		t.Error("assistant still on")
	}
}

func TestPublicURLWarning(t *testing.T) {
	load := func(yamlText string) *config.Config {
		t.Helper()
		dir := t.TempDir()
		h, _ := config.HashPassword("s3cret-pass")
		path := filepath.Join(dir, "signalith.yaml")
		if err := os.WriteFile(path, []byte("auth:\n  admin_password_hash: "+h+"\n"+yamlText), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cert, key := selfSigned(t)
	tlsOn := "\n  tls_cert: " + cert + "\n  tls_key: " + key + "\n"
	for _, c := range []struct {
		yaml, warn, suggest string
	}{
		{"server:\n  listen: 0.0.0.0:9090\n", "", ""},
		{"server:\n  listen: 0.0.0.0:9090\n  public_url: http://siem.example.com:9090\n  tls:\n    mode: off\n", "", ""},
		// HTTPS on by default: the same address over https:// is fine.
		{"server:\n  listen: 0.0.0.0:9090\n  public_url: https://siem.example.com:9090\n  tls:\n    mode: auto\n", "", ""},
		{"server:\n  listen: 0.0.0.0:9090\n  public_url: https://siem.example.com\n", "Agents are told to use https:// on port 443, but Signalith answers with http:// on port 9090.", "http://siem.example.com:9090"},
		{"server:\n  listen: 0.0.0.0:443\n  public_url: https://siem.example.com\n", "Agents are told to use https://, but Signalith answers with http://.", "http://siem.example.com:443"},
		{"server:\n  listen: 0.0.0.0:443\n  public_url: https://siem.example.com" + tlsOn, "", ""},
		{"server:\n  listen: 127.0.0.1:18743\n  public_url: http://127.0.0.1:18740\n  tls:\n    mode: off\n", "Agents are told to use port 18740, but Signalith answers on port 18743.", "http://127.0.0.1:18743"},
		// HTTPS turned on while the public address says http://, as
		// signalith init writes it.
		{"server:\n  listen: 127.0.0.1:18725\n  public_url: http://127.0.0.1:18725" + tlsOn, "Agents are told to use http://, but Signalith answers with https://.", "https://127.0.0.1:18725"},
	} {
		w, sg := publicURLWarning(load(c.yaml), false)
		if !strings.HasPrefix(w, c.warn) || (c.warn == "") != (w == "") || sg != c.suggest {
			t.Errorf("%q: %q, suggest %q", c.yaml, w, sg)
		}
	}
	if w, _ := publicURLWarning(load("server:\n  listen: 127.0.0.1:18743\n  public_url: http://127.0.0.1:18740\n  tls:\n    mode: off\n"), true); !strings.Contains(w, "will answer on port 18743") {
		t.Errorf("before the restart: %q", w)
	}
}

func TestBrokenSettingsFileOnThePage(t *testing.T) {
	dir := t.TempDir()
	// The server started while the settings file was broken.
	if err := os.MkdirAll(filepath.Join(dir, "lookups"), 0o750); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "lookups", "settings.yaml")
	os.WriteFile(file, []byte("settings: [not, a, map]\n"), 0o600)
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, []byte("auth:\n  admin_password_hash: "+h+"\n"), 0o600)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("a broken settings file stopped the start: %v", err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Config = cfg })
	_, view := do(t, ts, "GET", "/api/settings", "", true)
	sf := view["settings_file"].(map[string]any)
	// The page words the problem; the file only says what is wrong with it.
	if !strings.Contains(view["startup_problem"].(string), "signalith settings reset") || strings.Contains(sf["error"].(string), file) ||
		sf["error"] != "It is not laid out as Signalith writes it (line 1)." || view["startup_file"] != true || sf["backup"] != file+".broken" {
		t.Errorf("startup problem %q, file %v", view["startup_problem"], sf)
	}
	// Changes cannot be saved over it, but it can be reset as a whole.
	if code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"search.max_events":50}}`, true); code != 409 || out["code"] != "settings_file" {
		t.Errorf("save over a broken file %d %v", code, out)
	}
	if code, out := do(t, ts, "PUT", "/api/settings", `{"reset_all":true}`, true); code != 200 || out["backup"] != file+".broken" {
		t.Errorf("reset all %d %v", code, out)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the broken file is still there: %v", err)
	}
	// What it held is kept next to it.
	if data, err := os.ReadFile(file + ".broken"); err != nil || !strings.Contains(string(data), "not, a, map") {
		t.Errorf("backup %q %v", data, err)
	}
}
