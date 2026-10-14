package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// memSettings is a SettingsStore that keeps the shared layer of one
// server in memory, as clustercfg.Save would in OpenSearch, with a
// revision per setting (own counts a server's own settings') that a save
// naming another is refused for.
type memSettings struct {
	mu       sync.Mutex
	sh       *config.Shared
	own      map[string]int64
	writable error
}

func newMemSettings() *memSettings {
	return &memSettings{sh: (&config.Shared{Self: "siem-a", Server: map[string]*config.PageEntry{}}).Clone()}
}

func (m *memSettings) Shared() bool { return true }
func (m *memSettings) Writable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writable
}
func (m *memSettings) Self() string    { return "n_a" }
func (m *memSettings) ETag() string    { return `"1"` }
func (m *memSettings) Revision() int64 { return 0 }

func (m *memSettings) Layer(context.Context, string) (*config.Shared, *shared.NodeCfg, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sh.Clone(), nil, nil
}

func (m *memSettings) Save(_ context.Context, by, _ string, _ *config.Shared, res *config.SharedEditResult, versions map[string]int64) (map[string]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range res.Touched {
		rev := m.sh.Rev(k)
		if res.Scope == config.ScopeServer {
			rev = m.own[k]
		}
		if want, listed := versions[k]; listed && want != rev {
			from := m.sh.Cluster[k].From
			return nil, &shared.StaleError{By: from.By, Node: from.Node, At: from.At.UTC().Format(time.RFC3339)}
		}
	}
	revs := map[string]int64{}
	for _, k := range res.Touched {
		if res.Scope == config.ScopeServer {
			if m.own == nil {
				m.own = map[string]int64{}
			}
			m.own[k]++
			revs[k] = m.own[k]
			if e, ok := res.Shared.Server[k]; ok && e != nil {
				m.sh.Server[k] = e
			} else {
				delete(m.sh.Server, k)
			}
			continue
		}
		if v, ok := res.Shared.Cluster[k]; ok {
			v.Rev = m.sh.Rev(k) + 1
			v.From = config.Source{Kind: config.FromPage, By: by, Node: "siem-b", At: time.Now()}
			m.sh.Cluster[k] = v
			revs[k] = v.Rev
		} else if _, ok := m.sh.Cluster[k]; ok {
			if m.sh.Revs == nil {
				m.sh.Revs = map[string]int64{}
			}
			m.sh.Revs[k] = m.sh.Rev(k) + 1
			delete(m.sh.Cluster, k)
			revs[k] = m.sh.Revs[k]
		}
	}
	return revs, nil
}

func (m *memSettings) Check(context.Context, string, string, clustercfg.SettingsCheckArgs) (*clustercfg.SettingsCheckResult, bool, error) {
	return nil, false, nil
}

func (m *memSettings) Restart(context.Context, string, []string, bool) (*shared.Request, error) {
	return nil, errors.New("no other servers")
}

// W28: with the settings shared, saving trusted proxies that leave out
// the one the request came through is still refused, and listing it
// saves the shared value.
func TestSharedTrustedProxiesLockout(t *testing.T) {
	mem := newMemSettings()
	ts, srv, _ := newSettingsServer(t, "", func(s *Server) { s.Settings = mem })
	plain := httptest.NewServer(srv.PlainHandler(srv.Handler()))
	defer plain.Close()
	viaProxy := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, plain.URL+path, strings.NewReader(body))
		req.SetBasicAuth("admin", "s3cret-pass")
		req.Host = "siem.lan"
		req.Header.Set("X-Forwarded-Proto", "https")
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	code, view := viaProxy("GET", "/api/settings", "")
	if code != http.StatusOK || view["shared"] != true {
		t.Fatalf("the shared page: %d %v", code, view["shared"])
	}
	if f := field(t, view, "server.trusted_proxies"); f["scope"] != "cluster" {
		t.Errorf("trusted proxies %v", f)
	}
	code, out := viaProxy("PUT", "/api/settings", `{"values":{"server.trusted_proxies":["10.0.0.9"]}}`)
	fields, _ := out["fields"].(map[string]any)
	if msg, _ := fields["server.trusted_proxies"].(string); code != http.StatusBadRequest || !strings.Contains(msg, "through the reverse proxy at 127.0.0.1") {
		t.Fatalf("a list without the proxy: %d %v", code, out)
	}
	if _, ok := mem.sh.Cluster["server.trusted_proxies"]; ok {
		t.Fatal("the refused list was saved")
	}
	code, out = viaProxy("PUT", "/api/settings", `{"values":{"server.trusted_proxies":["127.0.0.1","10.0.0.9"]}}`)
	if code != http.StatusOK || !slices.Contains(toList(out["applied"]), "server.trusted_proxies") {
		t.Fatalf("listing the proxy: %d %v", code, out)
	}
	if v := mem.sh.Cluster["server.trusted_proxies"]; string(v.Value) != `["127.0.0.1","10.0.0.9"]` || v.Rev != 1 {
		t.Errorf("shared value %s rev %d", v.Value, v.Rev)
	}
	_ = ts
}

// W25, the page's part: while the shared settings cannot be changed
// (OpenSearch refuses writes), a change of a shared setting or of this
// server's own is answered 503 and nothing is saved; one of the settings
// this server needs to reach OpenSearch is saved in its settings.yaml.
func TestSharedSettingsWhileDegraded(t *testing.T) {
	mem := newMemSettings()
	mem.writable = &shared.PausedError{Why: "OpenSearch refuses writes"}
	ts, srv, _ := newSettingsServer(t, "", func(s *Server) { s.Settings = mem })
	code, view := do(t, ts, "GET", "/api/settings", "", true)
	if code != http.StatusOK || view["writable"] != false || !strings.Contains(view["paused"].(string), "OpenSearch refuses writes") {
		t.Fatalf("page: %d writable %v paused %v", code, view["writable"], view["paused"])
	}
	for _, body := range []string{`{"values":{"auth.session_timeout":"2h"}}`, `{"values":{"syslog.udp":"127.0.0.1:5514"}}`} {
		if code, out := do(t, ts, "PUT", "/api/settings", body, true); code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d %v", body, code, out)
		}
	}
	if len(mem.sh.Cluster) != 0 || len(mem.sh.Server) != 0 {
		t.Errorf("saved while paused: %v %v", mem.sh.Cluster, mem.sh.Server)
	}
	code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"opensearch.username":"siem"}}`, true)
	if code != http.StatusOK || !slices.Contains(toList(out["saved"]), "opensearch.username") {
		t.Fatalf("a connection setting: %d %v", code, out)
	}
	page, err := config.ReadPageSettings(srv.Config.SettingsFile())
	if err != nil || page.Settings["opensearch.username"] == nil {
		t.Fatalf("settings.yaml: %v %v", page, err)
	}
}

// toList turns a JSON list into strings.
func toList(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// W28 from another server's page: a change of a shared setting saved
// there applies here too, so it is checked against the proxy the request
// came through all the same.
func TestSharedTrustedProxiesLockoutFromOtherPage(t *testing.T) {
	mem := newMemSettings()
	_, srv, _ := newSettingsServer(t, "", func(s *Server) { s.Settings, s.Cluster = mem, &fakeCluster{holder: "siem-a"} })
	plain := httptest.NewServer(srv.PlainHandler(srv.Handler()))
	defer plain.Close()
	put := func(body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest("PUT", plain.URL+"/api/settings", strings.NewReader(body))
		req.SetBasicAuth("admin", "s3cret-pass")
		req.Host = "siem.lan"
		req.Header.Set("X-Forwarded-Proto", "https")
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	code, out := put(`{"server":"siem-a","values":{"server.trusted_proxies":["10.0.0.9"]}}`)
	fields, _ := out["fields"].(map[string]any)
	if msg, _ := fields["server.trusted_proxies"].(string); code != http.StatusBadRequest || !strings.Contains(msg, "through the reverse proxy at 127.0.0.1") {
		t.Fatalf("a list without the proxy, saved on siem-a's page: %d %v", code, out)
	}
	if _, ok := mem.sh.Cluster["server.trusted_proxies"]; ok {
		t.Fatal("the refused list was saved")
	}
	if code, out := put(`{"server":"siem-a","values":{"server.trusted_proxies":["127.0.0.1","10.0.0.9"]}}`); code != http.StatusOK {
		t.Fatalf("listing the proxy: %d %v", code, out)
	}
}

// W6, the page's part: two saves of one shared setting from pages that
// read the same revision: the second is answered 412 saying who changed
// it, on which server and when; a save of another setting lands. A save
// whose shared part was written before its own part was refused says
// which were saved.
func TestSharedSettingsStale(t *testing.T) {
	mem := newMemSettings()
	ts, _, _ := newSettingsServer(t, "", func(s *Server) { s.Settings = mem })
	code, view := do(t, ts, "GET", "/api/settings", "", true)
	if code != http.StatusOK {
		t.Fatalf("page: %d %v", code, view)
	}
	if v := field(t, view, "auth.session_timeout")["version"]; v != float64(0) {
		t.Fatalf("version %v", v)
	}
	if code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"auth.session_timeout":"2h"},"if_version":{"auth.session_timeout":0}}`, true); code != http.StatusOK {
		t.Fatalf("first save: %d %v", code, out)
	}
	code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"auth.session_timeout":"3h"},"if_version":{"auth.session_timeout":0}}`, true)
	if code != http.StatusPreconditionFailed || out["code"] != "stale" || out["changed_by"] != "admin" || out["changed_on"] != "siem-b" || out["changed_at"] == nil {
		t.Fatalf("second save of the same setting: %d %v", code, out)
	}
	if _, ok := out["saved"]; ok {
		t.Errorf("nothing was saved, yet: %v", out["saved"])
	}
	if code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"search.max_events":777},"if_version":{"search.max_events":0}}`, true); code != http.StatusOK {
		t.Fatalf("a save of another setting: %d %v", code, out)
	}
	if string(mem.sh.Cluster["auth.session_timeout"].Value) != `"2h"` || string(mem.sh.Cluster["search.max_events"].Value) != "777" {
		t.Errorf("shared values %v", mem.sh.Cluster)
	}
	code, out = do(t, ts, "PUT", "/api/settings", `{"values":{"search.default_earliest":"-4h","server.max_connections":50},"if_version":{"search.default_earliest":0,"server.max_connections":3}}`, true)
	if code != http.StatusPreconditionFailed || !slices.Equal(toList(out["saved"]), []string{"search.default_earliest"}) {
		t.Fatalf("a save refused after its shared part: %d %v", code, out)
	}
}

// W12, the page's part: a server's own setting changed on the page whose
// signalith.yaml says otherwise shows the page's value, and what Reset
// goes back to: signalith.yaml's.
func TestSharedServerSettingHandEdited(t *testing.T) {
	mem := newMemSettings()
	e := &config.PageEntry{ChangedBy: "bob", ChangedAt: time.Now()}
	if err := e.Value.Encode("0.0.0.0:7443"); err != nil {
		t.Fatal(err)
	}
	mem.sh.Server["server.listen"] = e
	ts, _, _ := newSettingsServer(t, "server:\n  listen: 0.0.0.0:9443\n", func(s *Server) { s.Settings = mem })
	code, view := do(t, ts, "GET", "/api/settings", "", true)
	if code != http.StatusOK {
		t.Fatalf("page: %d %v", code, view)
	}
	f := field(t, view, "server.listen")
	src, _ := f["source"].(map[string]any)
	reset, _ := f["reset_to"].(map[string]any)
	if f["value"] != "0.0.0.0:7443" || src["kind"] != "page" || reset["value"] != "0.0.0.0:9443" || reset["source"] != "file" {
		t.Errorf("listen field %v", f)
	}
}

// A shared setting that waits for a restart is said to be applied only on
// a server known to run it: not on one offline, nor on one whose last
// heartbeat had not seen the settings' revision yet.
func TestSharedServerStates(t *testing.T) {
	servers := []sharedServer{
		{Name: "siem-a", Self: true, SettingsRev: &cluster.SettingsRev{Settings: 7}},
		{Name: "siem-b", SettingsRev: &cluster.SettingsRev{Settings: 6}},
		{Name: "siem-c", Offline: true, SettingsRev: &cluster.SettingsRev{Settings: 7}},
		{Name: "siem-d", SettingsRev: &cluster.SettingsRev{Settings: 7}, Refused: []string{"syslog.allow"}},
		{Name: "siem-e", SettingsRev: &cluster.SettingsRev{Settings: 7}, RestartNeeded: []string{"syslog.allow"}},
		{Name: "siem-f"},
	}
	want := map[string]string{"siem-a": "applied", "siem-b": "waiting", "siem-c": "offline", "siem-d": "refused", "siem-e": "waiting", "siem-f": "waiting"}
	if got := serverStates(servers, "syslog.allow", 7); !reflect.DeepEqual(got, want) {
		t.Errorf("states %v, want %v", got, want)
	}
}

// The values a server had before its settings were shared are shown with
// the passwords in their addresses hidden.
func TestMigratedViewHidesPasswords(t *testing.T) {
	list := migratedView([]shared.MigratedValue{
		{Key: "assistant.url", Value: json.RawMessage(`"https://user:pw@llm.internal/v1"`), Shared: json.RawMessage(`"https://bob:pw2@llm.example/v1"`)},
		{Key: "search.max_events", Value: json.RawMessage(`300`), Shared: json.RawMessage(`2000`)},
	})
	for _, m := range list {
		if strings.Contains(string(m.Value)+string(m.Shared), "pw") {
			t.Errorf("%s: %s / %s", m.Key, m.Value, m.Shared)
		}
	}
	if string(list[1].Value) != "300" || string(list[1].Shared) != "2000" {
		t.Errorf("max events %s / %s", list[1].Value, list[1].Shared)
	}
}
