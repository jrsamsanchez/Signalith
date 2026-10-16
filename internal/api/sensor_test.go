package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/deploy"
	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// newSensorServer serves HTTPS with Signalith's own CA, keeps agent
// tokens in a fake OpenSearch (read already) and agents in memory, with
// a viewer (vera) and an analyst (andy).
func newSensorServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	fake := ostest.New(t)
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
		s.Config.Server.TLS = &config.ServerTLS{Mode: "auto"}
		s.TLS = newCertManager(t)
		s.Tokens = &agenttokens.Registry{Client: store.New(store.Config{URL: fake.URL}), Prefix: "st", Log: s.Log}
		s.Agents = &agentinv.Inventory{}
		s.Install = &ClusterInstall{}
		s.Users = users.NewMemory()
		for name, role := range map[string]users.Role{"vera": users.Viewer, "andy": users.Analyst} {
			if _, err := s.Users.Create(context.Background(), users.NewUser{Username: name, Role: role, Password: "role-password"}); err != nil {
				t.Fatal(err)
			}
		}
	})
	if err := srv.Tokens.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return ts, srv
}

func makeToken(t *testing.T, ts *httptest.Server, name, purpose string) (id, secret string) {
	t.Helper()
	code, out, raw := call(t, ts, "POST", "/api/agent-tokens", `{"name":"`+name+`","purpose":"`+purpose+`"}`, "admin", adminPass, nil)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	return out["token"].(map[string]any)["id"].(string), out["secret"].(string)
}

func sensorGet(t *testing.T, ts *httptest.Server, path, token string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

// The script is public, as Add a server's are, and the bytes the line's
// SHA-256 names.
func TestSensorInstallScriptIsPublic(t *testing.T) {
	ts, _ := newSensorServer(t)
	code, h, body := sensorGet(t, ts, "/api/sensor/install.sh", "")
	sum := sha256.Sum256(deploy.SensorInstallSH)
	if code != 200 || body != string(deploy.SensorInstallSH) || h.Get("X-Signalith-SHA256") != hex.EncodeToString(sum[:]) || h.Get("Cache-Control") != "no-store" {
		t.Errorf("install.sh: %d %v", code, h)
	}
}

func TestSensorInstallLine(t *testing.T) {
	ts, s := newSensorServer(t)
	q := url.Values{"server": {"https://siem.example.com:8443"}, "interface": {"ens192"}, "networks": {"10.9.0.0/16"}}
	code, out, raw := call(t, ts, "GET", "/api/sensor/install?"+q.Encode(), "", "admin", adminPass, nil)
	if code != 200 {
		t.Fatalf("install: %d %s", code, raw)
	}
	ca := sha256Hex(s.TLS.Fingerprint())
	line, _ := out["linux"].(string)
	for _, want := range []string{"https://siem.example.com:7779/api/sensor/install.sh", "--role sensor --from https://siem.example.com:7779 --ca-sha256 " + ca,
		"--version test --token -", "--interface ens192", "--networks 10.9.0.0/16", "echo '" + agents.TokenPlaceholder + "'"} {
		if !strings.Contains(line, want) {
			t.Errorf("line has no %q:\n%s", want, line)
		}
	}
	if len(ca) != 64 || out["ca_sha256"] != ca || out["token_placeholder"] != agents.TokenPlaceholder || out["add_name"] != nil || out["script_sha256"] == "" {
		t.Errorf("answer: %v", out)
	}

	// An address the certificate does not cover yet: the page adds it.
	code, out, _ = call(t, ts, "GET", "/api/sensor/install?server=https://10.0.0.5:8080", "", "admin", adminPass, nil)
	if code != 200 || out["add_name"] != "10.0.0.5" {
		t.Errorf("new name: %d %v", code, out)
	}

	// Errors under their field.
	for q, field := range map[string]string{
		"server=http://siem.example.com:8080":                       "server",
		"server=https://siem.example.com&interface=a+b":             "interface",
		"server=https://siem.example.com&networks=x":                "networks",
		"server=https://siem.example.com&zeek=false&suricata=false": "tools",
	} {
		code, out, _ := call(t, ts, "GET", "/api/sensor/install?"+q, "", "admin", adminPass, nil)
		if code != 400 || out["field"] != field {
			t.Errorf("%s: %d %v", q, code, out)
		}
	}
	if _, out, _ := call(t, ts, "GET", "/api/sensor/install?server=http://siem.example.com:8080", "", "admin", adminPass, nil); !strings.Contains(out["error"].(string), "Turn on HTTPS first") {
		t.Errorf("http: %v", out)
	}

	// Admins only: the line is the start of a new agent.
	for _, u := range []string{"vera", "andy"} {
		if code, _, _ := call(t, ts, "GET", "/api/sensor/install?server=https://siem.example.com", "", u, "role-password", nil); code != http.StatusForbidden {
			t.Errorf("%s: %d", u, code)
		}
	}
}

// With HTTPS off (a proxy in front with a public certificate), the line
// pins nothing: the sensor's system trusts the certificate.
func TestSensorInstallLineWithoutOwnCA(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Config.Server.TLS = &config.ServerTLS{Mode: "off"} })
	code, out := do(t, ts, "GET", "/api/sensor/install?server=https://siem.example.com", "", true)
	if line, _ := out["linux"].(string); code != 200 || strings.Contains(line, "--ca-sha256") || !strings.Contains(line, "--token -") {
		t.Errorf("no CA: %d %v", code, out)
	}
}

func TestSensorConfig(t *testing.T) {
	ts, s := newSensorServer(t)
	path := "/api/sensor/config?" + url.Values{"server": {"https://siem.example.com:8443"}}.Encode()
	_, sensor := makeToken(t, ts, "token 1", "sensor")
	_, linux := makeToken(t, ts, "token 2", "linux")
	revokedID, revoked := makeToken(t, ts, "token 3", "sensor")
	if code, _, raw := call(t, ts, "POST", "/api/agent-tokens/"+revokedID+"/revoke", "", "admin", adminPass, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, raw)
	}
	for name, c := range map[string]struct {
		token string
		code  int
		says  string
	}{
		"none":    {"", 401, "does not know this token"},
		"unknown": {"sgl_" + strings.Repeat("b", 52), 401, "does not know this token"},
		"revoked": {revoked, 401, "was revoked"},
		"linux":   {linux, 403, "a token for linux agents"},
		"shared":  {"tok-0123456789abcdef", 403, "shared token"},
	} {
		code, _, body := sensorGet(t, ts, path, c.token)
		if code != c.code || !strings.Contains(body, c.says) {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}

	code, h, cfg := sensorGet(t, ts, path, sensor)
	if code != 200 || h.Get("Cache-Control") != "no-store" || !strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
		t.Fatalf("config: %d %v %s", code, h, cfg)
	}
	pin := agentinv.Pin(s.TLS.Fingerprint())
	for _, want := range []string{"Authorization Bearer ${SIGNALITH_TOKEN}", "/etc/signalith-sensor/ca.pem", "Tag                  sensor.status",
		"/var/lib/signalith-sensor/agent/buffer", "ca=" + pin, "Host                 siem.example.com", "Port                 7779", "suricata.eve", "zeek.*"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config has no %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, sensor) || strings.Contains(cfg, agents.TokenPlaceholder) {
		t.Error("the config holds a token")
	}

	// Docker, Suricata only.
	code, _, cfg = sensorGet(t, ts, path+"&layout=docker&zeek=false", sensor)
	if code != 200 || !strings.Contains(cfg, "/config/ca.pem") || strings.Contains(cfg, "zeek") {
		t.Errorf("docker: %d %s", code, cfg)
	}
	for _, bad := range []string{"&layout=rpm", "&zeek=false&suricata=false"} {
		if code, _, body := sensorGet(t, ts, path+bad, sensor); code != 400 {
			t.Errorf("%s: %d %s", bad, code, body)
		}
	}
	if code, _, body := sensorGet(t, ts, "/api/sensor/config?server=http://siem.example.com", sensor); code != 400 || !strings.Contains(body, "HTTPS") {
		t.Errorf("http: %d %s", code, body)
	}
}

// The script waits for its first batch: seen answers for the calling
// token only.
func TestSensorSeen(t *testing.T) {
	ts, _ := newSensorServer(t)
	_, sensor := makeToken(t, ts, "token 4", "sensor")
	_, other := makeToken(t, ts, "token 5", "sensor")
	seen := func(tok string) sensorSeen {
		t.Helper()
		code, _, body := sensorGet(t, ts, "/api/sensor/seen", tok)
		var out sensorSeen
		if code != 200 || json.Unmarshal([]byte(body), &out) != nil {
			t.Fatalf("seen: %d %s", code, body)
		}
		return out
	}
	if s := seen(sensor); s.LastSeen != nil || s.Events1h != 0 {
		t.Errorf("before: %+v", s)
	}
	line := `{"kind":"signalith-sensor-status","v":1,"time":"2026-10-15T12:00:00Z","host":"nsm-01","role":"sensor"}`
	rec, _ := json.Marshal([]map[string]any{{"log": line}})
	if code, body := agentSend(t, ts.URL, "/api/ingest", other, string(rec), map[string]string{"X-Signalith-Tag": "sensor.status", "X-Signalith-Agent": "nsm-02"}); code != 200 {
		t.Fatalf("other sensor: %d %s", code, body)
	}
	if s := seen(sensor); s.LastSeen != nil {
		t.Errorf("another sensor's batch counted: %+v", s)
	}
	if code, body := agentSend(t, ts.URL, "/api/ingest", sensor, string(rec), map[string]string{"X-Signalith-Tag": "sensor.status", "X-Signalith-Agent": "nsm-01"}); code != 200 {
		t.Fatalf("sensor: %d %s", code, body)
	}
	if s := seen(sensor); s.LastSeen == nil || s.Events1h != 1 {
		t.Errorf("after: %+v", s)
	}
	if code, _, _ := sensorGet(t, ts, "/api/sensor/seen", ""); code != 401 {
		t.Errorf("no token: %d", code)
	}
}

// A status line reaches the agent's row and the Health page's counts.
func TestSensorStatusOnEndpointsAndHealth(t *testing.T) {
	ts, _ := newSensorServer(t)
	_, sensor := makeToken(t, ts, "token 6", "sensor")
	now := time.Now().UTC()
	line := `{"kind":"signalith-sensor-status","v":1,"time":"` + now.Format(time.RFC3339) + `","host":"nsm-01","role":"sensor",` +
		`"suricata":{"version":"8.0.1","running":true},"rules":{"updated":"` + now.Add(-96*time.Hour).Format(time.RFC3339) + `","count":10,"update":"ok"},` +
		`"interface":{"name":"eth1","link":"up","drop_percent":9.5}}`
	rec, _ := json.Marshal([]map[string]any{{"log": line}})
	if code, body := agentSend(t, ts.URL, "/api/ingest", sensor, string(rec), map[string]string{"X-Signalith-Tag": "sensor.status", "X-Signalith-Agent": "nsm-01"}); code != 200 {
		t.Fatalf("send: %d %s", code, body)
	}
	_, out, raw := call(t, ts, "GET", "/api/agents", "", "admin", adminPass, nil)
	agents, _ := out["agents"].([]any)
	if len(agents) != 1 {
		t.Fatalf("agents: %s", raw)
	}
	s, _ := agents[0].(map[string]any)["sensor"].(map[string]any)
	if s["interface"] != "eth1" || s["drop_percent"] != 9.5 || s["rules_count"] != 10.0 {
		t.Errorf("sensor on the row: %v", s)
	}
	for _, u := range []string{"admin", "vera"} {
		pass := adminPass
		if u != "admin" {
			pass = "role-password"
		}
		_, h, raw := call(t, ts, "GET", "/api/health", "", u, pass, nil)
		got, _ := h["sensors"].(map[string]any)
		if got["total"] != 1.0 || got["sending"] != 1.0 || got["silent"] != 0.0 || got["dropping"] != 1.0 || got["rules_old"] != 1.0 {
			t.Errorf("%s: health sensors: %s", u, raw)
		}
	}
}

// Only a sensor's token reports a sensor's health: a status line sent
// with another agent token is stored as an event and changes no row.
func TestSensorStatusNeedsSensorToken(t *testing.T) {
	ts, _ := newSensorServer(t)
	_, sensor := makeToken(t, ts, "token 7", "sensor")
	_, linux := makeToken(t, ts, "token 8", "linux")
	status := func(drop string) string {
		line := `{"kind":"signalith-sensor-status","v":1,"time":"` + time.Now().UTC().Format(time.RFC3339) + `","host":"nsm-01","role":"sensor",` +
			`"suricata":{"version":"8.0.1","running":true},"interface":{"name":"eth1","link":"up","drop_percent":` + drop + `}}`
		rec, _ := json.Marshal([]map[string]any{{"log": line}})
		return string(rec)
	}
	hdr := map[string]string{"X-Signalith-Tag": "sensor.status", "X-Signalith-Agent": "nsm-01"}
	sensorOf := func() map[string]any {
		t.Helper()
		_, out, _ := call(t, ts, "GET", "/api/agents", "", "admin", adminPass, nil)
		agents, _ := out["agents"].([]any)
		for _, a := range agents {
			if s, ok := a.(map[string]any)["sensor"].(map[string]any); ok {
				return s
			}
		}
		return nil
	}
	if code, body := agentSend(t, ts.URL, "/api/ingest", linux, status("0"), hdr); code != 200 {
		t.Fatalf("linux token: %d %s", code, body)
	}
	if s := sensorOf(); s != nil {
		t.Fatalf("a linux token made a sensor: %v", s)
	}
	if code, body := agentSend(t, ts.URL, "/api/ingest", sensor, status("30"), hdr); code != 200 {
		t.Fatalf("sensor token: %d %s", code, body)
	}
	if code, body := agentSend(t, ts.URL, "/api/ingest", linux, status("0"), hdr); code != 200 {
		t.Fatalf("linux token again: %d %s", code, body)
	}
	if s := sensorOf(); s == nil || s["drop_percent"] != 30.0 {
		t.Errorf("a linux token changed the sensor's status: %v", s)
	}
}

func TestCountSensors(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Hour).Format(time.RFC3339)
	agents := []agentinv.Agent{
		{Tag: "win.security", LastSeen: now},
		{Tag: "zeek.conn", LastSeen: now.Add(-time.Minute)},
		// Silent after an hour without a status line, as on Endpoints...
		{Tag: "suricata.eve", LastSeen: now.Add(-20 * time.Minute)},
		// ...and after 15 minutes with one.
		{Tag: "sensor.status", LastSeen: now.Add(-20 * time.Minute), Sensor: &ingest.SensorStatus{Zeek: &ingest.SensorTool{}}},
		{Tag: "sensor.status", LastSeen: now, Sensor: &ingest.SensorStatus{DropPercent: 5.1, Suricata: &ingest.SensorTool{}, RulesUpdated: fresh, RulesUpdate: "ok"}},
		{Tag: "zeek.dns", LastSeen: now, Sensor: &ingest.SensorStatus{Suricata: &ingest.SensorTool{}, RulesUpdated: fresh, RulesUpdate: "failed"}},
		{Tag: "zeek.dns", LastSeen: now, Sensor: &ingest.SensorStatus{Zeek: &ingest.SensorTool{}}},
		{Tag: "zeek", Refusing: true},
	}
	got := countSensors(agents, now)
	if got == nil || *got != (sensorCounts{Total: 6, Sending: 5, Silent: 1, Dropping: 1, RulesOld: 1}) {
		t.Errorf("counts: %+v", got)
	}
	if countSensors(agents[:1], now) != nil {
		t.Error("no sensors: counts")
	}
}
