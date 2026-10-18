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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/deploy"
	"github.com/jrsamsanchez/signalith/internal/agentd"
	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/clusterinstall"
	"github.com/jrsamsanchez/signalith/internal/config"
)

func agentDo(t *testing.T, ts *httptest.Server, method, path, token, name, body string, h map[string]string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if name != "" {
		req.Header.Set(agentproto.HeaderName, name)
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func TestManagedAgentInstallScriptIsPublic(t *testing.T) {
	ts, _ := newSensorServer(t)
	code, h, body := sensorGet(t, ts, agentproto.RouteInstallSH, "")
	sum := sha256.Sum256(deploy.AgentInstallSH)
	if code != 200 || body != string(deploy.AgentInstallSH) || h.Get("X-Signalith-SHA256") != hex.EncodeToString(sum[:]) {
		t.Errorf("install.sh: %d %v", code, h)
	}
}

func TestManagedAgentInstallLine(t *testing.T) {
	ts, s := newSensorServer(t)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, agentproto.ProgramName("linux", "amd64")), []byte("x"), 0o755)
	s.AgentPrograms = &clusterinstall.Programs{Dir: dir}
	q := url.Values{"server": {"https://siem.example.com:8443"}}
	code, out, raw := call(t, ts, "GET", "/api/agent/install?"+q.Encode(), "", "admin", adminPass, nil)
	if code != 200 {
		t.Fatalf("install: %d %s", code, raw)
	}
	ca := sha256Hex(s.TLS.Fingerprint())
	line, _ := out["linux"].(string)
	for _, want := range []string{"https://siem.example.com:7779/api/agent/install.sh", "--from https://siem.example.com:7779 --ca-sha256 " + ca,
		"--version test --token -", "echo '" + agents.TokenPlaceholder + "'", clusterinstall.ScriptSHA256().Agent} {
		if !strings.Contains(line, want) {
			t.Errorf("line has no %q:\n%s", want, line)
		}
	}
	if out["ca_sha256"] != ca || out["token_placeholder"] != agents.TokenPlaceholder || out["add_name"] != nil {
		t.Errorf("answer: %v", out)
	}
	if p, _ := out["programs"].([]any); len(p) != 1 || p[0] != "linux-amd64" {
		t.Errorf("programs: %v", out["programs"])
	}
	code, out, _ = call(t, ts, "GET", "/api/agent/install?server=http://siem.example.com:8080", "", "admin", adminPass, nil)
	if code != 400 || out["field"] != "server" || !strings.Contains(out["error"].(string), "Turn on HTTPS first") {
		t.Errorf("http: %d %v", code, out)
	}
	for _, u := range []string{"vera", "andy"} {
		if code, _, _ := call(t, ts, "GET", "/api/agent/install?"+q.Encode(), "", u, "role-password", nil); code != http.StatusForbidden {
			t.Errorf("%s: %d", u, code)
		}
	}
}

func TestManagedAgentConfig(t *testing.T) {
	ts, s := newSensorServer(t)
	path := agentproto.RouteConfig + "?" + url.Values{"os": {"linux"}, "arch": {"amd64"}, "server": {"https://siem.example.com:7779"}}.Encode()
	_, agent := makeToken(t, ts, "token 1", "agent")
	_, linux := makeToken(t, ts, "token 2", "linux")
	_, sensor := makeToken(t, ts, "token 3", "sensor")
	revokedID, revoked := makeToken(t, ts, "token 4", "agent")
	if code, _, raw := call(t, ts, "POST", "/api/agent-tokens/"+revokedID+"/revoke", "", "admin", adminPass, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, raw)
	}
	for name, c := range map[string]struct {
		token string
		code  int
		says  string
	}{
		"none":    {"", 401, "does not know this token"},
		"revoked": {revoked, 401, "was revoked"},
		"linux":   {linux, 403, "a token for linux agents"},
		"sensor":  {sensor, 403, "a token for sensor agents"},
		"shared":  {"tok-0123456789abcdef", 403, "shared token"},
	} {
		for _, p := range []string{path, agentproto.RouteProgram + "?os=linux&arch=amd64"} {
			code, _, body := sensorGet(t, ts, p, c.token)
			if code != c.code || !strings.Contains(body, c.says) {
				t.Errorf("%s %s: %d %s", name, p, code, body)
			}
		}
	}

	code, h, body := sensorGet(t, ts, path, agent)
	if code != 200 || h.Get("Cache-Control") != "no-store" || h.Get("ETag") == "" {
		t.Fatalf("config: %d %v %s", code, h, body)
	}
	var cfg agentproto.Config
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.FluentBit == nil || cfg.PollSeconds != agentPollSeconds || cfg.Revision != agentproto.RevisionOf(cfg) || !strings.Contains(cfg.CA, "BEGIN CERTIFICATE") {
		t.Fatalf("config: %+v", cfg)
	}
	pin := agentinv.Pin(s.TLS.Fingerprint())
	for _, want := range []string{"Authorization Bearer ${SIGNALITH_TOKEN}", "/etc/signalith-agent/ca.pem", "/var/lib/signalith-agent/fluent-bit",
		"ca=" + pin, "Host                 siem.example.com", "Port                 7779", "/var/log/auth.log"} {
		if !strings.Contains(cfg.FluentBit.Config, want) {
			t.Errorf("config has no %q:\n%s", want, cfg.FluentBit.Config)
		}
	}
	if strings.Contains(body, agent) || strings.Contains(body, agents.TokenPlaceholder) {
		t.Error("the config holds a token")
	}

	// Unchanged: 304.
	if code, _, _ := agentDo(t, ts, "GET", path, agent, "", "", map[string]string{"If-None-Match": h.Get("ETag")}); code != http.StatusNotModified {
		t.Errorf("same revision: %d", code)
	}
	// What the computer has changes the configuration.
	code, h2, body := sensorGet(t, ts, path+"&source=journal", agent)
	if code != 200 || h2.Get("ETag") == h.Get("ETag") || !strings.Contains(body, "systemd") {
		t.Errorf("journal: %d %s", code, body)
	}
	code, _, body = sensorGet(t, ts, strings.Replace(path, "os=linux", "os=windows", 1), agent)
	if code != 200 || !strings.Contains(body, `C:\\ProgramData\\Signalith\\Agent\\ca.pem`) {
		t.Errorf("windows: %d %s", code, body)
	}
	code, _, body = sensorGet(t, ts, strings.Replace(strings.Replace(path, "os=linux", "os=darwin", 1), "amd64", "arm64", 1), agent)
	if code != 200 || strings.Contains(body, "fluentbit") {
		t.Errorf("macOS (nothing yet): %d %s", code, body)
	}
	for _, bad := range []string{"?os=plan9&arch=amd64", "?os=linux&arch=amd64&server=http://siem.example.com:7779", "?os=linux&arch=amd64&server=" + url.QueryEscape("https://a b")} {
		if code, _, body := sensorGet(t, ts, agentproto.RouteConfig+bad, agent); code != 400 {
			t.Errorf("%s: %d %s", bad, code, body)
		}
	}
}

// Without HTTPS of its own (a proxy in front), the configuration names no
// certificate authority: the computer trusts the proxy's certificate.
func TestManagedAgentConfigWithoutOwnCA(t *testing.T) {
	ts, s := newSensorServer(t)
	s.Config.Server.TLS = &config.ServerTLS{Mode: "off"}
	_, agent := makeToken(t, ts, "token 1", "agent")
	code, _, body := sensorGet(t, ts, agentproto.RouteConfig+"?os=linux&arch=amd64&server=https://siem.example.com", agent)
	var cfg agentproto.Config
	if code != 200 || json.Unmarshal([]byte(body), &cfg) != nil || cfg.CA != "" || cfg.FluentBit == nil || strings.Contains(cfg.FluentBit.Config, "ca.pem") {
		t.Errorf("no CA: %d %s", code, body)
	}
}

func TestManagedAgentStatus(t *testing.T) {
	ts, s := newSensorServer(t)
	_, agent := makeToken(t, ts, "token 1", "agent")
	_, linux := makeToken(t, ts, "token 2", "linux")
	st := `{"version":"0.4.0","os":"linux","arch":"amd64","system":"Ubuntu 24.04 LTS","revision":"0123456789abcdef0123456789abcdef",
		"components":[{"name":"fluentbit","version":"4.0.3","state":"running"},{"name":"bad","state":"exploded"}]}`
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteStatus, linux, "web-01", st, nil); code != 403 {
		t.Errorf("linux token: %d %s", code, body)
	}
	if code, _, body := agentDo(t, ts, "POST", agentproto.RouteStatus, agent, "web-01", st, nil); code != http.StatusNoContent {
		t.Fatalf("status: %d %s", code, body)
	}
	list, _, err := s.agents().List(t.Context())
	if err != nil || len(list) != 1 {
		t.Fatalf("agents: %v %v", list, err)
	}
	a := list[0]
	if a.Name != "web-01" || a.Managed == nil || a.Managed.Version != "0.4.0" || len(a.Managed.Components) != 1 || a.Managed.Components[0].State != "running" {
		t.Errorf("agent: %+v %+v", a, a.Managed)
	}
	code, out, _ := call(t, ts, "GET", "/api/agents", "", "admin", adminPass, nil)
	if rows, _ := out["agents"].([]any); code != 200 || len(rows) != 1 || rows[0].(map[string]any)["managed"] == nil {
		t.Errorf("/api/agents: %d %v", code, out)
	}

	if code, _, _ := agentDo(t, ts, "POST", agentproto.RouteStatus, agent, "web-01", "{", nil); code != 400 {
		t.Errorf("bad JSON: %d", code)
	}
	big := `{"system":"` + strings.Repeat("x", agentproto.MaxStatusBytes) + `"}`
	if code, _, _ := agentDo(t, ts, "POST", agentproto.RouteStatus, agent, "web-01", big, nil); code != http.StatusRequestEntityTooLarge {
		t.Errorf("too large: %d", code)
	}
}

func TestManagedAgentProgram(t *testing.T) {
	ts, s := newSensorServer(t)
	dir := t.TempDir()
	prog := []byte("#!/bin/true\nagent program\n")
	if err := os.WriteFile(filepath.Join(dir, agentproto.ProgramName("linux", "arm64")), prog, 0o755); err != nil {
		t.Fatal(err)
	}
	s.AgentPrograms = &clusterinstall.Programs{Dir: dir}
	_, agent := makeToken(t, ts, "token 1", "agent")
	code, h, body := sensorGet(t, ts, agentproto.RouteProgram+"?os=linux&arch=arm64", agent)
	sum := sha256.Sum256(prog)
	if code != 200 || body != string(prog) || h.Get(agentproto.HeaderSHA256) != hex.EncodeToString(sum[:]) {
		t.Errorf("program: %d %v %q", code, h, body)
	}
	if code, _, body := sensorGet(t, ts, agentproto.RouteProgram+"?os=linux&arch=amd64", agent); code != 404 || !strings.Contains(body, "no agent program") {
		t.Errorf("missing: %d %s", code, body)
	}
	if code, _, _ := sensorGet(t, ts, agentproto.RouteProgram+"?os=../../etc&arch=passwd", agent); code != 400 {
		t.Errorf("bad platform: %d", code)
	}
}

// The agent program and these routes agree: it fetches its configuration,
// writes Fluent Bit's, and its status reaches the Endpoints page.
func TestManagedAgentTalksToServer(t *testing.T) {
	ts, s := newSensorServer(t)
	_, token := makeToken(t, ts, "token 1", "agent")
	// HTTPS in front of Signalith, as a proxy would serve it.
	s.Config.Server.TLS = &config.ServerTLS{Mode: "off"}
	front := httptest.NewTLSServer(ts.Config.Handler)
	defer front.Close()
	dir := t.TempDir()
	p := agentd.Paths{Conf: filepath.Join(dir, "conf"), State: filepath.Join(dir, "state"), FluentBit: filepath.Join(dir, "no-fluent-bit")}
	for _, d := range []string{p.Conf, p.State} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	a := &agentd.Agent{Paths: p, Settings: agentd.Settings{Server: front.URL, Token: token}, Version: "0.4.0", Name: "db-02",
		Client: front.Client(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	deadline := time.Now().Add(20 * time.Second)
	for {
		list, _, _ := s.agents().List(t.Context())
		if len(list) == 1 && list[0].Managed != nil && len(list[0].Managed.Components) == 1 && list[0].Managed.Components[0].State == "missing" {
			if list[0].Name != "db-02" || list[0].Managed.Revision == "" || list[0].Managed.ConfigError != "" {
				t.Errorf("agent: %+v %+v", list[0], list[0].Managed)
			}
			break
		}
		if time.Now().After(deadline) {
			if len(list) == 1 && list[0].Managed != nil {
				t.Fatalf("status: %+v", *list[0].Managed)
			}
			t.Fatalf("no status: %+v", list)
		}
		time.Sleep(20 * time.Millisecond)
	}
	conf, err := os.ReadFile(filepath.Join(p.Conf, "fluent-bit.conf"))
	if err != nil || !strings.Contains(string(conf), "${SIGNALITH_TOKEN}") || strings.Contains(string(conf), token) {
		t.Errorf("fluent-bit.conf: %v\n%s", err, conf)
	}
}
