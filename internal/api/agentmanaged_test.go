// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/jrsamsanchez/signalith/internal/keytrust"
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
	code, h, body = sensorGet(t, ts, agentproto.RouteInstallPS1, "")
	sum = sha256.Sum256(deploy.AgentInstallPS1)
	if code != 200 || body != string(deploy.AgentInstallPS1) || h.Get("X-Signalith-SHA256") != hex.EncodeToString(sum[:]) {
		t.Errorf("install.ps1: %d %v", code, h)
	}
	code, h, body = sensorGet(t, ts, agentproto.RouteInstallMacOS, "")
	sum = sha256.Sum256(deploy.AgentInstallMacOS)
	if code != 200 || body != string(deploy.AgentInstallMacOS) || h.Get("X-Signalith-SHA256") != hex.EncodeToString(sum[:]) {
		t.Errorf("install-macos.sh: %d %v", code, h)
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
	win, _ := out["windows"].(string)
	for _, want := range []string{"https://siem.example.com:7779/api/agent/install.ps1", "-From $u -CaSha256 " + ca + " -Version test -Token -",
		"'" + agents.TokenPlaceholder + "' | & $f", strings.ToUpper(clusterinstall.ScriptSHA256().AgentPS1)} {
		if !strings.Contains(win, want) {
			t.Errorf("Windows line has no %q:\n%s", want, win)
		}
	}
	mac, _ := out["macos"].(string)
	for _, want := range []string{"https://siem.example.com:7779/api/agent/install-macos.sh", "shasum -a 256 -c -s",
		"--from https://siem.example.com:7779 --ca-sha256 " + ca + " --version test --token -", clusterinstall.ScriptSHA256().AgentMac} {
		if !strings.Contains(mac, want) {
			t.Errorf("macOS line has no %q:\n%s", want, mac)
		}
	}
	if note, _ := out["macos_note"].(string); !strings.Contains(note, "Full Disk Access") {
		t.Errorf("macOS note %q", note)
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
	// The revision holds over the bytes sent, as the agent checks it.
	if rev, ok := agentproto.RawRevision([]byte(body)); !ok || `"`+rev+`"` != h.Get("ETag") {
		t.Errorf("revision over the bytes sent %q %v, ETag %s", rev, ok, h.Get("ETag"))
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
	if code != 200 || !strings.Contains(body, `C:\\ProgramData\\Signalith Agent\\ca.pem`) || strings.Contains(body, "osquery") {
		t.Errorf("windows: %d %s", code, body)
	}
	// A computer with osquery gets the flags that point it here, and
	// osquery enrolls with the agent token.
	for _, goos := range []string{"linux", "windows"} {
		code, _, body = sensorGet(t, ts, strings.Replace(path, "os=linux", "os="+goos, 1)+"&osquery=true", agent)
		var oc agentproto.Config
		if code != 200 || json.Unmarshal([]byte(body), &oc) != nil || oc.Osquery == nil || oc.Osquery.Error != "" {
			t.Fatalf("%s osquery: %d %s", goos, code, body)
		}
		for _, line := range strings.Split(strings.TrimSpace(oc.Osquery.Flags), "\n") {
			if !agentproto.OsqueryFlagAllowed(line) {
				t.Errorf("%s: the agent would leave out %q", goos, line)
			}
		}
		if !strings.Contains(oc.Osquery.Flags, "--tls_hostname=siem.example.com:7779\n") || strings.Contains(oc.Osquery.Flags, "enroll_secret_path") {
			t.Errorf("%s osquery flags:\n%s", goos, oc.Osquery.Flags)
		}
		if (goos == "windows") != strings.Contains(oc.Osquery.Flags, "ntfs") {
			t.Errorf("%s file events:\n%s", goos, oc.Osquery.Flags)
		}
	}
	if _, ok := s.EnrollToken(agent); !ok {
		t.Error("osquery cannot enroll with the agent token")
	}
	// A Mac runs osquery only: no Fluent Bit, and the CA for osquery.
	darwin := strings.Replace(strings.Replace(path, "os=linux", "os=darwin", 1), "amd64", "arm64", 1)
	code, _, body = sensorGet(t, ts, darwin, agent)
	if code != 200 || strings.Contains(body, "fluentbit") || strings.Contains(body, "osquery") {
		t.Errorf("macOS without osquery: %d %s", code, body)
	}
	code, _, body = sensorGet(t, ts, darwin+"&osquery=true", agent)
	var mc agentproto.Config
	if code != 200 || json.Unmarshal([]byte(body), &mc) != nil || mc.FluentBit != nil || mc.Osquery == nil || mc.Osquery.Error != "" ||
		!strings.Contains(mc.CA, "BEGIN CERTIFICATE") || mc.Revision != agentproto.RevisionOf(mc) {
		t.Fatalf("macOS: %d %s", code, body)
	}
	for _, line := range strings.Split(strings.TrimSpace(mc.Osquery.Flags), "\n") {
		if !agentproto.OsqueryFlagAllowed(line) {
			t.Errorf("macOS: the agent would leave out %q", line)
		}
	}
	if !strings.Contains(mc.Osquery.Flags, "--tls_hostname=siem.example.com:7779\n") || strings.Contains(mc.Osquery.Flags, "ntfs") {
		t.Errorf("macOS osquery flags:\n%s", mc.Osquery.Flags)
	}
	for _, bad := range []string{"?os=plan9&arch=amd64", "?os=linux&arch=amd64&server=http://siem.example.com:7779", "?os=linux&arch=amd64&server=" + url.QueryEscape("https://a b")} {
		if code, _, body := sensorGet(t, ts, agentproto.RouteConfig+bad, agent); code != 400 {
			t.Errorf("%s: %d %s", bad, code, body)
		}
	}
}

// An admin chooses on the Endpoints page what the agents of an install
// line collect; each agent's next configuration follows.
func TestManagedAgentCollect(t *testing.T) {
	ts, s := newSensorServer(t)
	var logs bytes.Buffer
	s.Log = slog.New(slog.NewTextHandler(&logs, nil))
	id, agent := makeToken(t, ts, "Web servers", "agent")
	otherID, other := makeToken(t, ts, "Desktops", "agent")
	linuxID, _ := makeToken(t, ts, "Old Linux", "linux")
	path := agentproto.RouteConfig + "?" + url.Values{"os": {"linux"}, "arch": {"amd64"}, "server": {"https://siem.example.com:7779"}}.Encode()
	win := strings.Replace(path, "os=linux", "os=windows", 1)
	fetch := func(p, token string) agentproto.Config {
		t.Helper()
		code, _, body := sensorGet(t, ts, p, token)
		var cfg agentproto.Config
		if code != 200 || json.Unmarshal([]byte(body), &cfg) != nil || cfg.FluentBit == nil {
			t.Fatalf("config: %d %s", code, body)
		}
		return cfg
	}
	before := fetch(path+"&osquery=true&sysmon=true", agent)
	if before.Osquery == nil || !strings.Contains(before.FluentBit.Config, "linux.web") || !strings.Contains(before.FluentBit.Config, "linux.audit") ||
		!strings.Contains(before.FluentBit.Config, "SYSLOG_IDENTIFIER=sysmon") {
		t.Fatalf("default: %+v\n%s", before.Osquery, before.FluentBit.Config)
	}
	if !strings.Contains(fetch(win, agent).FluentBit.Config, "PowerShell/Operational") {
		t.Fatal("default Windows: no PowerShell log")
	}
	// The list shows the default for agent tokens only.
	_, out, _ := call(t, ts, "GET", "/api/agent-tokens", "", "andy", "role-password", nil)
	for _, tok := range out["tokens"].([]any) {
		m := tok.(map[string]any)
		if _, has := m["collect"]; has != (m["purpose"] == "agent") {
			t.Errorf("collect listed for %v: %v", m["purpose"], m["collect"])
		}
	}

	body := `{"osquery":"off","sysmon":"off","powershell":"off","linux_log":"journal","web_logs":"off","audit_log":"off"}`
	for _, who := range [][2]string{{"andy", "role-password"}, {"vera", "role-password"}} {
		if code, _ := doAs(t, ts, who[0], who[1], "PUT", "/api/agent-tokens/"+id+"/collect", body); code != 403 {
			t.Errorf("%s: %d", who[0], code)
		}
	}
	code, out, raw := call(t, ts, "PUT", "/api/agent-tokens/"+id+"/collect", body, "admin", adminPass, nil)
	if code != 200 || strings.Contains(raw, agent) {
		t.Fatalf("set: %d %s", code, raw)
	}
	if c := out["token"].(map[string]any)["collect"].(map[string]any); c["osquery"] != "off" || c["linux_log"] != "journal" {
		t.Errorf("answer: %v", c)
	}
	after := fetch(path+"&osquery=true&sysmon=true", agent)
	if after.Osquery != nil || after.Revision == before.Revision {
		t.Errorf("osquery still on: %+v", after.Osquery)
	}
	for _, gone := range []string{"linux.web", "linux.audit", "SYSLOG_IDENTIFIER=sysmon", "/var/log/auth.log"} {
		if strings.Contains(after.FluentBit.Config, gone) {
			t.Errorf("config still has %q:\n%s", gone, after.FluentBit.Config)
		}
	}
	if !strings.Contains(after.FluentBit.Config, "systemd") {
		t.Errorf("not reading the journal:\n%s", after.FluentBit.Config)
	}
	if c := fetch(win+"&sysmon=true", agent).FluentBit.Config; strings.Contains(c, "PowerShell") || strings.Contains(c, "Sysmon") {
		t.Errorf("Windows still reads PowerShell or Sysmon:\n%s", c)
	}
	// Other lines keep the default.
	if c := fetch(path+"&osquery=true", other); c.Osquery == nil || !strings.Contains(c.FluentBit.Config, "linux.web") {
		t.Errorf("other line changed: %+v", c.Osquery)
	}
	if !strings.Contains(logs.String(), "agent collection settings changed") || !strings.Contains(logs.String(), "osquery=off") {
		t.Errorf("no audit line:\n%s", logs.String())
	}
	// Back to the default: on, auto and empty all mean it.
	if code, out, raw := call(t, ts, "PUT", "/api/agent-tokens/"+id+"/collect", `{"osquery":"on","linux_log":"auto"}`, "admin", adminPass, nil); code != 200 ||
		len(out["token"].(map[string]any)["collect"].(map[string]any)) != 0 {
		t.Fatalf("reset: %d %s", code, raw)
	}
	if c := fetch(path+"&osquery=true&sysmon=true", agent); c.Revision != before.Revision {
		t.Errorf("default again differs:\n%s", c.FluentBit.Config)
	}

	for name, c := range map[string]struct {
		id, body string
		code     int
		says     string
	}{
		"bad value":     {id, `{"osquery":"maybe"}`, 400, `"field":"osquery"`},
		"bad log":       {id, `{"linux_log":"syslog"}`, 400, `"field":"linux_log"`},
		"unknown field": {id, `{"osqueyr":"off"}`, 400, "unknown field"},
		"not an agent":  {linuxID, `{"osquery":"off"}`, 409, "Signalith Agent"},
		"unknown token": {"000000000000", `{}`, 404, "not_found"},
		"not an ID":     {"x", `{}`, 404, "not_found"},
	} {
		code, _, raw := call(t, ts, "PUT", "/api/agent-tokens/"+c.id+"/collect", c.body, "admin", adminPass, nil)
		if code != c.code || !strings.Contains(raw, c.says) {
			t.Errorf("%s: %d %s", name, code, raw)
		}
	}
	if code, _, raw := call(t, ts, "POST", "/api/agent-tokens/"+otherID+"/revoke", "", "admin", adminPass, nil); code != 200 {
		t.Fatalf("revoke: %d %s", code, raw)
	}
	if code, _, raw := call(t, ts, "PUT", "/api/agent-tokens/"+otherID+"/collect", `{"osquery":"off"}`, "admin", adminPass, nil); code != 409 || !strings.Contains(raw, "revoked") {
		t.Errorf("revoked: %d %s", code, raw)
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
	// osquery checks the certificate against the address it connects to:
	// an IP address works only with Signalith's own CA, so osquery is off,
	// with why.
	if o := agentOsquery("linux", agents.Options{ServerURL: "https://10.1.2.3:7779", CertNames: []string{"siem"}}); o.Flags != "" || !strings.Contains(o.Error, "host name") {
		t.Errorf("osquery at an IP address: %+v", o)
	}
	if o := agentOsquery("linux", agents.Options{ServerURL: "https://10.1.2.3:7779", OwnCA: true}); o.Error != "" || !strings.Contains(o.Flags, "--tls_hostname=10.1.2.3:7779") {
		t.Errorf("osquery at an IP address with Signalith's own CA: %+v", o)
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
	// It traded the line's token for a key of its own (ASI-102).
	key, err := os.ReadFile(filepath.Join(p.Conf, "hostkey"))
	if err != nil || !agentproto.IsHostKey(strings.TrimSpace(string(key))) || !s.tokens().Enrolled("db-02") {
		t.Errorf("host key: %v %q", err, key)
	}
}

func TestManagedAgentUpdate(t *testing.T) {
	ts, s := newSensorServer(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := agentproto.ReleaseKeys
	agentproto.ReleaseKeys = []ed25519.PublicKey{pub}
	t.Cleanup(func() { agentproto.ReleaseKeys = old })
	dir := t.TempDir()
	prog := []byte("agent program 2.0.0\n")
	if err := os.WriteFile(filepath.Join(dir, agentproto.ProgramName("linux", "amd64")), prog, 0o755); err != nil {
		t.Fatal(err)
	}
	s.AgentPrograms = &clusterinstall.Programs{Dir: dir}
	id, agent := makeToken(t, ts, "Web servers", "agent")
	path := agentproto.RouteConfig + "?" + url.Values{"os": {"linux"}, "arch": {"amd64"}, "server": {"https://siem.example.com:7779"}}.Encode()
	fetch := func(version string) agentproto.Config {
		t.Helper()
		code, _, body := agentDo(t, ts, "GET", path, agent, "", "", map[string]string{agentproto.HeaderVersion: version})
		var cfg agentproto.Config
		if code != 200 || json.Unmarshal([]byte(body), &cfg) != nil {
			t.Fatalf("config: %d %s", code, body)
		}
		return cfg
	}

	// Without a signed manifest there is nothing to offer.
	if cfg := fetch("1.0.0"); cfg.Update != nil {
		t.Errorf("offered without a manifest: %+v", cfg.Update)
	}
	if code, _, body := sensorGet(t, ts, agentproto.RouteManifest, agent); code != 404 || !strings.Contains(body, "no signed manifest") {
		t.Errorf("manifest missing: %d %s", code, body)
	}

	if _, err := clusterinstall.SignPrograms(dir, "2.0.0", priv); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(prog)
	if cfg := fetch("1.0.0"); cfg.Update == nil || cfg.Update.Version != "2.0.0" || cfg.Update.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("update: %+v", cfg.Update)
	}
	for _, v := range []string{"2.0.0", "2.1.0", "dev", ""} {
		if cfg := fetch(v); cfg.Update != nil {
			t.Errorf("offered %s to version %q", cfg.Update.Version, v)
		}
	}
	code, _, body := sensorGet(t, ts, agentproto.RouteManifest, agent)
	var ans agentproto.ManifestAnswer
	if code != 200 || json.Unmarshal([]byte(body), &ans) != nil {
		t.Fatalf("manifest: %d %s", code, body)
	}
	if m, err := agentproto.VerifyManifest(agentproto.ReleaseKeys, []byte(ans.Manifest), []byte(ans.Signature)); err != nil || m.Version != "2.0.0" {
		t.Errorf("manifest answer: %v %+v", err, m)
	}
	if code, _, _ := sensorGet(t, ts, agentproto.RouteManifest, ""); code != 401 {
		t.Errorf("manifest without a token: %d", code)
	}

	// The server hands its revocation list to agents with the manifest,
	// and refuses a manifest signed with a revoked key itself.
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldRoots := keytrust.Roots
	keytrust.Roots = []ed25519.PublicKey{rootPub}
	t.Cleanup(func() { keytrust.Roots = oldRoots })
	store := &keytrust.Store{Dir: t.TempDir()}
	s.Revocations, s.AgentPrograms.Revocations = store, store
	offer := func(issued time.Time, ids ...string) []byte {
		t.Helper()
		l := keytrust.List{Format: keytrust.Format, Issued: issued}
		for _, id := range ids {
			l.Revoked = append(l.Revoked, keytrust.RevokedKey{ID: id})
		}
		data, _ := json.Marshal(l)
		if kept, err := store.Offer(data, keytrust.Sign(rootPriv, data)); !kept || err != nil {
			t.Fatalf("offer: %v %v", kept, err)
		}
		return data
	}
	list := offer(time.Now().Add(-time.Hour), "0123456789ab")
	code, _, body = sensorGet(t, ts, agentproto.RouteManifest, agent)
	if json.Unmarshal([]byte(body), &ans) != nil || code != 200 || ans.Revocation != string(list) || ans.RevocationSignature == "" {
		t.Errorf("manifest with a revocation list: %d %s", code, body)
	}
	offer(time.Now(), keytrust.KeyID(pub))
	if cfg := fetch("1.0.0"); cfg.Update != nil {
		t.Errorf("offered an update signed with a revoked key: %+v", cfg.Update)
	}
	if code, _, body := sensorGet(t, ts, agentproto.RouteManifest, agent); code == 200 {
		t.Errorf("manifest signed with a revoked key handed out: %s", body)
	}
	s.Revocations, s.AgentPrograms.Revocations = nil, nil

	// Paused for the install line: no offer until it is turned back on.
	if code, _, raw := call(t, ts, "PUT", "/api/agent-tokens/"+id+"/collect", `{"updates":"off"}`, "admin", adminPass, nil); code != 200 {
		t.Fatalf("pause: %d %s", code, raw)
	}
	if cfg := fetch("1.0.0"); cfg.Update != nil {
		t.Errorf("offered while paused: %+v", cfg.Update)
	}
	if code, _, raw := call(t, ts, "PUT", "/api/agent-tokens/"+id+"/collect", `{"updates":"on"}`, "admin", adminPass, nil); code != 200 {
		t.Fatalf("resume: %d %s", code, raw)
	}
	if cfg := fetch("1.0.0"); cfg.Update == nil {
		t.Error("not offered after resuming")
	}

	// Rolling out to a share of the line's computers (ASI-07): only the
	// computers in it are offered the update, and the same ones each time.
	if code, _, raw := call(t, ts, "PUT", "/api/agent-tokens/"+id+"/collect", `{"update_share":"10"}`, "admin", adminPass, nil); code != 200 {
		t.Fatalf("share: %d %s", code, raw)
	}
	offered := 0
	for i := range 200 {
		name := fmt.Sprintf("host-%03d", i)
		code, _, body := agentDo(t, ts, "GET", path, agent, "", "", map[string]string{agentproto.HeaderVersion: "1.0.0", agentproto.HeaderName: name})
		var cfg agentproto.Config
		if code != 200 || json.Unmarshal([]byte(body), &cfg) != nil {
			t.Fatalf("config: %d %s", code, body)
		}
		if (cfg.Update != nil) != inUpdateShare(id, name, "10") {
			t.Errorf("%s: offered = %v", name, cfg.Update != nil)
		}
		if cfg.Update != nil {
			offered++
		}
	}
	if offered < 5 || offered > 40 {
		t.Errorf("offered to %d of 200 computers with a 10%% share", offered)
	}
	if code, _, raw := call(t, ts, "PUT", "/api/agent-tokens/"+id+"/collect", `{"update_share":"7"}`, "admin", adminPass, nil); code != 400 || !strings.Contains(raw, "update_share") {
		t.Errorf("share 7: %d %s", code, raw)
	}
	if code, _, raw := call(t, ts, "PUT", "/api/agent-tokens/"+id+"/collect", `{"update_share":"100"}`, "admin", adminPass, nil); code != 200 {
		t.Fatalf("share 100: %d %s", code, raw)
	}
	// The silent-agent alert (ASI-14) is a choice of the same window.
	if code, _, raw := call(t, ts, "PUT", "/api/agent-tokens/"+id+"/collect", `{"silent_alert":"24h"}`, "admin", adminPass, nil); code != 200 || !strings.Contains(raw, `"silent_alert":"24h"`) {
		t.Errorf("silent alert: %d %s", code, raw)
	}
	if code, _, raw := call(t, ts, "PUT", "/api/agent-tokens/"+id+"/collect", `{"silent_alert":"2h"}`, "admin", adminPass, nil); code != 400 || !strings.Contains(raw, "silent_alert") {
		t.Errorf("silent alert 2h: %d %s", code, raw)
	}

	// A program that is not the one signed is never offered.
	if err := os.WriteFile(filepath.Join(dir, agentproto.ProgramName("linux", "amd64")), []byte("something else, and longer"), 0o755); err != nil {
		t.Fatal(err)
	}
	if cfg := fetch("1.0.0"); cfg.Update != nil {
		t.Errorf("offered a program that is not the signed one: %+v", cfg.Update)
	}
	// Nor is anything signed by a key the agents do not trust.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	agentproto.ReleaseKeys = []ed25519.PublicKey{other}
	if err := os.WriteFile(filepath.Join(dir, agentproto.ProgramName("linux", "amd64")), prog, 0o755); err != nil {
		t.Fatal(err)
	}
	if cfg := fetch("1.0.0"); cfg.Update != nil {
		t.Errorf("offered with an untrusted signature: %+v", cfg.Update)
	}
}

// A computer in a share of the rollout stays in it, and in every larger
// share, so raising the share only adds computers.
func TestInUpdateShare(t *testing.T) {
	counts := map[string]int{}
	for i := range 2000 {
		name := fmt.Sprintf("WEB-%04d", i)
		prev := false
		for _, share := range []string{"10", "25", "50", ""} {
			in := inUpdateShare("tok1", name, share)
			if prev && !in {
				t.Fatalf("%s is in a smaller share than %s but not in it", name, share)
			}
			if in != inUpdateShare("tok1", strings.ToLower(name), share) {
				t.Fatalf("%s: the name's case changes the share", name)
			}
			prev = in
			if in {
				counts[share]++
			}
		}
	}
	for share, want := range map[string]int{"10": 200, "25": 500, "50": 1000, "": 2000} {
		if got := counts[share]; got < want*7/10 || got > want*13/10 {
			t.Errorf("share %q holds %d of 2000, want about %d", share, got, want)
		}
	}
}
