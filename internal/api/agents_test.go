package api

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
)

func TestAgentsAreListedWithWhyTheyNeedANewConfiguration(t *testing.T) {
	ts, s, _, _, _ := newTokenServer(t)
	s.Agents = &agentinv.Inventory{Server: func() string { return "siem-a" }}
	if err := s.Tokens.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	id, secret := createToken(t, ts, "Web servers")
	// A configuration from Add data says the computer's name and what it
	// expects; one from before does not.
	if code, body := agentSend(t, ts.URL, "/api/ingest", secret, `[{"msg":"a"},{"msg":"b"}]`, map[string]string{
		"X-Signalith-Agent": "WEB-01", "X-Signalith-Config": "v=1.4.0", "X-Signalith-Tag": "linux.auth"}); code != http.StatusOK {
		t.Fatalf("send: %d %s", code, body)
	}
	if code, body := agentSend(t, ts.URL, "/api/ingest", secret, `[{"msg":"c"}]`, nil); code != http.StatusOK {
		t.Fatalf("send: %d %s", code, body)
	}
	// An OpenTelemetry Collector sends no name, but its events carry its
	// computer's host.name; one that forwards several computers' events
	// is listed by address and token, with no note to get a new
	// configuration, which would not change that.
	otlp := func(hosts ...string) string {
		var rs []string
		for _, h := range hosts {
			rs = append(rs, `{"resource":{"attributes":[{"key":"host.name","value":{"stringValue":"`+h+`"}}]},"scopeLogs":[{"logRecords":[{"body":{"stringValue":"hi"}}]}]}`)
		}
		return `{"resourceLogs":[` + strings.Join(rs, ",") + `]}`
	}
	_, gatewaySecret := createToken(t, ts, "Gateway")
	for body, token := range map[string]string{otlp("DB-02"): secret, otlp("app-1", "app-2"): gatewaySecret} {
		if code, out := agentSend(t, ts.URL, "/api/otlp/v1/logs", token, body, map[string]string{"Content-Type": "application/json"}); code != http.StatusOK {
			t.Fatalf("otlp: %d %s", code, out)
		}
	}
	// Viewers do not see the agents.
	if code, _ := doAs(t, ts, "vera", "role-password", "GET", "/api/agents", ""); code != http.StatusForbidden {
		t.Errorf("viewer: %d", code)
	}
	agents := func() (map[string]map[string]any, map[string]any) {
		t.Helper()
		code, out := doAs(t, ts, "andy", "role-password", "GET", "/api/agents", "")
		if code != http.StatusOK {
			t.Fatalf("analyst: %d %v", code, out)
		}
		byName := map[string]map[string]any{}
		for _, a := range out["agents"].([]any) {
			m := a.(map[string]any)
			name := m["name"].(string)
			if name == "" {
				name = m["intake"].(string)
			}
			byName[name] = m
		}
		return byName, out["summary"].(map[string]any)
	}
	reasons := func(a map[string]any, key string) []string {
		var out []string
		for _, r := range a[key].([]any) {
			out = append(out, r.(string))
		}
		return out
	}
	byName, sum := agents()
	web, old, db, gateway := byName["web-01"], byName["agent"], byName["db-02"], byName["otlp"]
	if web == nil || old == nil || db == nil || gateway == nil || len(byName) != 4 {
		t.Fatalf("agents: %v", byName)
	}
	// This test server serves plain HTTP, but to the agents on its own
	// computer, where it never crosses the network: nothing to fix.
	if got := reasons(web, "needs_config"); len(got) != 0 || web["token_name"] != "Web servers" || web["local"] != true ||
		web["events_1h"].(float64) != 2 || web["tag"] != "linux.auth" || web["config_version"] != "1.4.0" {
		t.Errorf("web-01: %v", web)
	}
	if got := reasons(old, "notes"); !slices.Equal(got, []string{"old"}) {
		t.Errorf("older agent: %v", old)
	}
	if got := reasons(db, "notes"); len(got) != 0 || db["intake"] != "otlp" {
		t.Errorf("collector: %v", db)
	}
	if got := reasons(gateway, "notes"); len(got) != 0 {
		t.Errorf("collector of several computers: %v", gateway)
	}
	if sum["total"].(float64) != 4 || sum["needs_config"].(float64) != 0 || sum["silent"].(float64) != 0 {
		t.Errorf("summary: %v", sum)
	}
	// Its token revoked: it needs a new configuration for that too.
	if code, _, raw := call(t, ts, "POST", "/api/agent-tokens/"+id+"/revoke", "", "admin", adminPass, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, raw)
	}
	byName, _ = agents()
	if got := reasons(byName["web-01"], "needs_config"); !slices.Equal(got, []string{"revoked"}) {
		t.Errorf("after revoke: %v", got)
	}
}

// Plain HTTP from another computer needs a new configuration; from the
// server's own computer it does not.
func TestAgentFlagsPlainHTTP(t *testing.T) {
	s := &Server{}
	now := time.Now()
	a := agentinv.Agent{Name: "web-01", Transport: agentinv.TransportPlain, LastSeen: now}
	if got := s.agentFlags(a, "", "", now).NeedsConfig; !slices.Equal(got, []string{"plain"}) {
		t.Errorf("from another computer: %v", got)
	}
	a.Local = true
	if got := s.agentFlags(a, "", "", now).NeedsConfig; len(got) != 0 {
		t.Errorf("from this computer: %v", got)
	}
}

// An agent set up while a new certificate authority was prepared trusts
// both, and keeps working after the switch: it needs nothing.
func TestAgentSetUpDuringACASwitchIsFineAfterIt(t *testing.T) {
	ts, s, _, _, _ := newTokenServer(t)
	certs := newCertManager(t)
	s.TLS = certs
	s.Agents = &agentinv.Inventory{Server: func() string { return "siem-a" }, ServerCA: func() string { return agentinv.Pin(certs.Fingerprint()) }}
	if err := s.Tokens.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, secret := createToken(t, ts, "Web servers")
	if err := certs.Prepare("standard"); err != nil {
		t.Fatal(err)
	}
	code, out, raw := call(t, ts, "GET", "/api/agents/config?os=linux&server=https://siem.example.com:8080", "", "admin", adminPass, nil)
	if code != http.StatusOK {
		t.Fatalf("config: %d %s", code, raw)
	}
	cfg, _ := out["config"].(string)
	_, header, _ := strings.Cut(cfg, "X-Signalith-Config ")
	header, _, _ = strings.Cut(header, "\n")
	cur, next := s.caPins()
	if header != "ca="+cur+","+next+";v="+s.Version && !strings.HasPrefix(header, "ca="+cur+","+next+";v=") {
		t.Fatalf("config header %q, pins %s %s", header, cur, next)
	}
	send := func() {
		t.Helper()
		if code, body := agentSend(t, ts.URL, "/api/ingest", secret, `[{"msg":"a"}]`, map[string]string{
			"X-Signalith-Agent": "web-01", "X-Signalith-Config": header}); code != http.StatusOK {
			t.Fatalf("send: %d %s", code, body)
		}
	}
	needs := func() []any {
		t.Helper()
		code, out := doAs(t, ts, "andy", "role-password", "GET", "/api/agents", "")
		if code != http.StatusOK {
			t.Fatalf("agents: %d %v", code, out)
		}
		list := out["agents"].([]any)
		if len(list) != 1 {
			t.Fatalf("agents: %v", list)
		}
		return list[0].(map[string]any)["needs_config"].([]any)
	}
	send()
	if got := needs(); len(got) != 0 {
		t.Errorf("before the switch: %v", got)
	}
	if err := certs.Switch(); err != nil {
		t.Fatal(err)
	}
	send()
	if got := needs(); len(got) != 0 {
		t.Errorf("after the switch: %v", got)
	}
}
