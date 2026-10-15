package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster"
)

// stubDNS answers lookups from names for the test.
func stubDNS(t *testing.T, names map[string][]string) {
	t.Helper()
	prev := lookupHost
	lookupHost = func(_ context.Context, host string) ([]string, error) {
		if a, ok := names[host]; ok {
			return a, nil
		}
		return nil, errors.New("no such host")
	}
	t.Cleanup(func() { lookupHost = prev })
}

// destServers is siem-a (this one) and siem-b, each with its own address.
func destServers() cluster.Status {
	a, b := server("siem-a", nil), server("siem-b", nil)
	a.Self = true
	a.Detail.NodeURL, b.Detail.NodeURL = "https://siem-a.corp:8080", "https://siem-b.corp:8080"
	return cluster.Status{Self: a.NodeID, Servers: []cluster.ServerStatus{a, b}}
}

func TestDestinations(t *testing.T) {
	stubDNS(t, map[string][]string{
		"siem-a.corp": {"10.0.0.5"},
		"siem-b.corp": {"10.0.0.6"},
		"siem.corp":   {"10.0.0.5", "10.0.0.6"}, // round robin over both
		"half.corp":   {"10.0.0.5"},
		"vip.corp":    {"10.0.0.100"}, // a load balancer
	})
	ctx := context.Background()

	choices, warning := destinationsOf(ctx, "https://siem.corp:8080", destServers())
	sh := choices[0]
	if warning != "" || sh.Kind != "shared" || strings.Join(sh.Reaches, ",") != "siem-a,siem-b" || len(sh.Misses) != 0 || sh.Problem != "" {
		t.Errorf("round robin: %+v %q", sh, warning)
	}
	if len(choices) != 3 || choices[1].Kind != "self" || choices[2].Kind != "server" || choices[2].URL != "https://siem-b.corp:8080" {
		t.Errorf("choices %+v", choices)
	}

	choices, warning = destinationsOf(ctx, "https://vip.corp:8080", destServers())
	if sh := choices[0]; warning != "" || sh.Problem != "" || len(sh.Reaches) != 0 || sh.Resolves[0].Addr != "10.0.0.100" {
		t.Errorf("load balancer: %+v %q", sh, warning)
	}

	// The public address is one server's own: no failover.
	choices, warning = destinationsOf(ctx, "https://half.corp:8080", destServers())
	if !strings.HasPrefix(warning, "Agents sent to siem-a wait while siem-a is down") {
		t.Errorf("one server: %+v %q", choices[0], warning)
	}

	// A DNS name over some of the servers.
	st := destServers()
	c := server("siem-c", nil)
	c.Detail.NodeURL = "https://10.0.0.7:8080"
	st.Servers = append(st.Servers, c)
	choices, _ = destinationsOf(ctx, "https://siem.corp:8080", st)
	if sh := choices[0]; !strings.Contains(sh.Problem, "reaches siem-a and siem-b but not siem-c") {
		t.Errorf("partial: %+v", sh)
	}

	choices, _ = destinationsOf(ctx, "https://nowhere.corp:8080", destServers())
	if !strings.Contains(choices[0].Problem, "does not resolve") {
		t.Errorf("unresolvable: %+v", choices[0])
	}

	// One server: just the public address and its own.
	one := destServers()
	one.Servers = one.Servers[:1]
	choices, warning = destinationsOf(ctx, "https://half.corp:8080", one)
	if len(choices) != 2 || warning != "" || choices[0].Problem != "" || choices[0].Resolves != nil {
		t.Errorf("one server: %+v %q", choices, warning)
	}
}

func TestAgentConfigTo(t *testing.T) {
	stubDNS(t, map[string][]string{"siem-a.corp": {"10.0.0.5"}, "siem-b.corp": {"10.0.0.6"}})
	ts, _ := newTestServerWith(t, func(s *Server) { s.Cluster = statusCluster{destServers()} })
	code, body := do(t, ts, "GET", "/api/agents/config?os=linux&to=n_siem-b", "", true)
	cfg, _ := body["config"].(string)
	if code != 200 || !strings.Contains(cfg, "Host                 siem-b.corp\n") || !strings.Contains(cfg, "net.keepalive_max_recycle 100\n") {
		t.Errorf("to another server: %d %v", code, body)
	}
	code, body = do(t, ts, "GET", "/api/agents/config?os=linux&to=self", "", true)
	if cfg, _ := body["config"].(string); code != 200 || !strings.Contains(cfg, "Host                 siem-a.corp\n") {
		t.Errorf("to self: %d %v", code, body)
	}
	if code, body = do(t, ts, "GET", "/api/agents/config?os=linux&to=n_nope", "", true); code != 400 || body["field"] != "to" {
		t.Errorf("unknown server: %d %v", code, body)
	}
	code, body = do(t, ts, "GET", "/api/agents/destinations", "", true)
	if ch, _ := body["choices"].([]any); code != 200 || len(ch) != 3 {
		t.Errorf("destinations: %d %v", code, body)
	}

	// Without other servers the configuration is as before: no recycling.
	ts, _ = newTestServerWith(t, nil)
	_, body = do(t, ts, "GET", "/api/agents/config?os=linux", "", true)
	if cfg, _ := body["config"].(string); cfg == "" || strings.Contains(cfg, "keepalive_max_recycle") {
		t.Errorf("single server config: %v", body)
	}
}
