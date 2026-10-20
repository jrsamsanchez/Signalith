// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sendBatch posts one event to url's /api/ingest with the test token.
func sendBatch(t *testing.T, url string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/api/ingest", strings.NewReader(`[{"log":"hello"}]`))
	req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(body)
}

// TestAgentPort: with server.agent_listen set, agents send to the agent
// port alone. The web port tells an agent where to send with a 503, which
// agents retry, so it keeps its events; the agent port serves nothing but
// what agents call.
func TestAgentPort(t *testing.T) {
	ts, srv, _ := newSettingsServer(t, "server:\n  listen: 0.0.0.0:9000\n  agent_listen: 0.0.0.0:7779\n", nil)
	agents := httptest.NewServer(srv.AgentHandler())
	t.Cleanup(agents.Close)

	code, hdr, body := sendBatch(t, ts.URL)
	if code != http.StatusServiceUnavailable || hdr.Get("Retry-After") == "" || !strings.Contains(body, "port 7779") {
		t.Errorf("web port: %d %q %s", code, hdr.Get("Retry-After"), body)
	}
	if code, _, body := sendBatch(t, agents.URL); code != http.StatusOK {
		t.Errorf("agent port: %d %s", code, body)
	}
	// Nothing for browsers or the API on the agent port, signed in or not.
	for _, path := range []string{"/", "/login", "/api/health", "/api/settings"} {
		req, _ := http.NewRequest("GET", agents.URL+path, nil)
		req.SetBasicAuth("admin", "s3cret-pass")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("agent port GET %s: %d", path, resp.StatusCode)
		}
	}
	// What the sensor install line fetches answers as on the web port.
	for _, path := range []string{"/api/sensor/install.sh", "/api/tls/ca.pem"} {
		var codes []int
		for _, base := range []string{ts.URL, agents.URL} {
			resp, err := http.Get(base + path)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			codes = append(codes, resp.StatusCode)
		}
		if codes[0] != codes[1] {
			t.Errorf("GET %s: web port %d, agent port %d", path, codes[0], codes[1])
		}
	}
}

// TestAgentsOnWebPortUntilSet: a server whose signalith.yaml predates the
// agent port (server.agent_listen not set) keeps taking agents on the web
// port too, and notes each one, until it is set.
func TestAgentsOnWebPortUntilSet(t *testing.T) {
	ts, srv, logs := newSettingsServer(t, "server:\n  listen: 0.0.0.0:8080\n", nil)
	if a := srv.conf().Server.AgentListen; a != "0.0.0.0:7779" {
		t.Fatalf("agent_listen = %q", a)
	}
	if code, _, body := sendBatch(t, ts.URL); code != http.StatusOK {
		t.Errorf("web port: %d %s", code, body)
	}
	if !strings.Contains(logs.String(), "an agent sends to the web port") {
		t.Errorf("not noted:\n%s", logs)
	}
	agents := httptest.NewServer(srv.AgentHandler())
	t.Cleanup(agents.Close)
	if code, _, body := sendBatch(t, agents.URL); code != http.StatusOK {
		t.Errorf("agent port: %d %s", code, body)
	}
}

// TestAgentListenOff: agents send to the web port, as before 0.3, and
// agent configurations name it.
func TestAgentListenOff(t *testing.T) {
	ts, _, logs := newSettingsServer(t, "server:\n  listen: 0.0.0.0:9000\n  public_url: http://siem.example.com:9000\n  agent_listen: \"off\"\n  tls:\n    mode: \"off\"\n", nil)
	if code, _, body := sendBatch(t, ts.URL); code != http.StatusOK {
		t.Errorf("web port: %d %s", code, body)
	}
	if strings.Contains(logs.String(), "an agent sends to the web port") {
		t.Errorf("noted with the agent port off:\n%s", logs)
	}
	if _, body := do(t, ts, "GET", "/api/agents/config?os=linux", "", true); body["server_url"] != "http://siem.example.com:9000" {
		t.Errorf("server_url = %v", body["server_url"])
	}
}
