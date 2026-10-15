package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestAgentPort: agents send to server.agent_listen over HTTPS with the
// web page's certificate, the web port turns them away, load balancers
// can check the agent port, and a restart that moves it listens at the
// new address.
func TestAgentPort(t *testing.T) {
	t.Setenv("SIGNALITH_AGENT_LISTEN", "")
	agents := freeAddr(t)
	rs := startRunnerWith(t, runOptions{server: "  agent_listen: " + agents + "\n"})
	send := func(addr string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("POST", "https://"+addr+"/api/ingest", strings.NewReader(`[{"log":"hello"}]`))
		req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
		resp, err := rs.client.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		resp.Body.Close()
		return resp.StatusCode, ""
	}
	if code, err := send(agents); code != http.StatusOK {
		t.Fatalf("agent port: %d %s\n%s", code, err, rs.logs.String())
	}
	if code, err := send(rs.addr); code != http.StatusServiceUnavailable {
		t.Errorf("web port: %d %s", code, err)
	}
	resp, err := rs.client.Get("https://" + agents + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("readyz on the agent port: %d", resp.StatusCode)
	}

	moved := freeAddr(t)
	rs.save(`{"server.agent_listen":"` + moved + `"}`)
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart: %+v\n%s", res, rs.logs.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, _ := send(moved)
		if code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the moved agent port does not take agents: %d\n%s", code, rs.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code, _ := send(agents); code != 0 {
		t.Errorf("the old agent port still answers: %d", code)
	}
}
