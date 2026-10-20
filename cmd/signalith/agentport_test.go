// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestAgentPort: agents send to server.agent_listen over HTTPS with the
// web page's certificate, the web port turns them away, load balancers
// can check the agent port, a restart keeps it open, and one that moves
// it listens at the new address.
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
	// The server is ready once its first heartbeat reached OpenSearch,
	// which can come a moment after it takes events; a load balancer
	// asks again.
	ready := 0
	for deadline := time.Now().Add(15 * time.Second); ; {
		resp, err := rs.client.Get("https://" + agents + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if ready = resp.StatusCode; ready == http.StatusOK || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if ready != http.StatusOK {
		t.Errorf("readyz on the agent port: %d", ready)
	}

	// A restart that keeps the address keeps the port open: agents
	// sending meanwhile are held back, never refused or reset.
	open := rs.r.agentPort()
	stop := make(chan struct{})
	failed := make(chan string, 1)
	go func() {
		defer close(failed)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if code, err := send(agents); code == 0 {
				failed <- err
				return
			}
		}
	}()
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart: %+v\n%s", res, rs.logs.String())
	}
	close(stop)
	if err, ok := <-failed; ok {
		t.Errorf("an agent could not reach the agent port during a restart: %s", err)
	}
	if rs.r.agentPort() != open {
		t.Error("a restart that keeps the agent address listened again")
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
