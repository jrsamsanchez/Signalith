// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
)

// In demo mode the background jobs that reach other systems or take
// events in do not run, and one keeps the sample data fresh; otherwise
// the jobs are as they were.
func TestDemoJobs(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	var jobs []cluster.Job
	for _, name := range append([]string{"detections", "retention"}, demoOffJobs...) {
		// Each name is a job start() really has, so a renamed job cannot
		// slip back on in demo mode.
		if !strings.Contains(string(src), "Name: "+strconv.Quote(name)) {
			t.Errorf("main.go has no job named %q", name)
		}
		jobs = append(jobs, cluster.Job{Name: name, Run: func(context.Context) {}})
	}
	c := config.Default()
	log := slog.New(slog.DiscardHandler)
	if got := demoJobs(c, jobs, nil, log); len(got) != len(jobs) {
		t.Errorf("without demo mode %d jobs, want %d", len(got), len(jobs))
	}
	c.Demo.Enabled = true
	var names []string
	for _, j := range demoJobs(c, jobs, nil, log) {
		names = append(names, j.Name)
	}
	if strings.Join(names, ",") != "detections,retention,"+demoSampleJob {
		t.Errorf("demo jobs = %v", names)
	}
}

// A server started in demo mode opens no agent port and no syslog port,
// whatever its settings say, and its visitors can sign in.
func TestDemoServerTakesNoEventsIn(t *testing.T) {
	t.Setenv("SIGNALITH_AGENT_LISTEN", "")
	t.Setenv("SIGNALITH_DEMO", "")
	t.Setenv("SIGNALITH_DEMO_ADMIN_NETWORKS", "")
	agents, syslogTLS := freeAddr(t), freeAddr(t)
	rs := startRunnerWith(t, runOptions{server: "  agent_listen: " + agents + "\n",
		extra: "syslog:\n  tls: " + syslogTLS + "\ndemo:\n  enabled: true\n  admin_networks: [127.0.0.1/32]\n"})
	if rs.r.agentPort() != nil {
		t.Error("the demo listens for agents")
	}
	for _, addr := range []string{agents, syslogTLS} {
		if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			conn.Close()
			t.Errorf("the demo listens on %s", addr)
		}
	}
	if !strings.Contains(rs.logs.String(), "this server is a public demo") {
		t.Errorf("the log does not say the server is a demo:\n%s", rs.logs.String())
	}
	resp, err := rs.client.Post(rs.scheme+"://"+rs.addr+"/api/demo", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("demo sign-in = %d", resp.StatusCode)
	}
	if code, _, err := rs.call("", "POST", "/api/ingest", `[{"log":"hello"}]`); code != http.StatusForbidden {
		t.Errorf("ingest on the web port = %d %v", code, err)
	}
}
