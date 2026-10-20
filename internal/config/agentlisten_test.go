// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestDefaultAgentListen(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:9000":   "0.0.0.0:7779",
		"127.0.0.1:9000": "127.0.0.1:7779",
		"[::1]:9000":     "[::1]:7779",
		":9000":          ":7779",
		"localhost:9000": "localhost:7779",
		"9000":           "",
	} {
		if got := DefaultAgentListen(in); got != want {
			t.Errorf("DefaultAgentListen(%q) = %q, want %q", in, got, want)
		}
	}
}

// An unset server.agent_listen takes the web page's host on port 7779, so
// a loopback-only server takes agents on loopback only, and goes without
// an agent port when 7779 is in use already.
func TestDerivedAgentListen(t *testing.T) {
	t.Setenv("SIGNALITH_AGENT_LISTEN", "")
	c := Default()
	c.Server.Listen, c.Server.AgentListen = "127.0.0.1:9000", ""
	if p := c.agentListenProblems(); len(p) > 0 {
		t.Fatal(p)
	}
	if c.Server.AgentAddr() != "127.0.0.1:7779" || !c.AgentListenDerived() || !c.AgentsOnWebPort() {
		t.Errorf("derived %q %v", c.Server.AgentAddr(), c.AgentListenDerived())
	}
	c.DropDerivedAgentListen()
	if c.Server.AgentAddr() != "" || c.AgentListenDerived() || !c.AgentsOnWebPort() {
		t.Errorf("dropped %q %v", c.Server.AgentAddr(), c.AgentListenDerived())
	}

	for _, used := range []func(*Config){
		func(c *Config) { c.Server.Listen = "0.0.0.0:7779" },
		func(c *Config) { c.Syslog.TCP = "0.0.0.0:7779" },
		func(c *Config) { c.Syslog.TLS = "0.0.0.0:7779" },
	} {
		c := Default()
		c.Server.Listen, c.Server.AgentListen = "0.0.0.0:9000", ""
		used(c)
		if p := c.agentListenProblems(); len(p) > 0 || c.Server.AgentAddr() != "" || c.AgentListenDerived() {
			t.Errorf("7779 in use: %v %q %v", p, c.Server.AgentAddr(), c.AgentListenDerived())
		}
	}

	// A set address is used as it is, and DropDerivedAgentListen keeps it.
	c = Default()
	c.Server.Listen, c.Server.AgentListen = "127.0.0.1:9000", "0.0.0.0:7779"
	c.agentListenProblems()
	c.DropDerivedAgentListen()
	if c.Server.AgentAddr() != "0.0.0.0:7779" || c.AgentsOnWebPort() {
		t.Errorf("set %q %v", c.Server.AgentAddr(), c.AgentsOnWebPort())
	}
}
