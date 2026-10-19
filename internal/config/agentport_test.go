// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestAgentURLOn(t *testing.T) {
	for _, c := range []struct{ raw, listen, want string }{
		{"https://siem.example.com:9000/x", "", "https://siem.example.com:9000/x"},
		{"https://siem.example.com:9000/x", "0.0.0.0:7779", "https://siem.example.com:7779/x"},
		{"https://siem.example.com", "0.0.0.0:7779", "https://siem.example.com:7779"},
		{"https://[::1]:9000", "[::]:7779", "https://[::1]:7779"},
		{"https://siem.example.com:9000", "no-port", "https://siem.example.com:9000"},
		{"not a url", "0.0.0.0:7779", "not a url"},
		{"%zz", "0.0.0.0:7779", "%zz"},
	} {
		if got := AgentURLOn(c.raw, c.listen); got != c.want {
			t.Errorf("AgentURLOn(%q, %q) = %q, want %q", c.raw, c.listen, got, c.want)
		}
	}
}

// The agent port is worked out from the web address unless set, off
// serves agents on the web port, and a bad one is refused.
func TestAgentListenChecks(t *testing.T) {
	c := validConfig(t)
	c.Server.Listen = "127.0.0.1:9000"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Server.AgentListen != "127.0.0.1:7779" || !c.AgentListenDerived() || !c.AgentsOnWebPort() || c.Server.AgentPort() != "7779" {
		t.Errorf("derived %q %v", c.Server.AgentListen, c.AgentListenDerived())
	}
	if n := c.AgentListenNotice(); !strings.Contains(n, "server.agent_listen is not set") {
		t.Errorf("notice %q", n)
	}
	if got := c.AgentURL("https://siem.example.com:9000"); got != "https://siem.example.com:7779" {
		t.Errorf("AgentURL %q", got)
	}
	c.DropDerivedAgentListen()
	if c.Server.AgentListen != "" || c.Server.AgentPort() != "9000" {
		t.Errorf("after dropping: %q, port %s", c.Server.AgentListen, c.Server.AgentPort())
	}

	c = validConfig(t)
	c.Server.AgentListen = " OFF "
	if err := c.Validate(); err != nil || c.Server.AgentListen != AgentListenOff || c.Server.AgentAddr() != "" || !c.AgentsOnWebPort() || c.AgentListenNotice() != "" {
		t.Errorf("off: %v %q", err, c.Server.AgentListen)
	}

	// The default port in use already by syslog: no agent port.
	c = validConfig(t)
	c.Syslog.TCP = "0.0.0.0:" + DefaultAgentPort
	_ = c.Validate()
	if c.Server.AgentListen != "" {
		t.Errorf("agent port taken from syslog: %q", c.Server.AgentListen)
	}
	if DefaultAgentListen("nope") != "" {
		t.Error("a default from a listen address that is not host:port")
	}

	for listen, want := range map[string]string{
		"nope":            "must be host:port",
		"0.0.0.0:99999":   "port \"99999\" must be 1-65535",
		"siem.local:7779": "host \"siem.local\" must be an IP address",
	} {
		c := validConfig(t)
		c.Server.AgentListen = listen
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", listen, err)
		}
	}
}
