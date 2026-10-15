package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// DefaultAgentPort is the port agents send to when server.agent_listen
// is not set: the web page has a port of its own (9000 by default).
const DefaultAgentPort = "7779"

// AgentListenOff is the server.agent_listen value that serves agents on
// the web port, as before Signalith 0.3.
const AgentListenOff = "off"

// AgentAddr is the address agents are served on: server.agent_listen, or
// "" when it is off and agents send to the web port.
func (s Server) AgentAddr() string {
	if strings.EqualFold(s.AgentListen, AgentListenOff) {
		return ""
	}
	return s.AgentListen
}

// AgentPort is the port agents send to: agent_listen's, or the web
// port's when that is off.
func (s Server) AgentPort() string {
	addr := s.AgentAddr()
	if addr == "" {
		addr = s.Listen
	}
	_, port, _ := net.SplitHostPort(addr)
	return port
}

// AgentsOnWebPort reports whether the web port serves agents too: when
// server.agent_listen is off, or was not set at all, which is how a
// server installed before 0.3 keeps its agents working until they are
// set up again (new installs set it).
func (c *Config) AgentsOnWebPort() bool {
	return c.Server.AgentAddr() == "" || c.agentListenDerived
}

// AgentListenDerived reports whether server.agent_listen was worked out
// from the listen address because it was empty.
func (c *Config) AgentListenDerived() bool { return c.agentListenDerived }

// AgentURL turns an address of this server (such as server.public_url or
// one typed on Add data) into the one agents send to: the same scheme and
// host, on the agent port. With agents on the web port it is unchanged.
func (c *Config) AgentURL(raw string) string {
	return AgentURLOn(raw, c.Server.AgentAddr())
}

// AgentURLOn is AgentURL for a server whose agent listen address is
// agentListen ("" when agents send to its web port).
func AgentURLOn(raw, agentListen string) string {
	if agentListen == "" {
		return raw
	}
	_, port, err := net.SplitHostPort(agentListen)
	if err != nil {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return raw
	}
	u.Host = net.JoinHostPort(u.Hostname(), port)
	return u.String()
}

// agentListenProblems fills server.agent_listen in when it is empty and
// checks it. Validating again starts from the setting as it was given.
func (c *Config) agentListenProblems() []string {
	if c.agentListenDerived {
		c.Server.AgentListen = ""
	}
	c.agentListenDerived = false
	c.Server.AgentListen = strings.TrimSpace(c.Server.AgentListen)
	if strings.EqualFold(c.Server.AgentListen, AgentListenOff) {
		c.Server.AgentListen = AgentListenOff
		return nil
	}
	if c.Server.AgentListen == "" {
		host, _, err := net.SplitHostPort(c.Server.Listen)
		if err != nil {
			return nil // server.listen's own problem
		}
		c.Server.AgentListen, c.agentListenDerived = net.JoinHostPort(host, DefaultAgentPort), true
	}
	host, port, err := net.SplitHostPort(c.Server.AgentListen)
	if err != nil {
		return []string{fmt.Sprintf("server.agent_listen %q must be host:port, for example 0.0.0.0:%s (or off to serve agents on the web port)", c.Server.AgentListen, DefaultAgentPort)}
	}
	var p []string
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		p = append(p, fmt.Sprintf("server.agent_listen port %q must be 1-65535", port))
	}
	if _, err := netip.ParseAddr(host); err != nil && host != "" && host != "localhost" {
		p = append(p, fmt.Sprintf("server.agent_listen host %q must be an IP address of this server, or 0.0.0.0 for all of them", host))
	}
	return p
}

// AgentListenNotice says, for a server whose web port still accepts
// agents because server.agent_listen was not set, how to stop that; ""
// otherwise.
func (c *Config) AgentListenNotice() string {
	if !c.agentListenDerived {
		return ""
	}
	return "server.agent_listen is not set, so the web port (" + c.Server.Listen + ") still accepts agents set up before Signalith 0.3, " +
		"besides the agent port (" + c.Server.AgentListen + "). Set agents up again from the Add data page, then set server.agent_listen to " +
		c.Server.AgentListen + " so the web port takes no agent traffic. The next release stops accepting agents on the web port."
}
