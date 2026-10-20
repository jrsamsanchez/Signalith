// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/clusterinstall"
)

// Agents send to a port of their own (server.agent_listen, 7779 by
// default), apart from the web page and API: AgentHandler serves it. The
// web port serves the same routes only while the configuration says
// agents may still send there (config.AgentsOnWebPort): with
// server.agent_listen off, or not set on a server installed before 0.3.

// agentRoutes are the routes agents call. They check an agent token or
// osquery node key themselves, never a sign-in.
var agentRoutes = slices.Concat([]string{"POST /api/ingest", otlpLogsRoute}, osqueryRoutes, sensorPublicRoutes, hecRoutes, agentManagedRoutes)

// routeAgentIntake registers the agent routes on mux.
func (s *Server) routeAgentIntake(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/ingest", s.handleIngest)
	mux.HandleFunc(otlpLogsRoute, s.handleOTLPLogs)
	s.routeOsquery(mux)
	s.routeSensorAgent(mux)
	s.routeHEC(mux)
	s.routeAgentManagedIntake(mux)
}

// AgentHandler returns the handler of the agent port: the agent routes,
// the certificate authority and the install scripts of the sensor and the
// Signalith Agent, which their pasted lines fetch from the address they
// send to.
func (s *Server) AgentHandler() http.Handler {
	if s.demo() {
		// A public demo takes no events in, and hands out no installs.
		return limitBodies(s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writeDemoOff(w) })))
	}
	s.tokens()
	mux := http.NewServeMux()
	s.routeAgentIntake(mux)
	mux.HandleFunc("GET /api/tls/ca.pem", s.handleCAPEM)
	mux.HandleFunc("GET /api/sensor/install.sh", s.handleInstallScript(clusterinstall.ScriptSensor))
	mux.HandleFunc("GET "+agentproto.RouteInstallSH, s.handleInstallScript(clusterinstall.ScriptAgent))
	mux.HandleFunc("GET "+agentproto.RouteInstallPS1, s.handleInstallScript(clusterinstall.ScriptAgentPS1))
	mux.HandleFunc("GET "+agentproto.RouteInstallMacOS, s.handleInstallScript(clusterinstall.ScriptAgentMac))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, fmt.Errorf("this port is for agents; the web page is at %s", s.conf().Server.PublicURL))
	})
	return limitBodies(s.securityHeaders(mux))
}

// AgentPlainHandler answers plain HTTP on the agent port when it serves
// HTTPS, as PlainHandler does on the web port.
func (s *Server) AgentPlainHandler(secure http.Handler) http.Handler {
	return s.plainHandler(secure, false)
}

// webPortAgents serves an agent route on the web port while agents may
// still send there, noting each agent that does once a day; otherwise it
// tells the agent where to send. The answer is 503, which agents retry,
// so they keep their events until they are set up again.
func (s *Server) webPortAgents(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := s.conf()
		if c.Server.AgentAddr() == "" {
			h.ServeHTTP(w, r)
			return
		}
		from := clientaddr.Parse(r.RemoteAddr).String()
		if c.AgentsOnWebPort() {
			if s.Log != nil && s.webAgentLog.due(from, 24*time.Hour) {
				s.Log.Warn("an agent sends to the web port; set it up again from the Add data page so it sends to the agent port",
					"from", from, "path", r.URL.Path, "agent_port", c.Server.AgentPort())
			}
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("agents send to port %s on this server, not the web port; set this agent up again from the Add data page",
			c.Server.AgentPort()))
	})
}

// agentURL is the address agents send to for raw, an address of this
// server such as server.public_url: the same host on the agent port.
func (s *Server) agentURL(raw string) string { return s.conf().AgentURL(raw) }
