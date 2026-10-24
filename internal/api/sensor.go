// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/clusterinstall"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// A network sensor built by the sensor install script (Add data > Network
// sensor > Set up a new sensor). The page makes the line (GET
// /api/sensor/install); the line downloads the script (GET
// /api/sensor/install.sh, public like Add a server's); the script, holding
// the sensor's own agent token, fetches the Fluent Bit configuration (GET
// /api/sensor/config) and waits until its first batch arrived (GET
// /api/sensor/seen). Once set up, the sensor fetches the rule tuning
// every 10 minutes (GET /api/sensor/tuning, sensors.go). Those three check
// the token themselves, as ingest does: the sensor has nothing else to
// sign in with.

// sensorPublicRoutes check the sensor's agent token instead of a sign-in.
var sensorPublicRoutes = []string{
	"GET /api/sensor/config",
	"GET /api/sensor/seen",
	"GET /api/sensor/tuning",
}

func (s *Server) routeSensor(mux *http.ServeMux, api *router) {
	mux.HandleFunc("GET /api/sensor/install.sh", s.handleInstallScript(clusterinstall.ScriptSensor))
	api.admin("GET /api/sensor/install", s.handleSensorInstall)
}

// routeSensorAgent registers the routes a sensor calls with its token.
func (s *Server) routeSensorAgent(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/sensor/config", s.handleSensorConfig)
	mux.HandleFunc("GET /api/sensor/seen", s.handleSensorSeen)
	mux.HandleFunc("GET /api/sensor/tuning", s.handleSensorTuningFetch)
}

// msgSensorHTTPS is why no line is made for a server reached over plain
// HTTP.
const msgSensorHTTPS = "Turn on HTTPS first: a sensor sends what it sees on your network, so it only sends over HTTPS (Settings > HTTPS)."

// sensorInstall is the answer to GET /api/sensor/install.
type sensorInstall struct {
	clusterinstall.SensorCommands
	// CASHA256 and NextCASHA256 are the certificate authorities the line
	// pins (hex), for the page to show.
	CASHA256     string `json:"ca_sha256,omitempty"`
	NextCASHA256 string `json:"next_ca_sha256,omitempty"`
	// TokenPlaceholder stands for the sensor's token in the line, until
	// the page makes one.
	TokenPlaceholder string `json:"token_placeholder"`
	// AddName is the address the certificate does not cover yet, for the
	// page to add (as for agent configurations).
	AddName string `json:"add_name,omitempty"`
}

// sha256Hex turns a fingerprint written AB:CD:... into lower-case hex.
func sha256Hex(fp string) string {
	return strings.ToLower(strings.ReplaceAll(fp, ":", ""))
}

// handleSensorInstall makes the sensor's pasted line. The address the
// sensor sends to is checked as for an agent configuration (Add data),
// and must be https.
func (s *Server) handleSensorInstall(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	conf := s.conf()
	fieldError := func(field string, err error) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "field": field})
	}
	server := conf.Server.PublicURL
	if o := v.Get("server"); o != "" {
		server = o
	}
	server = s.agentURL(server)
	u, err := agents.ParseServerURL(server)
	if err != nil {
		fieldError("server", err)
		return
	}
	if u.Scheme != "https" {
		fieldError("server", errors.New(msgSensorHTTPS))
		return
	}
	certs := s.TLS
	if !conf.Server.HTTPS() {
		certs = nil
	}
	addName := ""
	line := clusterinstall.SensorLine{
		URL:       u.Scheme + "://" + u.Host,
		Version:   s.Version,
		Interface: strings.TrimSpace(v.Get("interface")),
		Networks:  v.Get("networks"),
		Zeek:      v.Get("zeek") != "false",
		Suricata:  v.Get("suricata") != "false",
		Protocols: v.Get("protocols") == "true",
		Docker:    v.Get("docker") == "true",
		OT:        v.Get("ot") == "true",
	}
	if line.Version == "" {
		line.Version = "dev"
	}
	if certs != nil {
		if err := certs.CanCover(u.Hostname()); err != nil {
			fieldError("server", err)
			return
		}
		if !certs.Covers(u.Hostname()) {
			addName = u.Hostname()
		}
		if certs.CAPEM() == nil && !certs.PublicCA() {
			fieldError("server", errors.New("This server's certificate file does not include the certificate authority that issued it, so a sensor cannot check it. Add that CA to the end of the certificate file (server.tls_cert), or let Signalith make its own certificate."))
			return
		}
		if fp := certs.Fingerprint(); fp != "" {
			line.CASHA256 = sha256Hex(fp)
			if next := certs.Next(); next != nil && certs.LocalCA() {
				line.NextCASHA256 = sha256Hex(next.Fingerprint)
			}
		}
	}
	// The configuration the sensor will fetch must be possible too: an
	// address by IP with a CA that vouches for other computers has no
	// name to check, which the page shows under the address now rather
	// than on the sensor later.
	opts := s.sensorAgentOptions(server, agents.SensorPackages, line.Zeek, line.Suricata, line.Protocols, certs)
	if _, err := agents.Generate(opts); errors.Is(err, agents.ErrNoNameToCheck) {
		fieldError("server", err)
		return
	}
	c, err := clusterinstall.SensorLines(line)
	var fe *clusterinstall.FieldError
	if errors.As(err, &fe) {
		fieldError(fe.Field, fe.Err)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, sensorInstall{SensorCommands: c, CASHA256: line.CASHA256, NextCASHA256: line.NextCASHA256,
		TokenPlaceholder: agents.TokenPlaceholder, AddName: addName})
}

// sensorAgentOptions are the Fluent Bit options of a sensor the install
// script builds: the token from the unit's environment and the status
// line.
func (s *Server) sensorAgentOptions(server, layout string, zeek, suricata, protocols bool, certs *tlsauto.Manager) agents.Options {
	o := agents.Options{OS: "linux", LinuxSource: "sensor", SensorLayout: layout, Heartbeat: true,
		ServerURL: server, Token: agents.EnvToken, Version: s.Version,
		Zeek: zeek, Suricata: suricata, SuricataProtocols: protocols}
	agentTLS(&o, certs)
	return o
}

// sensorToken checks the agent token of a request from the sensor
// install script, and answers the request when it is refused. Only an
// active token made for a sensor passes, so the script can say plainly
// what is wrong before it installs anything.
func (s *Server) sensorToken(w http.ResponseWriter, r *http.Request) (agenttokens.Identity, bool) {
	id, res := s.tokens().Check(bearerToken(r))
	switch res {
	case agenttokens.Valid:
	case agenttokens.NotLoaded:
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Signalith is still starting (agent tokens are loading); try again in a minute.", "code": agenttokens.CodeLoading})
		return id, false
	case agenttokens.Revoked:
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "This token was revoked. Make the line again on Add data > Network sensor > Set up a new sensor: it holds a new token.", "code": "token_revoked"})
		return id, false
	default:
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "Signalith does not know this token. Copy the whole line again from Add data > Network sensor > Set up a new sensor.", "code": "token_unknown"})
		return id, false
	}
	if id.Legacy || id.Purpose != agenttokens.PurposeSensor {
		what := "a shared token from the configuration"
		if !id.Legacy {
			what = "a token for other agents"
			if id.Purpose != "" {
				what = "a token for " + id.Purpose + " agents"
			}
		}
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "This is " + what + ", not a sensor token. Make the line on Add data > Network sensor > Set up a new sensor: it holds a sensor token.", "code": "token_purpose"})
		return id, false
	}
	return id, true
}

// handleSensorConfig hands the sensor install script the sensor's Fluent
// Bit configuration, made by the same generator as every agent's, for
// the address the sensor reaches this server at (server). The token is
// read from the sensor's environment (agents.EnvToken), so the file
// holds no secret.
func (s *Server) handleSensorConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sensorToken(w, r); !ok {
		return
	}
	v := r.URL.Query()
	conf := s.conf()
	server := v.Get("server")
	if server == "" {
		server = conf.Server.PublicURL
	}
	server = s.agentURL(server)
	u, err := agents.ParseServerURL(server)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("server: %w", err))
		return
	}
	if u.Scheme != "https" {
		writeError(w, http.StatusBadRequest, errors.New(msgSensorHTTPS))
		return
	}
	layout := v.Get("layout")
	if layout == "" {
		layout = agents.SensorPackages
	}
	if layout != agents.SensorPackages && layout != agents.SensorDocker {
		writeError(w, http.StatusBadRequest, errors.New("layout must be packages or docker"))
		return
	}
	certs := s.TLS
	if !conf.Server.HTTPS() {
		certs = nil
	}
	opts := s.sensorAgentOptions(server, layout, v.Get("zeek") != "false", v.Get("suricata") != "false", v.Get("protocols") == "true", certs)
	a, err := agents.Generate(opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(a.Config))
}

// sensorSeen is the answer to GET /api/sensor/seen.
type sensorSeen struct {
	// LastSeen is when a batch sent with the token last arrived; nil
	// before the first.
	LastSeen *time.Time `json:"last_seen"`
	Events1h int64      `json:"events_1h"`
}

// handleSensorSeen tells the sensor install script whether its batches
// arrive: when the newest one sent with the calling token came, from the
// agent inventory. Only the caller's own token is looked up.
func (s *Server) handleSensorSeen(w http.ResponseWriter, r *http.Request) {
	who, ok := s.sensorToken(w, r)
	if !ok {
		return
	}
	list, _, err := s.agents().List(r.Context())
	if err != nil {
		// This server's own agents are listed still; the sensor sends
		// to the address it fetched the script from.
		s.Log.Warn("the agents other servers heard from could not be read", "err", err)
	}
	var out sensorSeen
	for _, a := range list {
		if a.TokenID != who.ID || a.Refusing {
			continue
		}
		if out.LastSeen == nil || a.LastSeen.After(*out.LastSeen) {
			t := a.LastSeen
			out.LastSeen = &t
		}
		out.Events1h += a.Events1h
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}
