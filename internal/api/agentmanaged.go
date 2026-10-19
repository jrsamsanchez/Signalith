// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/clusterinstall"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// The Signalith Agent (Add data > Signalith Agent): one program per
// computer that runs the collectors for it (see internal/agentproto). The
// page makes the pasted line (GET /api/agent/install); the line downloads
// the install script (GET /api/agent/install.sh, or install.ps1 for
// Windows, public like the sensor's). The script and then the agent hold an agent token made for
// the agent (purpose agent): with it the script downloads the agent
// program (GET /api/agent/program) and the agent fetches its
// configuration (GET /api/agent/config) and reports its status (POST
// /api/agent/status) every few minutes. Those three check the token
// themselves, as ingest does.

// agentManagedRoutes check the Signalith Agent's token instead of a
// sign-in.
var agentManagedRoutes = []string{
	"GET " + agentproto.RouteConfig,
	"POST " + agentproto.RouteStatus,
	"GET " + agentproto.RouteProgram,
	"GET " + agentproto.RouteManifest,
}

// agentPollSeconds is how often an agent fetches its configuration and
// reports its status.
const agentPollSeconds = 300

func (s *Server) routeAgentManaged(mux *http.ServeMux, api *router) {
	mux.HandleFunc("GET "+agentproto.RouteInstallSH, s.handleInstallScript(clusterinstall.ScriptAgent))
	mux.HandleFunc("GET "+agentproto.RouteInstallPS1, s.handleInstallScript(clusterinstall.ScriptAgentPS1))
	mux.HandleFunc("GET "+agentproto.RouteInstallMacOS, s.handleInstallScript(clusterinstall.ScriptAgentMac))
	api.admin("GET /api/agent/install", s.handleAgentInstall)
}

// routeAgentManagedIntake registers the routes the agent calls with its
// token.
func (s *Server) routeAgentManagedIntake(mux *http.ServeMux) {
	mux.HandleFunc("GET "+agentproto.RouteConfig, s.handleAgentManagedConfig)
	mux.HandleFunc("POST "+agentproto.RouteStatus, s.handleAgentManagedStatus)
	mux.HandleFunc("GET "+agentproto.RouteProgram, s.handleAgentManagedProgram)
	mux.HandleFunc("GET "+agentproto.RouteManifest, s.handleAgentManagedManifest)
}

// agentPrograms returns the agent programs this server hands out.
func (s *Server) agentPrograms() *clusterinstall.Programs {
	s.agentProgramsOnce.Do(func() {
		if s.AgentPrograms == nil {
			s.AgentPrograms = &clusterinstall.Programs{}
		}
	})
	return s.AgentPrograms
}

// msgAgentHTTPS is why no line is made for a server reached over plain
// HTTP.
const msgAgentHTTPS = "Turn on HTTPS first: the agent fetches its configuration and sends events only over HTTPS (Settings > HTTPS)."

// agentInstall is the answer to GET /api/agent/install.
type agentInstall struct {
	clusterinstall.AgentCommands
	// CASHA256 and NextCASHA256 are the certificate authorities the line
	// pins (hex), for the page to show.
	CASHA256     string `json:"ca_sha256,omitempty"`
	NextCASHA256 string `json:"next_ca_sha256,omitempty"`
	// TokenPlaceholder stands for the agent token in the line, until the
	// page makes one.
	TokenPlaceholder string `json:"token_placeholder"`
	// AddName is the address the certificate does not cover yet, for the
	// page to add (as for agent configurations).
	AddName string `json:"add_name,omitempty"`
	// Programs are the platforms (os-arch) this server has the agent
	// program for; the page warns when the one picked is missing.
	Programs []string `json:"programs"`
}

// handleAgentInstall makes the agent's pasted line. The address the agent
// sends to is checked as for an agent configuration, and must be https.
func (s *Server) handleAgentInstall(w http.ResponseWriter, r *http.Request) {
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
		fieldError("server", errors.New(msgAgentHTTPS))
		return
	}
	certs := s.TLS
	if !conf.Server.HTTPS() {
		certs = nil
	}
	addName := ""
	line := clusterinstall.AgentLine{URL: u.Scheme + "://" + u.Host, Version: s.Version}
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
			fieldError("server", errors.New("This server's certificate file does not include the certificate authority that issued it, so an agent cannot check it. Add that CA to the end of the certificate file (server.tls_cert), or let Signalith make its own certificate."))
			return
		}
		if fp := certs.Fingerprint(); fp != "" {
			line.CASHA256 = sha256Hex(fp)
			if next := certs.Next(); next != nil && certs.LocalCA() {
				line.NextCASHA256 = sha256Hex(next.Fingerprint)
			}
		}
	}
	// The configuration the agent will fetch must be possible too (see
	// handleSensorInstall).
	for _, goos := range []string{"linux", "windows"} {
		opts := s.agentManagedOptions(server, goos, agentFacts{}, agenttokens.Collect{}, certs)
		if _, err := agents.Generate(opts); errors.Is(err, agents.ErrNoNameToCheck) {
			fieldError("server", err)
			return
		}
	}
	c, err := clusterinstall.AgentLines(line)
	var fe *clusterinstall.FieldError
	if errors.As(err, &fe) {
		fieldError(fe.Field, fe.Err)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, agentInstall{AgentCommands: c, CASHA256: line.CASHA256, NextCASHA256: line.NextCASHA256,
		TokenPlaceholder: agents.TokenPlaceholder, AddName: addName, Programs: s.agentPrograms().Available()})
}

// agentFacts are what an agent says about its computer when it fetches
// its configuration, which decide what the configuration collects where
// an admin has not chosen otherwise (agenttokens.Collect, set on the
// Endpoints page for each install line): which file the Linux sign-in log
// is in, and whether Sysmon runs and osquery is installed.
type agentFacts struct {
	// Source is the Linux sign-in log: file (auth.log or secure) or
	// journal (the systemd journal only).
	Source  string
	Sysmon  bool
	Osquery bool
}

// with returns the facts as the admin's choices c leave them: a
// collector turned off counts as missing, and a sign-in log chosen
// replaces the one the agent found.
func (f agentFacts) with(c agenttokens.Collect) agentFacts {
	if c.Sysmon == agenttokens.CollectOff {
		f.Sysmon = false
	}
	if c.Osquery == agenttokens.CollectOff {
		f.Osquery = false
	}
	if c.LinuxLog != "" {
		f.Source = c.LinuxLog
	}
	return f
}

// agentManagedOptions are the Fluent Bit options of an agent on goos that
// sends to server and collects as c says, with the certificate made by
// certs (nil when Signalith does not serve HTTPS itself).
func (s *Server) agentManagedOptions(server, goos string, f agentFacts, c agenttokens.Collect, certs *tlsauto.Manager) agents.Options {
	f = f.with(c)
	o := agents.Options{OS: goos, ServerURL: server, Token: agents.EnvToken, Version: s.Version, Managed: true,
		Recycle: s.agentRecycleFor(), Sysmon: f.Sysmon}
	switch goos {
	case "linux":
		o.LinuxSource = "file"
		if f.Source == "journal" {
			o.LinuxSource = "journal"
		}
		o.NoWebLogs = c.WebLogs == agenttokens.CollectOff
		o.NoAuditLog = c.AuditLog == agenttokens.CollectOff
	case "windows":
		o.PowerShell = c.PowerShell != agenttokens.CollectOff
	}
	agentTLS(&o, certs)
	return o
}

// agentManagedToken checks the agent token of a request from the
// Signalith Agent or its install script, and answers the request when it
// is refused. Only an active token made for the agent passes.
func (s *Server) agentManagedToken(w http.ResponseWriter, r *http.Request) (agenttokens.Identity, bool) {
	id, res := s.tokens().Check(bearerToken(r))
	switch res {
	case agenttokens.Valid:
	case agenttokens.NotLoaded:
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Signalith is still starting (agent tokens are loading); try again in a minute.", "code": agenttokens.CodeLoading})
		return id, false
	case agenttokens.Revoked:
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "This token was revoked. Make the line again on Add data > Signalith Agent: it holds a new token.", "code": "token_revoked"})
		return id, false
	default:
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "Signalith does not know this token. Copy the whole line again from Add data > Signalith Agent.", "code": "token_unknown"})
		return id, false
	}
	if id.Legacy || id.Purpose != agenttokens.PurposeAgent {
		what := "a shared token from the configuration"
		if !id.Legacy {
			what = "a token for other agents"
			if id.Purpose != "" {
				what = "a token for " + id.Purpose + " agents"
			}
		}
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "This is " + what + ", not a Signalith Agent token. Make the line on Add data > Signalith Agent: it holds an agent token.", "code": "token_purpose"})
		return id, false
	}
	return id, true
}

// agentManagedTenant sends a request of a tenant's agent to that tenant's
// server, as ingest does; true when it was answered.
func (s *Server) agentManagedTenant(w http.ResponseWriter, r *http.Request, h func(*Server, http.ResponseWriter, *http.Request)) bool {
	t, wait := s.agentTenant(r)
	if wait {
		w.Header().Set("Retry-After", tenantAgentRetry)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": tenantAgentWait, "code": "tenant_unavailable"})
		return true
	}
	if t != nil {
		h(t, w, r)
		return true
	}
	return false
}

// agentPlatform reads ?os=&arch= and checks them.
func agentPlatform(r *http.Request) (goos, goarch string, err error) {
	q := r.URL.Query()
	goos, goarch = q.Get("os"), q.Get("arch")
	for _, p := range agentproto.Platforms {
		if p == goos+"-"+goarch {
			return goos, goarch, nil
		}
	}
	return "", "", fmt.Errorf("os and arch must be one of %s", strings.Join(agentproto.Platforms, ", "))
}

// handleAgentManagedConfig hands an agent its configuration: Fluent Bit's,
// made by the same generator as every agent's for the address the agent
// reaches this server at (?server=), which reads the token from the agent (so the
// file holds no secret), the certificate authority, and osquery's flags
// when the computer has osquery (?osquery=true). What it collects is what
// the computer has, as the admin's choices for the agent's install line
// leave it (agenttokens.Collect). A configuration
// that has not changed since the revision the agent has is answered 304.
func (s *Server) handleAgentManagedConfig(w http.ResponseWriter, r *http.Request) {
	if s.agentManagedTenant(w, r, (*Server).handleAgentManagedConfig) {
		return
	}
	who, ok := s.agentManagedToken(w, r)
	if !ok {
		return
	}
	goos, _, err := agentPlatform(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	conf := s.conf()
	certs := s.TLS
	if !conf.Server.HTTPS() {
		certs = nil
	}
	// The address the agent reaches this server at (the SERVER its install
	// line wrote) is the one its Fluent Bit sends to.
	q := r.URL.Query()
	server := q.Get("server")
	if server == "" {
		server = conf.Server.PublicURL
	}
	server = s.agentURL(server)
	if u, err := agents.ParseServerURL(server); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("server: %w", err))
		return
	} else if u.Scheme != "https" {
		writeError(w, http.StatusBadRequest, errors.New(msgAgentHTTPS))
		return
	}
	facts := agentFacts{Source: q.Get("source"), Sysmon: q.Get("sysmon") == "true", Osquery: q.Get("osquery") == "true"}
	// What the admin chose for the agent's install line.
	collect := s.tokens().Collect(who.ID)
	cfg := agentproto.Config{PollSeconds: agentPollSeconds}
	if goos == "linux" || goos == "windows" {
		opts := s.agentManagedOptions(server, goos, facts, collect, certs)
		a, err := agents.Generate(opts)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		cfg.FluentBit = &agentproto.FluentBit{Config: a.Config}
		cfg.CA = a.CA
		if facts.with(collect).Osquery {
			cfg.Osquery = agentOsquery(goos, opts)
		}
	} else if goos == "darwin" {
		// On macOS osquery is the agent's only collector: program starts,
		// inventory, file changes and checks.
		opts := s.agentManagedOptions(server, goos, facts, collect, certs)
		cfg.CA = strings.TrimSpace(opts.CA)
		if facts.with(collect).Osquery {
			cfg.Osquery = agentOsquery(goos, opts)
		}
	}
	cfg.Update = s.agentUpdate(r, goos, collect)
	cfg.Revision = agentproto.RevisionOf(cfg)
	etag := `"` + cfg.Revision + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// agentUpdate is the update to offer the agent of r, nil when there is
// none or the admin paused updates for its install line. The agent says
// its version in a header; it checks the update against the signed
// manifest itself.
func (s *Server) agentUpdate(r *http.Request, goos string, c agenttokens.Collect) *agentproto.Update {
	if c.Updates == agenttokens.CollectOff {
		return nil
	}
	u, err := s.agentPrograms().Update(goos, r.URL.Query().Get("arch"), r.Header.Get(agentproto.HeaderVersion))
	if err != nil && !errors.Is(err, clusterinstall.ErrNoManifest) && !errors.Is(err, clusterinstall.ErrNoProgram) {
		s.Log.Warn("cannot offer agents an update", "err", err)
	}
	if err != nil {
		return nil
	}
	return u
}

// handleAgentManagedManifest hands an agent the signed manifest of the
// programs, to check an update with.
func (s *Server) handleAgentManagedManifest(w http.ResponseWriter, r *http.Request) {
	if s.agentManagedTenant(w, r, (*Server).handleAgentManagedManifest) {
		return
	}
	if _, ok := s.agentManagedToken(w, r); !ok {
		return
	}
	data, sig, _, err := s.agentPrograms().Manifest()
	if errors.Is(err, clusterinstall.ErrNoManifest) {
		writeError(w, http.StatusNotFound, errors.New("this server's agent programs have no signed manifest, so agents do not update themselves from it"))
		return
	}
	if err != nil {
		s.Log.Warn("cannot hand out the agent manifest", "err", err)
		writeError(w, http.StatusInternalServerError, errors.New("this server cannot read the agent programs' manifest"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, agentproto.ManifestAnswer{Manifest: string(data), Signature: string(sig)})
}

// agentOsquery is the osquery part of the configuration of an agent
// whose computer has osquery: the flags that make it enroll here with the
// agent token, or why it cannot.
func agentOsquery(goos string, o agents.Options) *agentproto.Osquery {
	flags, err := agents.ManagedOsqueryFlags(goos, o)
	if err != nil {
		return &agentproto.Osquery{Error: err.Error()}
	}
	return &agentproto.Osquery{Flags: flags}
}

// handleAgentManagedStatus takes an agent's status for the Endpoints page.
func (s *Server) handleAgentManagedStatus(w http.ResponseWriter, r *http.Request) {
	if s.agentManagedTenant(w, r, (*Server).handleAgentManagedStatus) {
		return
	}
	who, ok := s.agentManagedToken(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, agentproto.MaxStatusBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("a status is at most %d bytes", agentproto.MaxStatusBytes))
		return
	}
	var st agentproto.Status
	if err := json.Unmarshal(body, &st); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("the status is not valid JSON"))
		return
	}
	clean := st.Clean()
	s.noteAgentManaged(r, who, &clean)
	w.WriteHeader(http.StatusNoContent)
}

// noteAgentManaged records an agent's status in the agent inventory, on
// the row of its computer: the agent sends the same computer name as its
// Fluent Bit (agentproto.HeaderName).
func (s *Server) noteAgentManaged(r *http.Request, who agenttokens.Identity, st *agentproto.Status) {
	from := clientaddr.Parse(r.RemoteAddr)
	s.tokens().Note(who.ID, from.String(), 0)
	s.agents().Note(agentinv.Contact{
		Name:    r.Header.Get(agentproto.HeaderName),
		Address: from.String(),
		Intake:  ingest.IntakeAgent,
		TLS:     r.TLS != nil || s.viaTrustedProxy(r),
		Local:   from.IsValid() && from.Unmap().IsLoopback(),
		TokenID: who.ID, TokenName: who.Name,
		Managed: st,
	})
}

// handleAgentManagedProgram hands the install script (and, later, the
// agent) the agent program for a platform, with its SHA-256.
func (s *Server) handleAgentManagedProgram(w http.ResponseWriter, r *http.Request) {
	if s.agentManagedTenant(w, r, (*Server).handleAgentManagedProgram) {
		return
	}
	if _, ok := s.agentManagedToken(w, r); !ok {
		return
	}
	goos, goarch, err := agentPlatform(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	f, _, sum, err := s.agentPrograms().Open(goos, goarch)
	if errors.Is(err, clusterinstall.ErrNoProgram) {
		writeError(w, http.StatusNotFound, fmt.Errorf("this server has no agent program for %s/%s; a released Signalith carries them (a development build does not)", goos, goarch))
		return
	}
	if err != nil {
		s.Log.Warn("cannot hand out the agent program", "os", goos, "arch", goarch, "err", err)
		writeError(w, http.StatusInternalServerError, errors.New("this server cannot read the agent program"))
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+agentproto.ProgramName(goos, goarch)+`"`)
	w.Header().Set(agentproto.HeaderSHA256, sum)
	w.Header().Set("Cache-Control", "no-store")
	var mod time.Time
	if st, err := f.Stat(); err == nil {
		mod = st.ModTime()
	}
	http.ServeContent(w, r, "", mod, f)
}
