package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/notebooks"
	"github.com/jrsamsanchez/signalith/internal/tenants"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// What each API route works on, by its resource (the path's segment after
// /api/). Every resource is in exactly one list, and a test fails on a
// route whose resource is in none (TestEveryRouteHasAScope).
var (
	// tenantResources work on the data of the request's tenant, in that
	// tenant's own server.
	tenantResources = []string{
		"me", "health", "search", "explain", "build", "parse", "datamodels", "fields", "language", "ask",
		"detections", "coverage", "findings", "cases", "lookups", "lookuptables", "risk", "intel", "posture",
		"dashboards", "panels", "notebooks", "investigate", "notify", "respond", "playbooks", "retention", "sample",
		"endpoints", "agents", "agent-tokens", "users", "ticketing",
	}
	// platformResources are about the server itself, shared by every
	// tenant: only the provider's own users may use them, and always in
	// the default tenant's server. So are the resources a tenant's server
	// cannot keep apart yet: API tokens (in the shared settings),
	// compliance notes (in the state folder), vulnerability scans (the
	// server's scanners and OpenVAS), network sensors, the custom
	// parsers (one set that reads every tenant's records) and the chat
	// accounts linked for the buttons in Slack and Teams messages, whose
	// clicks the default tenant's server answers, and the behavior
	// baselines, which learn from the default tenant's data only for now.
	// The summaries' status lists every tenant's, so it is the provider's
	// too.
	platformResources = []string{
		"settings", "cluster", "security", "tls", "auth", "audit", "requests", "tenants",
		"api-tokens", "compliance", "vulns", "sensor", "sensors", "parsers", "chat", "baselines", "summaries",
	}
	// providerManaged are tenant routes that make the server send
	// requests to addresses a user gives (feeds, webhooks, mail servers,
	// scripts, Jira and ServiceNow): a tenant's own users could reach the
	// provider's network with them, so only the provider's users may
	// change them.
	providerManaged = []string{
		"POST /api/intel/feeds", "PUT /api/intel/feeds/{name}", "DELETE /api/intel/feeds/{name}",
		"POST /api/intel/feeds/test", "POST /api/intel/feeds/{name}/refresh", "POST /api/intel/catalog",
		"POST /api/intel/taxii/collections", "PUT /api/notify", "POST /api/notify/test",
		"PUT /api/respond/config", "POST /api/respond/test",
		"PUT /api/ticketing", "POST /api/ticketing/test",
	}
	// tenantVisible are routes about the server every user may use, the
	// same for every tenant: the web UI asks every user which cluster
	// features are on.
	tenantVisible = []string{"GET /api/cluster/features"}
)

// routeResource returns the resource of a route pattern, and false for a
// path outside /api/.
func routeResource(pattern string) (string, bool) {
	_, path, ok := strings.Cut(pattern, " ")
	if !ok {
		path = pattern
	}
	rest, ok := strings.CutPrefix(path, "/api/")
	if !ok {
		return "", false
	}
	res, _, _ := strings.Cut(rest, "/")
	return res, true
}

// routeScope classifies a route pattern: platform (provider users only,
// in the default tenant's server), managed (a tenant's data that only
// provider users may change), shared (the same for everyone: the web UI's
// files and tenantVisible), else the request's tenant's. An /api/ route of
// a resource in no list is a platform route.
func routeScope(pattern string) (platform, managed, shared bool) {
	if slices.Contains(tenantVisible, pattern) {
		return false, false, true
	}
	res, ok := routeResource(pattern)
	if !ok {
		return false, false, true
	}
	if !slices.Contains(tenantResources, res) {
		return true, false, false
	}
	return false, slices.Contains(providerManaged, pattern), false
}

// tenantUsable reports whether tenant id exists and is not turned off. An
// install without tenants has only the default tenant.
func (s *Server) tenantUsable(id string) bool {
	if id == "" || id == tenants.Default {
		return true
	}
	if s.Tenants == nil {
		return false
	}
	t, err := s.Tenants.Get(id)
	return err == nil && !t.Disabled
}

// TenantRuntime runs the servers of the tenants other than the default
// one, each with its own data (see docs/multi-tenant.md).
type TenantRuntime interface {
	// Server returns the server of tenant id while it runs, else nil.
	Server(id string) *Server
	// Servers returns the servers running here, also while Ready fails.
	Servers() []*Server
	// Changed starts tenant id's server, or stops it, after the tenant
	// was added, turned off or on.
	Changed(ctx context.Context, id string) error
	// SettingsChanged has every tenant's server follow the settings
	// applied at once on this server (see Server.FollowLive).
	SettingsChanged()
	// Ready says why this server cannot run tenants now, or nil.
	Ready() error
	// NotebookStores returns the hunting notebooks of every tenant but
	// the default one, running or not, by tenant ID.
	NotebookStores() map[string]notebooks.Store
}

// tenantKey is the tenant of this server's data: tenants.Default for the
// default tenant's.
func (s *Server) tenantKey() string {
	if s.TenantID == "" {
		return tenants.Default
	}
	return s.TenantID
}

// userTenant is User.Tenant of the users that belong to this server's
// tenant: "" for the provider's own, in the default tenant.
func (s *Server) userTenant() string {
	if s.TenantID == "" || s.TenantID == tenants.Default {
		return ""
	}
	return s.TenantID
}

// servesTenant reports whether this server can answer the routes of
// tenant id: a tenant's server only its own tenant's; the default
// tenant's server the default tenant's, and those of the tenants it
// runs, which it sends on (dispatchTo).
func (s *Server) servesTenant(id string) bool {
	if id == "" {
		id = tenants.Default
	}
	if id == s.tenantKey() {
		return true
	}
	return s.TenantID == "" && s.TenantRuntime != nil && s.TenantRuntime.Server(id) != nil
}

// dispatchTo returns the server that answers route rt for p when that is
// another tenant's, and whether it is: other is true with a nil server
// when the tenant stopped meanwhile, which must be refused.
func (s *Server) dispatchTo(rt route, p *principal) (t *Server, other bool) {
	if s.TenantID != "" || rt.Platform || rt.Anytime || rt.Shared || p.Active == "" || p.Active == tenants.Default {
		return nil, false
	}
	if s.TenantRuntime == nil {
		return nil, true
	}
	return s.TenantRuntime.Server(p.Active), true
}

// agentTenant returns the server of the tenant whose agent token the
// request carries, or nil when it is the default tenant's (or none's,
// which the default tenant's server refuses). Agent tokens are 256 random
// bits, so at most one tenant has a token. wait is true for a token of a
// tenant this server does not run now (another server of the cluster
// does): the agent is told to send again later, as its batch would
// otherwise be refused and lost.
func (s *Server) agentTenant(r *http.Request) (t *Server, wait bool) {
	return s.tokenTenant(bearerToken(r))
}

// tokenTenant is agentTenant for an agent token however the request
// carries it.
func (s *Server) tokenTenant(tok string) (t *Server, wait bool) {
	if s.TenantID != "" || s.TenantRuntime == nil {
		return nil, false
	}
	if tok == "" {
		return nil, false
	}
	if _, res := s.tokens().Check(tok); res == agenttokens.Valid || res == agenttokens.Revoked || res == agenttokens.Refused {
		return nil, false
	}
	runs := s.TenantRuntime.Ready() == nil
	// A tenant whose tokens are not read yet answers "send again later",
	// as the default tenant's server does then.
	var loading *Server
	for _, t := range s.TenantRuntime.Servers() {
		if !s.tenantUsable(t.TenantID) {
			continue
		}
		switch _, res := t.tokens().Check(tok); {
		case res == agenttokens.Valid, res == agenttokens.Revoked && runs:
			return t, !runs
		case res == agenttokens.NotLoaded:
			if loading == nil {
				loading = t
			}
		}
	}
	if !runs {
		return nil, loading != nil
	}
	return loading, false
}

// tenantAgentWait is the answer to an agent of a tenant this server does
// not run now (see agentTenant).
const tenantAgentWait = "This server does not run your organization's data right now; send again in a moment."

// tenantAgentRetry is the Retry-After of tenantAgentWait, in seconds: a
// server takes over the background jobs within seconds.
const tenantAgentRetry = "10"

// activeTenant returns the tenant a request of p works in: a tenant
// user's own; for the provider's users the one their session switched
// to, else the default tenant. lost says why the session's tenant can no
// longer be used, when it cannot (turned off or removed, or the user may
// no longer switch): the request is then refused (see allow), never
// answered with the default tenant's data instead. A server that does
// not run the tenants now (another server of a cluster) refuses the
// tenant's requests but leaves a session of a tenant turned off as it is.
func (s *Server) activeTenant(p *principal, session string) (active, lost string) {
	if p.Tenant != "" {
		return p.Tenant, ""
	}
	if session == "" || session == tenants.Default {
		return tenants.Default, ""
	}
	if !p.Role.AtLeast(users.Analyst) {
		// Switching is for analysts and admins: one whose role was
		// lowered since cannot stay in the tenant.
		return session, "Your role no longer lets you work in other tenants. You are back in the default tenant."
	}
	if runs := s.TenantRuntime != nil && s.TenantRuntime.Ready() == nil; runs && !s.tenantUsable(session) {
		return session, fmt.Sprintf("Tenant %q was turned off or removed. You are back in the default tenant.", session)
	}
	return session, ""
}

func (s *Server) routeTenants(api *router) {
	api.viewer("GET /api/tenants", s.handleListTenants)
	// Switching reads another customer's data: analysts and admins.
	api.analyst("POST /api/tenants/switch", s.handleSwitchTenant)
	api.sensitive("POST /api/tenants", s.handleAddTenant)
	api.sensitive("PATCH /api/tenants/{id}", s.handleChangeTenant)
}

// tenantsWritable answers when tenants cannot be added or changed here.
func (s *Server) tenantsWritable(w http.ResponseWriter) bool {
	switch {
	case s.Tenants == nil:
		writeError(w, http.StatusServiceUnavailable, errors.New("the list of tenants cannot be read; see the server's log"))
	case s.TenantRuntime == nil:
		writeError(w, http.StatusConflict, errors.New("this server cannot run tenants"))
	default:
		if err := s.TenantRuntime.Ready(); err != nil {
			writeError(w, http.StatusConflict, err)
			return false
		}
		return true
	}
	return false
}

// handleAddTenant adds a tenant and starts its data.
func (s *Server) handleAddTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.tenantsWritable(w) {
		return
	}
	t, err := s.Tenants.Add(strings.TrimSpace(req.ID), req.Name, userOf(r), time.Now())
	if err != nil {
		writeTenantError(w, err)
		return
	}
	s.audit(r, "tenants.add: tenant added", "tenant_id", t.ID, "name", t.Name)
	if err := s.TenantRuntime.Changed(r.Context(), t.ID); err != nil {
		s.Log.Error("a new tenant could not start", "tenant", t.ID, "err", err)
		writeJSON(w, http.StatusCreated, map[string]any{"tenant": tenantView{ID: t.ID, Name: t.Name},
			"warning": "The tenant was added but its data could not start; see the server's log."})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"tenant": tenantView{ID: t.ID, Name: t.Name}})
}

// handleChangeTenant renames a tenant, or turns it off or on. Turning it
// off refuses its users and agents at once; its data stays.
func (s *Server) handleChangeTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     *string `json:"name"`
		Disabled *bool   `json:"disabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.tenantsWritable(w) {
		return
	}
	id := r.PathValue("id")
	before, err := s.Tenants.Get(id)
	if err != nil {
		writeTenantError(w, err)
		return
	}
	t, err := s.Tenants.Change(id, req.Name, req.Disabled, userOf(r))
	if err != nil {
		writeTenantError(w, err)
		return
	}
	if t.Name != before.Name {
		s.audit(r, "tenants.rename: tenant renamed", "tenant_id", t.ID, "from", before.Name, "to", t.Name)
	}
	if t.Disabled != before.Disabled {
		s.audit(r, "tenants.disable: tenant turned "+map[bool]string{true: "off", false: "on"}[t.Disabled], "tenant_id", t.ID)
		if err := s.TenantRuntime.Changed(r.Context(), t.ID); err != nil {
			s.Log.Error("a tenant could not start or stop", "tenant", t.ID, "err", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": tenantView{ID: t.ID, Name: t.Name, Disabled: t.Disabled}})
}

func writeTenantError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, tenants.ErrNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, tenants.ErrExists), errors.Is(err, tenants.ErrTooMany):
		writeError(w, http.StatusConflict, err)
	default:
		writeError(w, http.StatusBadRequest, err)
	}
}

type tenantView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Disabled bool   `json:"disabled,omitempty"`
	Default  bool   `json:"default,omitempty"`
	// Created and CreatedBy are listed for Settings > Tenants.
	Created   *time.Time `json:"created,omitempty"`
	CreatedBy string     `json:"created_by,omitempty"`
}

// tenantsOff says why tenants cannot be added or changed here now, the
// way tenantsWritable refuses it, or "" when they can: Settings > Tenants
// shows it before anyone tries.
func (s *Server) tenantsOff() string {
	switch {
	case s.Tenants == nil:
		return "the list of tenants cannot be read; see the server's log"
	case s.TenantRuntime == nil:
		return "this server cannot run tenants"
	}
	if err := s.TenantRuntime.Ready(); err != nil {
		return err.Error()
	}
	return ""
}

// handleListTenants lists the tenants a provider user may switch to, the
// default tenant first, and the one the request works in.
func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	list := []tenantView{{ID: tenants.Default, Name: "Default", Default: true}}
	if s.Tenants != nil {
		ts, err := s.Tenants.List()
		if err != nil {
			s.Log.Error("could not read the tenants", "file", s.Tenants.Path, "err", err)
			writeError(w, http.StatusInternalServerError, errors.New("the list of tenants cannot be read; see the server's log"))
			return
		}
		for _, t := range ts {
			v := tenantView{ID: t.ID, Name: t.Name, Disabled: t.Disabled, CreatedBy: t.CreatedBy}
			if !t.Created.IsZero() {
				v.Created = &t.Created
			}
			list = append(list, v)
		}
	}
	out := map[string]any{"tenants": list, "active": p.Active, "enabled": len(list) > 1}
	// "off" is for the admins who add and change tenants.
	if p.runsServer() {
		out["off"] = s.tenantsOff()
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSwitchTenant moves the provider user's session to another tenant.
// Only a session can switch: API tokens and HTTP Basic sign-ins work in
// the default tenant.
func (s *Server) handleSwitchTenant(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	var req struct {
		Tenant string `json:"tenant"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	id := strings.TrimSpace(req.Tenant)
	if p.Method != "session" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "session_only",
			"error": "Only a signed-in browser session can switch tenants."})
		return
	}
	if !s.tenantUsable(id) {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": "no_tenant",
			"error": "There is no tenant with that ID that can be used now."})
		return
	}
	stored := id
	if id == tenants.Default {
		stored = ""
	}
	if err := s.sessions().SetTenant(r.Context(), p.token, stored); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	s.audit(r, "tenants.switch: switched tenant", "from", p.Active, "to", id)
	writeJSON(w, http.StatusOK, map[string]any{"active": id})
}
