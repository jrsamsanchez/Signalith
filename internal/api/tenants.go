package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/tenants"
)

// platformPaths are the API paths about the server itself rather than one
// tenant's data: settings, servers, certificates, the security report,
// how people sign in, the audit log and the tenants. Only the provider's
// own users may use them (route.Platform). Every other route works on the
// request's active tenant.
var platformPaths = []string{"settings", "cluster", "security", "tls", "auth", "audit", "requests", "tenants"}

// tenantVisible are routes under platformPaths every user may use: the
// web UI asks every user which cluster features are on.
var tenantVisible = []string{"GET /api/cluster/features"}

// platformRoute reports whether the route pattern is a platform route.
func platformRoute(pattern string) bool {
	for _, v := range tenantVisible {
		if pattern == v {
			return false
		}
	}
	_, path, ok := strings.Cut(pattern, " ")
	if !ok {
		path = pattern
	}
	for _, p := range platformPaths {
		if path == "/api/"+p || strings.HasPrefix(path, "/api/"+p+"/") {
			return true
		}
	}
	return false
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

// servesTenant reports whether this server has the data of tenant id to
// serve its routes with.
func (s *Server) servesTenant(id string) bool {
	return id == "" || id == tenants.Default
}

// activeTenant returns the tenant a request of p works in: a tenant
// user's own; for the provider's users the one their session switched
// to, while it can still be used, else the default tenant.
func (s *Server) activeTenant(p *principal, session string) string {
	if p.Tenant != "" {
		return p.Tenant
	}
	if session != "" && s.tenantUsable(session) {
		return session
	}
	return tenants.Default
}

func (s *Server) routeTenants(api *router) {
	api.viewer("GET /api/tenants", s.handleListTenants)
	api.viewer("POST /api/tenants/switch", s.handleSwitchTenant)
}

type tenantView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Disabled bool   `json:"disabled,omitempty"`
	Default  bool   `json:"default,omitempty"`
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
			list = append(list, tenantView{ID: t.ID, Name: t.Name, Disabled: t.Disabled})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": list, "active": p.Active, "enabled": len(list) > 1})
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
