package api

import (
	"errors"
	"net/http"

	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// Scan logins are the SSH and Windows accounts OpenVAS signs in to hosts
// with. Their keys and passwords are written here and never read back:
// the page gets each login's name, user name and whether this server can
// decrypt it, and nothing else.

func (s *Server) routeVulnLogins(api *router) {
	api.admin("GET /api/vulns/logins", s.handleVulnLogins)
	api.admin("PUT /api/vulns/logins/{id}", s.handleSaveVulnLogin)
	api.admin("DELETE /api/vulns/logins/{id}", s.handleDeleteVulnLogin)
}

// vulnLogin is a scan login as the page shows it.
type vulnLogin struct {
	vulnscan.LoginView
	// UsedBy names the networks that sign in with it.
	UsedBy []string `json:"used_by"`
}

func (s *Server) handleVulnLogins(w http.ResponseWriter, r *http.Request) {
	if s.vulnsMissing(w) {
		return
	}
	ctx := r.Context()
	list, _, err := s.Vulns.Store.Logins(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	set, _, err := s.Vulns.Store.Settings(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	out := make([]vulnLogin, 0, len(list))
	for _, c := range list {
		used := vulnscan.LoginUsers(set, c.ID)
		if used == nil {
			used = []string{}
		}
		out = append(out, vulnLogin{LoginView: c.View(s.Vulns.Store.Keys), UsedBy: used})
	}
	writeJSON(w, http.StatusOK, map[string]any{"logins": out, "can_save": s.Vulns.Store.Keys != nil})
}

func (s *Server) handleSaveVulnLogin(w http.ResponseWriter, r *http.Request) {
	if s.vulnsMissing(w) {
		return
	}
	var in vulnscan.LoginInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	in.ID = r.PathValue("id")
	c, err := s.Vulns.Store.SaveLogin(r.Context(), in, userOf(r))
	if err != nil {
		var bad *vulnscan.InputError
		switch {
		case errors.As(err, &bad):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, vulnscan.ErrNoKeys):
			writeError(w, http.StatusServiceUnavailable, err)
		default:
			writeError(w, http.StatusBadGateway, err)
		}
		return
	}
	// The audit record says what changed, never the key or password.
	s.audit(r, "vulnerability scan login saved", "login", c.Name, "id", c.ID, "type", c.Kind,
		"username", c.Username, "auth", c.Auth, "secret_changed", in.Secret != "",
		"passphrase_changed", in.Passphrase != "" || in.ClearPassphrase)
	writeJSON(w, http.StatusOK, c.View(s.Vulns.Store.Keys))
}

func (s *Server) handleDeleteVulnLogin(w http.ResponseWriter, r *http.Request) {
	if s.vulnsMissing(w) {
		return
	}
	gone, err := s.Vulns.Store.DeleteLogin(r.Context(), r.PathValue("id"))
	if err != nil {
		var bad *vulnscan.InputError
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, errors.New("no such scan login; it may have been removed"))
		case errors.As(err, &bad):
			writeError(w, http.StatusConflict, err)
		default:
			writeError(w, http.StatusBadGateway, err)
		}
		return
	}
	s.audit(r, "vulnerability scan login removed", "login", gone.Name, "id", gone.ID, "type", gone.Kind, "username", gone.Username)
	w.WriteHeader(http.StatusNoContent)
}
