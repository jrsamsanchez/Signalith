package api

import (
	"net/http"
)

func (s *Server) routeClusterUpgrade(api *router) {
	// The upgrade checklist of the Servers page is for admins, like the
	// rest of that page.
	api.admin("GET /api/cluster/upgrade", s.handleClusterUpgrade)
}

// handleClusterUpgrade answers GET /api/cluster/upgrade: whether the next
// server may be upgraded now, which one, and each server's version and
// state, as signalith cluster upgrade-check -json says it. Drain and
// Resume reuse POST /api/cluster/servers/{id}/drain and resume.
func (s *Server) handleClusterUpgrade(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Upgrade == nil {
		writeError(w, http.StatusServiceUnavailable, errNoCluster)
		return
	}
	v, err := s.Upgrade(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
