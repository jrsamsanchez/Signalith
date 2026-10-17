package api

import (
	"net/http"
)

func (s *Server) routeClusterFeatures(api *router) {
	// Every page may grey out a control whose feature waits for older
	// servers, so every signed-in user may ask.
	api.viewer("GET /api/cluster/features", s.handleClusterFeatures)
}

// featureAnswer is a feature in GET /api/cluster/features.
type featureAnswer struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Level int    `json:"level"`
	On    bool   `json:"on"`
	Why   string `json:"why,omitempty"`
	// Waiting names the servers that hold the feature back, for admins
	// only.
	Waiting []featureServer `json:"waiting,omitempty"`
}

type featureServer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// handleClusterFeatures answers GET /api/cluster/features: the features
// that come with a cluster level, whether each is on and, if not, why.
// Viewers learn that a feature waits; only admins which servers it waits
// for.
func (s *Server) handleClusterFeatures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	out := map[string]any{"version": s.Version, "features": []featureAnswer{}}
	if s.Features == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	admin := false
	if principalOf(r).runsServer() {
		admin = true
	}
	states := s.Features()
	list := make([]featureAnswer, 0, len(states))
	for _, st := range states {
		a := featureAnswer{Name: st.Name, Label: st.Label, Level: st.Level, On: st.On, Why: st.Why}
		if admin {
			for _, p := range st.Waiting {
				a.Waiting = append(a.Waiting, featureServer{Name: p.Name, Version: p.Version})
			}
		}
		list = append(list, a)
	}
	out["features"] = list
	if s.ClusterLevel != nil {
		out["level"] = s.ClusterLevel()
	}
	writeJSON(w, http.StatusOK, out)
}
