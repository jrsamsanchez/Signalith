package api

import (
	"net/http"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterpki"
)

// ClusterOSIdentity is OpenSearch's certificate authority as the cluster
// keeps it (internal/clusterpki), for the Servers page.
type ClusterOSIdentity interface {
	// CA returns the osca document; false while the cluster keeps none.
	CA() (*clusterpki.Body, bool)
}

func (s *Server) routeClusterOSIdentity(api *router) {
	// Who each server signs in to OpenSearch as: admins only, like the
	// rest of the Servers page.
	api.admin("GET /api/cluster/opensearch-identity", s.handleClusterOSIdentity)
}

// osIdentityReport is GET /api/cluster/opensearch-identity.
type osIdentityReport struct {
	// Alone is true on a server that is not a member of a cluster.
	Alone bool `json:"alone,omitempty"`
	// CA is OpenSearch's certificate authority the cluster keeps, nil
	// when it keeps none.
	CA *osIdentityCA `json:"ca"`
	// Servers is each server's sign-in, as its heartbeat says.
	Servers []osIdentityServer `json:"servers"`
}

type osIdentityCA struct {
	CASHA256   string    `json:"ca_sha256"`
	ImportedBy string    `json:"imported_by"`
	ImportedOn string    `json:"imported_on,omitempty"`
	ImportedAt time.Time `json:"imported_at"`
}

type osIdentityServer struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Self   bool   `json:"self,omitempty"`
	// Identity is nil from a version that does not report it.
	Identity *cluster.OSIdentityStatus `json:"identity"`
}

// handleClusterOSIdentity answers GET /api/cluster/opensearch-identity.
func (s *Server) handleClusterOSIdentity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	out := osIdentityReport{Servers: []osIdentityServer{}}
	if s.ClusterOSIdentity == nil || s.Cluster == nil {
		out.Alone = true
		writeJSON(w, http.StatusOK, out)
		return
	}
	if b, ok := s.ClusterOSIdentity.CA(); ok {
		out.CA = &osIdentityCA{CASHA256: b.CASHA256, ImportedBy: b.ImportedBy, ImportedOn: b.ImportedOn, ImportedAt: b.ImportedAt}
	}
	for _, sv := range s.Cluster.Status().Servers {
		row := osIdentityServer{NodeID: sv.NodeID, Name: sv.Name, State: sv.State, Self: sv.Self}
		if sv.Detail != nil {
			row.Identity = sv.Detail.OSIdentity
		}
		out.Servers = append(out.Servers, row)
	}
	writeJSON(w, http.StatusOK, out)
}
