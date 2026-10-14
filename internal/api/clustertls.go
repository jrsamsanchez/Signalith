package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// ClusterTLS is the cluster's one certificate authority as the API uses
// it (internal/clustertls): the Servers page shows it, and while the
// servers were set up with their own, an admin chooses which to keep.
type ClusterTLS interface {
	// Off says why the cluster does not keep one certificate authority
	// now, "" when it does.
	Off() string
	// CA returns the cluster's certificate authority; false while none
	// is published.
	CA() (*clustertls.Body, bool)
	// Founder is the node id of the server that founded the cluster.
	Founder() string
	// Writable says why the shared settings cannot be changed now, nil
	// when they can.
	Writable() error
	// Publish asks the server node to publish its certificate authority,
	// whose fingerprint is fp, as the cluster's, for the user by.
	Publish(ctx context.Context, node, fp, by string) (*shared.Request, error)
}

func (s *Server) routeClusterTLS(api *router) {
	// Which certificate authority every agent and browser trusts: admins
	// only, like the rest of the Servers page.
	api.admin("GET /api/cluster/tls", s.handleClusterTLS)
	api.admin("POST /api/cluster/tls/choose", s.handleClusterTLSChoose)
}

// clusterTLSReport is GET /api/cluster/tls.
type clusterTLSReport struct {
	// On is false while the cluster does not keep one certificate
	// authority, and Off says why; the rest is then empty.
	On  bool   `json:"on"`
	Off string `json:"off,omitempty"`
	// Alone is true on a server that is not a member of a cluster: the
	// page then says nothing of a cluster's certificate authority.
	Alone bool `json:"alone,omitempty"`
	*clustertls.Report
	// AgentsUnread says why the agents could not be counted, "" when
	// they were.
	AgentsUnread string `json:"agents_unread,omitempty"`
}

// clusterTLSOff is why the cluster keeps no certificate authority of its
// own on this server: it is not a member, or has no list of servers.
func (s *Server) clusterTLSOff() string {
	switch {
	case s.ClusterTLS == nil:
		return "This server isn't a member of a cluster, so it keeps its own certificate authority."
	case s.Cluster == nil:
		return "This server has no list of servers."
	}
	return s.ClusterTLS.Off()
}

// clusterTLSReport puts the report together from the servers' last
// heartbeats and, while none is published, the agent inventory.
func (s *Server) clusterTLSReport(ctx context.Context) clusterTLSReport {
	if off := s.clusterTLSOff(); off != "" {
		return clusterTLSReport{Off: off, Alone: s.ClusterTLS == nil}
	}
	st := s.Cluster.Status()
	in := clustertls.ReportInput{Founder: s.ClusterTLS.Founder(), Self: st.Self, Now: time.Now()}
	for _, sv := range st.Servers {
		if sv.Detail != nil {
			hb := *sv.Detail
			// The page's own clock decides who was seen in the last day,
			// and this server's view who runs now.
			hb.HeartbeatAt, hb.State = sv.HeartbeatAt, sv.State
			if sv.State != cluster.StateOffline && sv.State != cluster.StateStopped {
				// It runs, as this server sees it: whatever its clock says.
				hb.HeartbeatAt = in.Now
			}
			in.Heartbeats = append(in.Heartbeats, hb)
		} else {
			in.Heartbeats = append(in.Heartbeats, cluster.Heartbeat{NodeID: sv.NodeID, Name: sv.Name, HeartbeatAt: sv.HeartbeatAt, State: sv.State})
		}
	}
	out := clusterTLSReport{On: true}
	if b, ok := s.ClusterTLS.CA(); ok {
		in.Body = b
	} else if s.Agents != nil {
		actx, cancel := context.WithTimeout(ctx, 20*time.Second)
		agents, _, err := s.Agents.List(actx)
		cancel()
		in.Agents = agents
		if err != nil {
			out.AgentsUnread = "The agents couldn't all be read from OpenSearch, so the counts may be short: " + err.Error()
		}
	}
	out.Report = clustertls.BuildReport(in)
	return out
}

// handleClusterTLS answers GET /api/cluster/tls.
func (s *Server) handleClusterTLS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.clusterTLSReport(r.Context()))
}

// errCAPublished: the cluster has its certificate authority already.
var errCAPublished = errors.New("the cluster already has a certificate authority; changing it comes in a later version")

// handleClusterTLSChoose answers POST /api/cluster/tls/choose
// {ca_sha256}: the server that holds that certificate authority is asked
// to publish it as the cluster's (a tls_publish request), and the answer
// is 202 with the request's id, which GET /api/requests/{id} follows.
func (s *Server) handleClusterTLSChoose(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CASHA256 string `json:"ca_sha256"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.CASHA256) == "" {
		writeError(w, http.StatusBadRequest, errors.New("name the certificate authority to keep by its fingerprint (ca_sha256)"))
		return
	}
	if off := s.clusterTLSOff(); off != "" {
		writeError(w, http.StatusServiceUnavailable, errors.New(off))
		return
	}
	if err := s.ClusterTLS.Writable(); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	if _, ok := s.ClusterTLS.CA(); ok {
		writeError(w, http.StatusConflict, errCAPublished)
		return
	}
	rep := s.clusterTLSReport(r.Context())
	if rep.Report == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New(rep.Off))
		return
	}
	var c *clustertls.Candidate
	for i := range rep.Candidates {
		if clustertls.SameFingerprint(rep.Candidates[i].CASHA256, req.CASHA256) {
			c = &rep.Candidates[i]
		}
	}
	if c == nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no server seen in the last day uses the certificate authority %s", req.CASHA256))
		return
	}
	if !c.Up {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("%s is offline, and only a server that holds the certificate authority can publish it: start it first",
			strings.Join(c.Servers, ", ")))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rq, err := s.ClusterTLS.Publish(ctx, c.NodeIDs[0], c.CASHA256, userOf(r))
	if err != nil {
		if !sharedError(w, err) {
			writeError(w, http.StatusServiceUnavailable, err)
		}
		return
	}
	s.audit(r, "certificate authority chosen for the cluster", "server", c.Servers[0], "ca_sha256", c.CASHA256,
		"agents", c.AgentCount, "breaks", c.BreakCount, "request", rq.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"request_id": rq.ID, "server": c.Servers[0], "ca_sha256": c.CASHA256})
}

// clusterCAOwner is "cluster" when this server's certificate comes from
// the cluster's certificate authority, "" otherwise.
func (s *Server) clusterCAOwner() string {
	if s.TLS.LocalCA() && s.TLS.Store() == tlsauto.KindCluster {
		return "cluster"
	}
	return ""
}
