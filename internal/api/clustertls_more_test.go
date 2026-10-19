package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// publishFails is the cluster's CA whose publish requests are refused.
type publishFails struct {
	*fakeClusterTLS
	err error
}

func (p *publishFails) Publish(context.Context, string, string, string) (*shared.Request, error) {
	return nil, p.err
}

// Without a list of servers nothing is reported or chosen; a body that
// does not read is a 400; a publish request that cannot be made says
// why. The report reads the agents while no CA is published, and lists a
// server that sent no heartbeat yet.
func TestClusterTLSMore(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.ClusterTLS = &fakeClusterTLS{} })
	if _, out := do(t, ts, "GET", "/api/cluster/tls", "", true); out["on"] != false || !strings.Contains(out["off"].(string), "no list of servers") {
		t.Errorf("no cluster: %v", out)
	}
	if code, _ := do(t, ts, "POST", "/api/cluster/tls/choose", `{`, true); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}

	a, b := newCertManager(t), newCertManager(t)
	ct := &publishFails{fakeClusterTLS: &fakeClusterTLS{}, err: errDown}
	ts, _ = newClusterTLSServer(t, ct, a, b)
	code, out := do(t, ts, "POST", "/api/cluster/tls/choose", `{"ca_sha256":"`+b.Fingerprint()+`"}`, true)
	if code != http.StatusServiceUnavailable || !strings.Contains(out["error"].(string), errDown.Error()) {
		t.Errorf("publish fails: %d %v", code, out)
	}
	ct.err = &shared.MovingError{}
	if code, _ := do(t, ts, "POST", "/api/cluster/tls/choose", `{"ca_sha256":"`+b.Fingerprint()+`"}`, true); code != http.StatusServiceUnavailable {
		t.Errorf("publish while moving: %d", code)
	}

	quiet := &statusCluster{st: cluster.Status{Self: "n_a", Servers: []cluster.ServerStatus{
		{NodeID: "n_a", Name: "siem-a", Self: true, State: cluster.StateReady},
	}}}
	var srv *Server
	newTestServerWith(t, func(s *Server) {
		s.ClusterTLS, s.Cluster, s.Agents = &fakeClusterTLS{}, quiet, &agentinv.Inventory{}
		srv = s
	})
	rep := srv.clusterTLSReport(context.Background())
	if !rep.On || rep.Report == nil || rep.AgentsUnread != "" {
		t.Errorf("report %+v", rep)
	}
}
