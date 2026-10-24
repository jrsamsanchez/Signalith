// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

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

// The Servers page warns while a running server reports the cluster's
// certificate authority key lost, with the soonest expiry among them;
// the security checks read this server's own report.
func TestCAKeyLostWarnings(t *testing.T) {
	soon, later := time.Now().Add(-time.Hour).AddDate(0, 6, 0).UTC(), time.Now().Add(-time.Hour).AddDate(1, 0, 0).UTC()
	sv := func(name string, self bool, state string, lost bool, exp time.Time) cluster.ServerStatus {
		return cluster.ServerStatus{NodeID: "n_" + name, Name: name, Self: self, State: state,
			Detail: &cluster.Heartbeat{TLS: &cluster.TLSStatus{Mode: "auto", Cluster: true, CAKeyLost: lost, LeafExpires: &exp}}}
	}
	st := cluster.Status{Servers: []cluster.ServerStatus{
		sv("siem-a", true, cluster.StateReady, true, later),
		sv("siem-b", false, cluster.StateReady, true, soon),
		// Offline: its last heartbeat is old news.
		sv("siem-c", false, cluster.StateOffline, true, soon.AddDate(0, -1, 0)),
		sv("siem-d", false, cluster.StateReady, false, soon.AddDate(0, -2, 0)),
	}}
	w := caKeyLostWarnings(st)
	want := "The cluster's certificate authority key was lost; HTTPS certificates expire on " + soon.Format("2 Jan 2006") + " and cannot be renewed."
	if len(w) != 1 || w[0].Level != "red" || !strings.HasPrefix(w[0].Text, want) {
		t.Errorf("warnings %+v", w)
	}
	if !(&Server{Cluster: statusCluster{st: st}}).selfCAKeyLost() {
		t.Error("this server's report not read")
	}
	st.Servers = st.Servers[2:]
	if w := caKeyLostWarnings(st); len(w) != 0 {
		t.Errorf("warned without a running server reporting it: %+v", w)
	}
	if (&Server{Cluster: statusCluster{st: st}}).selfCAKeyLost() || (&Server{}).selfCAKeyLost() {
		t.Error("lost without this server reporting it")
	}
}
