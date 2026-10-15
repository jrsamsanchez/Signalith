package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// statusCluster answers with a fixed status.
type statusCluster struct{ st cluster.Status }

func (c statusCluster) RunsJobs() bool         { return true }
func (c statusCluster) JobHolder() string      { return "" }
func (c statusCluster) Status() cluster.Status { return c.st }
func (c statusCluster) Banners() []string      { return nil }

var hbAt = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) *time.Time {
	t := hbAt.Add(-d)
	return &t
}

// server is a ready server that started up an hour ago with traffic t
// (nil: a version that does not report it).
func server(name string, t *cluster.Traffic) cluster.ServerStatus {
	return cluster.ServerStatus{NodeID: "n_" + name, Name: name, State: cluster.StateReady, HeartbeatAt: hbAt,
		StartedAt: hbAt.Add(-time.Hour), Uptime: time.Hour, Detail: &cluster.Heartbeat{Name: name, Traffic: t}}
}

func traffic(batches, events int64, lastAgent *time.Time, syslog int64) *cluster.Traffic {
	return &cluster.Traffic{Since: hbAt.Add(-time.Hour), Agents: cluster.AgentTraffic{Batches: batches, Events: events, LastAt: lastAgent},
		Syslog: cluster.SyslogTraffic{Messages: syslog, LastAt: ago(time.Minute)}}
}

func TestHealthClusterTotals(t *testing.T) {
	off := server("siem-c", traffic(1000, 9000, ago(2*time.Hour), 5))
	off.State = cluster.StateOffline
	st := cluster.Status{Self: "n_siem-a", Servers: []cluster.ServerStatus{
		server("siem-a", traffic(10, 400, ago(time.Minute), 7)),
		server("siem-b", traffic(5, 100, ago(3*time.Minute), 3)),
		server("siem-old", nil),
		off,
	}}
	st.Servers[0].Self = true
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Cluster = statusCluster{st}
		s.Users = users.NewMemory()
		if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "vera", Role: users.Viewer, Password: "role-password"}); err != nil {
			t.Fatal(err)
		}
	})

	// Without scope=cluster, Health answers as before.
	if _, out := do(t, ts, "GET", "/api/health", "", true); out["cluster"] != nil {
		t.Errorf("cluster block without scope=cluster: %v", out["cluster"])
	}
	_, out := do(t, ts, "GET", "/api/health?scope=cluster", "", true)
	ch, _ := out["cluster"].(map[string]any)
	if ch == nil {
		t.Fatalf("no cluster block: %v", out)
	}
	tot := ch["totals"].(map[string]any)
	ing, sys := tot["ingest"].(map[string]any), tot["syslog"].(map[string]any)
	if ing["batches"] != float64(15) || ing["events"] != float64(500) || sys["messages"] != float64(10) ||
		tot["servers"] != float64(2) || tot["no_figures"] != float64(1) {
		t.Errorf("totals %v", tot)
	}
	if ing["last_at"] != hbAt.Add(-time.Minute).Format(time.RFC3339) {
		t.Errorf("latest agent batch %v", ing["last_at"])
	}
	rows := ch["servers"].([]any)
	if len(rows) != 4 || rows[2].(map[string]any)["figures"] != false || rows[0].(map[string]any)["figures"] != true {
		t.Errorf("rows %v", rows)
	}

	// Viewers see the totals, not each server.
	_, vout := doAs(t, ts, "vera", "role-password", "GET", "/api/health?scope=cluster", "")
	vch := vout["cluster"].(map[string]any)
	if vch["servers"] != nil || vch["totals"].(map[string]any)["servers"] != float64(2) {
		t.Errorf("viewer cluster block %v", vch)
	}
}

func TestAgentTrafficWarnings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		servers []cluster.ServerStatus
		want    []string
	}{
		{"both get traffic", []cluster.ServerStatus{
			server("siem-a", traffic(1, 1, ago(time.Minute), 0)), server("siem-b", traffic(1, 1, ago(9*time.Minute), 0))}, nil},
		{"one gets none", []cluster.ServerStatus{
			server("siem-a", traffic(1, 1, ago(time.Minute), 0)), server("siem-b", traffic(0, 0, nil, 0))}, []string{"siem-b"}},
		{"one's traffic stopped", []cluster.ServerStatus{
			server("siem-a", traffic(1, 1, ago(time.Minute), 0)), server("siem-b", traffic(9, 9, ago(11*time.Minute), 0))}, []string{"siem-b"}},
		{"no agents at all", []cluster.ServerStatus{
			server("siem-a", traffic(0, 0, nil, 0)), server("siem-b", traffic(0, 0, nil, 0))}, nil},
		{"one server", []cluster.ServerStatus{server("siem-a", traffic(1, 1, ago(time.Minute), 0))}, nil},
		{"older version", []cluster.ServerStatus{server("siem-a", traffic(1, 1, ago(time.Minute), 0)), server("siem-b", nil)}, nil},
	} {
		got := agentTrafficWarnings(cluster.Status{Servers: tc.servers})
		if len(got) != len(tc.want) {
			t.Errorf("%s: %v", tc.name, got)
			continue
		}
		for i, w := range tc.want {
			if !strings.HasPrefix(got[i], w+" receives no agent traffic") {
				t.Errorf("%s: %v", tc.name, got)
			}
		}
	}

	// A server that just started, or just started counting, is given time.
	young := server("siem-b", traffic(0, 0, nil, 0))
	young.Uptime = 5 * time.Minute
	recount := server("siem-c", &cluster.Traffic{Since: hbAt.Add(-5 * time.Minute)})
	st := cluster.Status{Servers: []cluster.ServerStatus{server("siem-a", traffic(1, 1, ago(time.Minute), 0)), young, recount}}
	if got := agentTrafficWarnings(st); len(got) != 0 {
		t.Errorf("new servers warned about: %v", got)
	}
	// And one that is not ready is not.
	down := server("siem-b", traffic(0, 0, nil, 0))
	down.State = cluster.StateOffline
	if got := agentTrafficWarnings(cluster.Status{Servers: []cluster.ServerStatus{server("siem-a", traffic(1, 1, ago(time.Minute), 0)), down}}); len(got) != 0 {
		t.Errorf("offline server warned about: %v", got)
	}
}
