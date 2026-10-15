package api

import (
	"net/http"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// How the Health page decides that a server gets no agent traffic: agents
// sent another server a batch within trafficRecent, and this one, running
// for at least trafficSettled, had none in that time.
const (
	trafficRecent  = 10 * time.Minute
	trafficSettled = 15 * time.Minute
)

// clusterHealth is the cluster block of GET /api/health?scope=cluster:
// totals for every running server, and for admins each server's figures.
type clusterHealth struct {
	Totals  clusterTotals   `json:"totals"`
	Servers []serverTraffic `json:"servers,omitempty"`
}

// clusterTotals adds up the running servers that report figures; Servers
// counts them, and NoFigures those of versions that do not (left out of
// the totals rather than counted as zero).
type clusterTotals struct {
	Ingest    cluster.AgentTraffic  `json:"ingest"`
	Syslog    cluster.SyslogTraffic `json:"syslog"`
	Servers   int                   `json:"servers"`
	NoFigures int                   `json:"no_figures,omitempty"`
}

// serverTraffic is one server's figures; Figures is false for a server
// whose version does not report them.
type serverTraffic struct {
	Name        string                 `json:"name"`
	Self        bool                   `json:"self,omitempty"`
	State       string                 `json:"state"`
	Figures     bool                   `json:"figures"`
	Since       *time.Time             `json:"since,omitempty"`
	Ingest      *cluster.AgentTraffic  `json:"ingest,omitempty"`
	Syslog      *cluster.SyslogTraffic `json:"syslog,omitempty"`
	HeartbeatAt time.Time              `json:"heartbeat_at"`
}

// addClusterHealth puts the cluster block in out when the request asks
// for scope=cluster and this server shares its OpenSearch with others.
// Without either, Health answers as it always has.
func (s *Server) addClusterHealth(r *http.Request, out map[string]any) {
	if s.Cluster == nil || r.URL.Query().Get("scope") != "cluster" {
		return
	}
	p := principalOf(r)
	out["cluster"] = clusterHealthOf(s.Cluster.Status(), p != nil && p.Role.AtLeast(users.Admin))
}

// running reports whether a server in st is up now: offline and stopped
// servers' last figures are not current.
func running(sv cluster.ServerStatus) bool {
	return sv.State != cluster.StateOffline && sv.State != cluster.StateStopped
}

func clusterHealthOf(st cluster.Status, detail bool) clusterHealth {
	var ch clusterHealth
	for _, sv := range st.Servers {
		row := serverTraffic{Name: sv.Name, Self: sv.Self, State: sv.State, HeartbeatAt: sv.HeartbeatAt}
		if d := sv.Detail; d != nil && d.Traffic != nil {
			t := *d.Traffic
			row.Figures, row.Since, row.Ingest, row.Syslog = true, &t.Since, &t.Agents, &t.Syslog
		}
		if running(sv) {
			if !row.Figures {
				ch.Totals.NoFigures++
			} else {
				ch.Totals.Servers++
				ch.Totals.Ingest.Batches += row.Ingest.Batches
				ch.Totals.Ingest.Events += row.Ingest.Events
				ch.Totals.Ingest.LastAt = later(ch.Totals.Ingest.LastAt, row.Ingest.LastAt)
				ch.Totals.Syslog.Messages += row.Syslog.Messages
				ch.Totals.Syslog.LastAt = later(ch.Totals.Syslog.LastAt, row.Syslog.LastAt)
			}
		}
		if detail {
			ch.Servers = append(ch.Servers, row)
		}
	}
	return ch
}

func later(a, b *time.Time) *time.Time {
	if a == nil || (b != nil && b.After(*a)) {
		return b
	}
	return a
}

// agentTrafficWarnings names the servers that agents do not reach while
// they reach another: with two or more ready servers, some server had an
// agent batch in the last 10 minutes, and a server running for 15 minutes
// or more had none in that time. That server is missing from the load
// balancer or the DNS name agents send to. Times are compared on each
// server's own clock (its heartbeat time), so clocks that differ between
// servers do not matter.
func agentTrafficWarnings(st cluster.Status) []string {
	type seen struct {
		name    string
		recent  bool
		settled bool
	}
	var ready []seen
	anyRecent := false
	for _, sv := range st.Servers {
		d := sv.Detail
		if sv.State != cluster.StateReady || d == nil || d.Traffic == nil {
			continue
		}
		t := d.Traffic
		at := sv.HeartbeatAt
		recent := t.Agents.LastAt != nil && at.Sub(*t.Agents.LastAt) < trafficRecent
		settled := at.Sub(t.Since) >= trafficSettled && sv.Uptime >= trafficSettled
		ready = append(ready, seen{name: sv.Name, recent: recent, settled: settled})
		anyRecent = anyRecent || recent
	}
	if len(ready) < 2 || !anyRecent {
		return nil
	}
	var w []string
	for _, r := range ready {
		if !r.recent && r.settled {
			w = append(w, r.name+" receives no agent traffic: add it to your load balancer or DNS name, or check that agents can reach it.")
		}
	}
	slices.Sort(w)
	return w
}

// agentTrafficClusterWarnings are agentTrafficWarnings for the Servers page.
func agentTrafficClusterWarnings(st cluster.Status) []cluster.Warning {
	var out []cluster.Warning
	for _, text := range agentTrafficWarnings(st) {
		out = append(out, cluster.Warning{Level: "amber", Text: text})
	}
	return out
}
