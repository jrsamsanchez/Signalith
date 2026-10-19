package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// removedLifecycle is fakeLifecycle with servers removed.
type removedLifecycle struct {
	*fakeLifecycle
	removed []shared.RemovedServer
}

func (r *removedLifecycle) Lifecycle() ClusterLifecycle {
	lc := r.fakeLifecycle.Lifecycle()
	lc.Removed = r.removed
	return lc
}

// Each refusal of OpenSearch is worded with what to do about it.
func TestOSTrouble(t *testing.T) {
	for _, c := range []struct {
		err    error
		status string
		want   string
	}{
		{&store.Error{Status: http.StatusServiceUnavailable, Body: "OpenSearch Security not initialized."}, "refused", "needs no restart"},
		{&store.Error{Status: http.StatusTooManyRequests, Body: "too many"}, "refused", "keeps trying"},
		{&store.Error{Status: http.StatusUnauthorized, Body: "unauthorized"}, "refused", "user name and password"},
		{&store.Error{Status: http.StatusForbidden, Body: "no permissions"}, "refused", "cluster_monitor"},
		{&store.Error{Status: http.StatusInternalServerError, Body: "boom"}, "refused", "isn't ready"},
		{&store.Error{Status: http.StatusBadRequest, Body: "odd"}, "refused", "may say why"},
		{errDown, "unreachable", ""},
	} {
		status, _, advice := osTrouble(c.err)
		if status != c.status || !strings.Contains(advice, c.want) {
			t.Errorf("%v: %q %q", c.err, status, advice)
		}
	}
}

// The Servers page leaves out a removed server that no longer runs,
// marks one that still does, and shows how long since each was seen,
// how it uses the shared settings and how detections are spread.
func TestClusterServersView(t *testing.T) {
	ago := 90 * time.Second
	cl := &statusCluster{st: cluster.Status{Self: "n_a", Servers: []cluster.ServerStatus{
		{NodeID: "n_a", Name: "siem-a", Self: true, State: cluster.StateReady, Detail: &cluster.Heartbeat{Mode: "member", ConfigSeq: 7}},
		{NodeID: "n_b", Name: "siem-b", State: cluster.StateOffline, SeenAgo: &ago},
		{NodeID: "n_c", Name: "siem-c", State: cluster.StateReady},
	}}}
	lf := &removedLifecycle{fakeLifecycle: &fakeLifecycle{members: []string{"siem-a"}},
		removed: []shared.RemovedServer{{NodeID: "n_b", Name: "siem-b"}, {NodeID: "n_c", Name: "siem-c"}}}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Cluster, s.ClusterServers = cl, lf
		s.DetectionSpread = func(context.Context) []detect.SpreadView { return []detect.SpreadView{{Tenant: "", Buckets: 4}} }
	})
	code, out := do(t, ts, "GET", "/api/cluster", "", true)
	if code != http.StatusOK || out["detections"] == nil {
		t.Fatalf("cluster: %d %v", code, out)
	}
	servers := out["servers"].([]any)
	if len(servers) != 2 {
		t.Fatalf("servers %v", servers)
	}
	a, c := servers[0].(map[string]any), servers[1].(map[string]any)
	if sh, _ := a["shared"].(map[string]any); sh["mode"] != "member" || sh["config_seq"] != float64(7) {
		t.Errorf("siem-a %v", a)
	}
	if c["name"] != "siem-c" || c["removed"] != true {
		t.Errorf("siem-c %v", c)
	}

	cl.st.Servers[2].State = cluster.StateOffline
	cl.st.Servers[1].SeenAgo = &ago
	ts, _ = newTestServerWith(t, func(s *Server) { s.Cluster = cl })
	_, out = do(t, ts, "GET", "/api/cluster", "", true)
	for _, sv := range out["servers"].([]any) {
		if sv := sv.(map[string]any); sv["name"] == "siem-b" && sv["seen_seconds_ago"] != float64(90) {
			t.Errorf("siem-b %v", sv)
		}
	}
}
