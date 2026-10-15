package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// lifecycleCluster is three servers: siem-a runs the jobs, siem-b is
// this one, and siem-c is in whatever state the test sets.
type lifecycleCluster struct {
	mu     sync.Mutex
	cState string
	cAgo   time.Duration
	cOld   bool // siem-c runs a version without drain
}

func (c *lifecycleCluster) set(state string, ago time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cState, c.cAgo = state, ago
}

func (c *lifecycleCluster) RunsJobs() bool    { return false }
func (c *lifecycleCluster) JobHolder() string { return "siem-a" }
func (c *lifecycleCluster) Banners() []string { return nil }
func (c *lifecycleCluster) Status() cluster.Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	feats := []string{cluster.FeatureDrain}
	row := func(id, name, state, jobs string, self bool) cluster.ServerStatus {
		return cluster.ServerStatus{NodeID: id, Name: name, State: state, Jobs: jobs, Self: self,
			Detail: &cluster.Heartbeat{NodeID: id, Name: name, Features: feats}}
	}
	cRow := row("n_c", "siem-c", c.cState, "standby", false)
	if c.cOld {
		cRow.Detail.Features = nil
	}
	if c.cState == cluster.StateOffline || c.cState == cluster.StateStopped {
		ago := c.cAgo
		cRow.SeenAgo = &ago
		cRow.Jobs = ""
	}
	return cluster.Status{Self: "n_b",
		Servers: []cluster.ServerStatus{row("n_a", "siem-a", cluster.StateReady, "runs", false),
			row("n_b", "siem-b", cluster.StateReady, "standby", true), cRow},
		Jobs: cluster.JobsStatus{Holder: "n_a", HolderName: "siem-a"}}
}

// fakeLifecycle records the requests made and the servers removed.
type fakeLifecycle struct {
	mu       sync.Mutex
	off      string
	rotation bool
	members  []string
	asked    []string // typ target
	removed  []string
}

func (f *fakeLifecycle) Off() string { return f.off }
func (f *fakeLifecycle) Lifecycle() ClusterLifecycle {
	f.mu.Lock()
	defer f.mu.Unlock()
	lc := ClusterLifecycle{Rotation: shared.RotationStatus{On: f.rotation}}
	for _, m := range f.members {
		lc.Members = append(lc.Members, LifecycleMember{NodeID: "n_" + strings.TrimPrefix(m, "siem-"), Name: m})
	}
	return lc
}
func (f *fakeLifecycle) Submit(_ context.Context, typ, target string, _ any, _ string) (*shared.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, typ+" "+target)
	return &shared.Request{ID: "rq_1"}, nil
}
func (f *fakeLifecycle) Remove(_ context.Context, nodeID, name, _ string, _ bool) (shared.RemovedServer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, nodeID)
	return shared.RemovedServer{NodeID: nodeID, Name: name}, nil
}

func (f *fakeLifecycle) take() (asked, removed []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	asked, removed = f.asked, f.removed
	f.asked, f.removed = nil, nil
	return asked, removed
}

func TestClusterServersLifecycle(t *testing.T) {
	cl := &lifecycleCluster{cState: cluster.StateReady}
	lf := &fakeLifecycle{rotation: true, members: []string{"siem-a", "siem-b", "siem-c"}}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Cluster = cl
		s.ClusterServers = lf
		s.Users = users.NewMemory()
		if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "ana", Role: users.Analyst, Password: "role-password"}); err != nil {
			t.Fatal(err)
		}
	})
	for _, r := range [][2]string{{"GET", "/api/cluster/lifecycle"}, {"POST", "/api/cluster/servers/n_c/drain"},
		{"DELETE", "/api/cluster/servers/n_c"}, {"POST", "/api/cluster/rotate-key"}} {
		if code, _ := doAs(t, ts, "ana", "role-password", r[0], r[1], ""); code != http.StatusForbidden {
			t.Errorf("analyst %s %s: %d", r[0], r[1], code)
		}
	}
	if code, out := do(t, ts, "GET", "/api/cluster/lifecycle", "", true); code != 200 || out["on"] != true {
		t.Fatalf("lifecycle: %d %v", code, out)
	}

	// Drain and resume.
	if code, out := do(t, ts, "POST", "/api/cluster/servers/n_c/drain", "", true); code != http.StatusAccepted || out["request_id"] != "rq_1" {
		t.Fatalf("drain: %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/cluster/servers/n_x/drain", "", true); code != http.StatusNotFound {
		t.Errorf("drain an unknown server: %d", code)
	}
	cl.mu.Lock()
	cl.cOld = true
	cl.mu.Unlock()
	if code, out := do(t, ts, "POST", "/api/cluster/servers/n_c/resume", "", true); code != http.StatusConflict || !strings.Contains(out["error"].(string), "upgrade") {
		t.Errorf("resume an old version: %d %v", code, out)
	}
	cl.mu.Lock()
	cl.cOld = false
	cl.mu.Unlock()
	if asked, _ := lf.take(); len(asked) != 1 || asked[0] != clustercfg.RequestDrain+" n_c" {
		t.Errorf("asked %v", asked)
	}

	// Removing a running server, or one that just went offline, is
	// refused; this server cannot remove itself.
	if code, out := do(t, ts, "DELETE", "/api/cluster/servers/n_c", "", true); code != http.StatusConflict || !strings.Contains(out["error"].(string), "drain it first") {
		t.Errorf("remove a running server: %d %v", code, out)
	}
	cl.set(cluster.StateOffline, 2*time.Minute)
	if code, _ := do(t, ts, "DELETE", "/api/cluster/servers/n_c", "", true); code != http.StatusConflict {
		t.Errorf("remove a server offline for 2 minutes: %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/cluster/servers/n_b", "", true); code != http.StatusBadRequest {
		t.Errorf("remove this server: %d", code)
	}
	if _, removed := lf.take(); len(removed) != 0 {
		t.Fatalf("removed %v", removed)
	}

	// Drained: removed, and the key rotated.
	cl.set(cluster.StateDraining, 0)
	code, out := do(t, ts, "DELETE", "/api/cluster/servers/n_c", "", true)
	if code != 200 || out["request_id"] != "rq_1" {
		t.Fatalf("remove a drained server: %d %v", code, out)
	}
	asked, removed := lf.take()
	if len(removed) != 1 || removed[0] != "n_c" || len(asked) != 1 || asked[0] != clustercfg.RequestRotateKey+" "+shared.TargetLeader {
		t.Errorf("removed %v, asked %v", removed, asked)
	}
	// Stopped, without rotating.
	cl.set(cluster.StateStopped, time.Minute)
	code, out = do(t, ts, "DELETE", "/api/cluster/servers/n_c?rotate=false", "", true)
	if code != 200 || out["rotate_skipped"] == nil || out["request_id"] != nil {
		t.Fatalf("remove without rotating: %d %v", code, out)
	}
	if asked, _ := lf.take(); len(asked) != 0 {
		t.Errorf("asked %v without rotating", asked)
	}

	// Moving the jobs.
	cl.set(cluster.StateReady, 0)
	if code, out := do(t, ts, "POST", "/api/cluster/jobs/move", `{"to":"n_c"}`, true); code != http.StatusAccepted || out["to"] != "siem-c" {
		t.Fatalf("move: %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/cluster/jobs/move", `{"to":"n_a"}`, true); code != http.StatusConflict {
		t.Errorf("move to the holder: %d", code)
	}
	if asked, _ := lf.take(); len(asked) != 1 || asked[0] != clustercfg.RequestReleaseJobs+" "+shared.TargetLeader {
		t.Errorf("asked %v", asked)
	}

	// Rotating the key needs the level.
	if code, _ := do(t, ts, "POST", "/api/cluster/rotate-key", "", true); code != http.StatusAccepted {
		t.Errorf("rotate: %d", code)
	}
	lf.mu.Lock()
	lf.rotation = false
	lf.mu.Unlock()
	if code, _ := do(t, ts, "POST", "/api/cluster/rotate-key", "", true); code != http.StatusConflict {
		t.Errorf("rotate below the level: %d", code)
	}
}

// Without a cluster the routes answer that this server is not in one.
func TestClusterServersOff(t *testing.T) {
	ts, _ := newTestServerWith(t, nil)
	if code, out := do(t, ts, "GET", "/api/cluster/lifecycle", "", true); code != 200 || out["on"] != false {
		t.Errorf("lifecycle: %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/cluster/rotate-key", "", true); code != http.StatusServiceUnavailable {
		t.Errorf("rotate: %d", code)
	}
}
