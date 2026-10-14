package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// fakeCluster is two servers, siem-a and siem-b; this one is siem-b.
type fakeCluster struct {
	mu     sync.Mutex
	runs   bool
	holder string
}

func (f *fakeCluster) RunsJobs() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs
}

func (f *fakeCluster) JobHolder() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.holder
}

func (f *fakeCluster) set(runs bool, holder string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs, f.holder = runs, holder
}

func (f *fakeCluster) Banners() []string {
	if f.RunsJobs() || f.JobHolder() != "" {
		return nil
	}
	return []string{"No server is running detections, threat intel downloads or retention."}
}

func (f *fakeCluster) Status() cluster.Status {
	off := int64(-12)
	started := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	a := &cluster.Heartbeat{NodeID: "n_a", Name: "siem-a", Version: "1.5.0", OS: "linux", Arch: "amd64",
		NodeURL: "https://10.0.0.5:8443", Listen: "0.0.0.0:8443", LeaderEligible: true, ClockOffsetMS: &off,
		OpenSearch: cluster.OSInfo{OK: true, Endpoint: "https://os1:9200", LatencyMS: 3}, Problems: []string{}}
	b := &cluster.Heartbeat{NodeID: "n_b", Name: "siem-b", Version: "1.5.0", OS: "windows", Arch: "amd64",
		NodeURL: "https://10.0.0.6:8443", Listen: "0.0.0.0:8443", LeaderEligible: true, Problems: []string{}}
	acq := started.Add(time.Minute)
	return cluster.Status{Self: "n_b",
		Servers: []cluster.ServerStatus{
			{NodeID: "n_a", Name: "siem-a", State: cluster.StateReady, Version: "1.5.0", Jobs: "runs", StartedAt: started, HeartbeatAt: started, Detail: a},
			{NodeID: "n_b", Name: "siem-b", Self: true, State: cluster.StateReady, Version: "1.5.0", Jobs: "standby", StartedAt: started,
				HeartbeatAt: started, Detail: b, CannotTakeOver: "its retention policies differ from siem-a's"},
		},
		Jobs:     cluster.JobsStatus{Holder: "n_a", HolderName: "siem-a", Epoch: 17, AcquiredAt: &acq, RenewedAt: &acq},
		Warnings: []cluster.Warning{{Level: "amber", Text: "siem-b cannot take over the background jobs if siem-a stops: its retention policies differ from siem-a's."}},
	}
}

// The list of servers is for admins; everyone sees a banner when no
// server runs the background jobs.
func TestClusterIsForAdmins(t *testing.T) {
	cl := &fakeCluster{holder: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Cluster = cl
		s.Users = users.NewMemory()
		if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "vera", Role: users.Viewer, Password: "role-password"}); err != nil {
			t.Fatal(err)
		}
	})
	if code, _ := doAs(t, ts, "vera", "role-password", "GET", "/api/cluster", ""); code != http.StatusForbidden {
		t.Errorf("viewer: %d", code)
	}
	code, out := do(t, ts, "GET", "/api/cluster", "", true)
	if code != 200 {
		t.Fatalf("admin: %d %v", code, out)
	}
	a := out["servers"].([]any)[0].(map[string]any)
	if a["node_url"] != "https://10.0.0.5:8443" || a["clock_offset_ms"] != float64(-12) || a["opensearch"].(map[string]any)["latency_ms"] != float64(3) {
		t.Errorf("admin row %v", a)
	}
	if _, ok := a["uptime_seconds"]; !ok {
		t.Errorf("no uptime: %v", a)
	}
	b := out["servers"].([]any)[1].(map[string]any)
	if b["self"] != true || !strings.Contains(b["cannot_take_over"].(string), "retention policies") {
		t.Errorf("admin self row %v", b)
	}
	lease := out["lease"].(map[string]any)
	if lease["holder"] != "n_a" || lease["epoch"] != float64(17) || lease["mine"] != false {
		t.Errorf("admin lease %v", lease)
	}
	if w := out["warnings"].([]any); len(w) != 1 || out["self"] != "n_b" {
		t.Errorf("admin warnings %v self %v", w, out["self"])
	}
	// The banner, for everyone.
	_, h := doAs(t, ts, "vera", "role-password", "GET", "/api/health", "")
	if _, ok := h["cluster_banners"]; ok {
		t.Errorf("a banner while siem-a runs the jobs: %v", h["cluster_banners"])
	}
	cl.set(false, "")
	_, h = doAs(t, ts, "vera", "role-password", "GET", "/api/health", "")
	if b, _ := h["cluster_banners"].([]any); len(b) != 1 || !strings.HasPrefix(b[0].(string), "No server is running detections") {
		t.Errorf("banners %v", h["cluster_banners"])
	}
}

// On a server that does not run the background jobs, the Detections page
// says where they run.
func TestDetectionsSayWhereTheyRun(t *testing.T) {
	cl := &fakeCluster{holder: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Cluster = cl })
	_, out := do(t, ts, "GET", "/api/detections", "", true)
	if out["scheduler"] != false || out["runs_on"] != "siem-a" || out["scheduler_here"] != true {
		t.Errorf("standby: %v %v %v", out["scheduler"], out["runs_on"], out["scheduler_here"])
	}
	cl.set(true, "")
	_, out = do(t, ts, "GET", "/api/detections", "", true)
	if out["scheduler"] != true || out["runs_on"] != nil {
		t.Errorf("runner: %v %v", out["scheduler"], out["runs_on"])
	}
}

func TestClusterNeedsTheCluster(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _ := do(t, ts, "GET", "/api/cluster", "", true); code != http.StatusServiceUnavailable {
		t.Errorf("without a cluster: %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/cluster", "", false); code != http.StatusUnauthorized {
		t.Errorf("signed out: %d", code)
	}
}

// Of the servers that share one OpenSearch, only the one that runs the
// background jobs downloads feeds, so only its page changes them.
func TestFeedsChangeOnlyWhereTheyDownload(t *testing.T) {
	store := intel.NewStore(intel.NewMemory())
	if err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	feeds := &intel.Feeds{Store: store, AllowLoopback: true, File: filepath.Join(t.TempDir(), "intel_feeds.yaml")}
	cl := &fakeCluster{holder: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Intel, s.Feeds, s.Cluster = store, feeds, cl
	})
	code, raw := feedCall(t, ts, "GET", "/api/intel", "")
	if out := asMap(t, raw); code != 200 || out["manage"] != false || out["downloads"] != false ||
		!strings.HasPrefix(out["downloads_why"].(string), "This server does not download feeds right now: siem-a does") {
		t.Errorf("overview = %d %v", code, out)
	}
	add := `{"name":"x-feed","url":"https://feeds.example/x"}`
	if code, raw := feedCall(t, ts, "POST", "/api/intel/feeds", add); code != 409 || !strings.Contains(raw, "siem-a does") {
		t.Errorf("standby add = %d %s", code, raw)
	}
	cl.set(false, "")
	if code, raw := feedCall(t, ts, "POST", "/api/intel/feeds", add); code != 409 || !strings.Contains(raw, "no server runs the background jobs") {
		t.Errorf("no holder add = %d %s", code, raw)
	}
	cl.set(true, "")
	if code, raw := feedCall(t, ts, "POST", "/api/intel/feeds", add); code != 201 && code != 200 {
		t.Errorf("holder add = %d %s", code, raw)
	}
	if out := asMap(t, getRaw(t, ts, "/api/intel")); out["manage"] != true || out["downloads_why"] != nil {
		t.Errorf("holder overview %v", out)
	}
}

// The Health and Servers pages tell an OpenSearch that answers but turns
// Signalith away from one that can't be reached, and say how it refused;
// what to do is for admins.
func TestOpenSearchRefusalsInHealth(t *testing.T) {
	cl := &fakeCluster{holder: "siem-a"}
	ts, fos := newTestServerWith(t, func(s *Server) {
		s.Cluster = cl
		s.Users = users.NewMemory()
		if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "vera", Role: users.Viewer, Password: "role-password"}); err != nil {
			t.Fatal(err)
		}
	})
	osOf := func(body map[string]any) map[string]any {
		m, _ := body["opensearch"].(map[string]any)
		return m
	}
	for _, c := range []struct {
		name            string
		err             error
		status, problem string
		advice          string
	}{
		{"security settings not loaded", &store.Error{Status: 503, Body: "OpenSearch Security not initialized."}, "refused", "not_initialized",
			"Otherwise, with the Docker quick start, run docker compose -f deploy/docker/docker-compose.yml up -d again from the Signalith folder: " +
				"it re-runs the step that loads OpenSearch's security settings."},
		{"busy", &store.Error{Status: 429, Body: `{"error":{"type":"rejected_execution_exception","reason":"queue full"},"status":429}`}, "refused", "busy",
			"Signalith keeps trying."},
		{"no rights", &store.Error{Status: 403, Body: `{"error":{"type":"security_exception","reason":"no permissions"},"status":403}`}, "refused", "forbidden",
			"cluster_monitor"},
		{"not ready", &store.Error{Status: 503, Body: `{"error":{"type":"cluster_manager_not_discovered_exception","reason":"no cluster manager"},"status":503}`},
			"refused", "unavailable", "OpenSearch's log says why it isn't ready. With the Docker quick start, show it with docker compose -f deploy/docker/docker-compose.yml logs opensearch"},
		{"unreachable", errors.New("opensearch unreachable at http://os:9200: connection refused"), "unreachable", "", ""},
		// Reached, but too slow: not out of reach.
		{"no answer in time", noAnswerErr(t), "unreachable", "timeout", "Signalith keeps trying. If this lasts more than a few minutes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fos.healthErr = c.err
			_, body := do(t, ts, "GET", "/api/health", "", true)
			o := osOf(body)
			if o["status"] != c.status || (o["problem"] != nil) != (c.problem != "") || c.problem != "" && o["problem"] != c.problem || o["error"] != c.err.Error() {
				t.Errorf("admin: %v", o)
			}
			if adv, _ := o["advice"].(string); !strings.Contains(adv, c.advice) || c.advice == "" && adv != "" || strings.Contains(adv, "right to") {
				t.Errorf("advice %q", adv)
			}
			_, body = doAs(t, ts, "vera", "role-password", "GET", "/api/health", "")
			if o := osOf(body); o["status"] != c.status || o["error"] != nil || o["advice"] != nil || c.problem != "" && o["problem"] != c.problem {
				t.Errorf("viewer: %v", o)
			}
			_, body = do(t, ts, "GET", "/api/cluster", "", true)
			if o := osOf(body); o["status"] != c.status || c.problem != "" && o["problem"] != c.problem || o["url"] == nil {
				t.Errorf("cluster: %v", o)
			}
		})
	}
}

// noAnswerErr is the error of a request OpenSearch took but didn't
// answer in time.
func noAnswerErr(t *testing.T) error {
	t.Helper()
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer stall.Close()
	_, err := store.New(store.Config{URL: stall.URL, Timeout: 50 * time.Millisecond}).Health(context.Background())
	if !store.NoAnswer(err) {
		t.Fatalf("not a late answer: %v", err)
	}
	return err
}
