package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeUpgradeCluster answers the upgrade check, the list of servers and
// drain and resume as two servers, a (which runs the jobs) and b, do.
// A server runs 1.1 once a file named after it is in dir, which is what
// the test's install command writes.
type fakeUpgradeCluster struct {
	dir   string
	mu    sync.Mutex
	state map[string]string
	calls []string
}

func (f *fakeUpgradeCluster) version(name string) string {
	if _, err := os.Stat(filepath.Join(f.dir, name)); err == nil {
		return "1.1"
	}
	return "1.0"
}

func (f *fakeUpgradeCluster) serve(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	type server struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		State   string `json:"state"`
		Live    bool   `json:"live"`
		Jobs    bool   `json:"jobs"`
		NodeID  string `json:"node_id"`
	}
	list := func() []server {
		f.mu.Lock()
		defer f.mu.Unlock()
		var out []server
		for _, n := range []string{"a", "b"} {
			out = append(out, server{Name: n, Version: f.version(n), State: f.state[n], Live: true, Jobs: n == "a", NodeID: "id-" + n})
		}
		return out
	}
	mux.HandleFunc("GET /api/cluster/upgrade", func(w http.ResponseWriter, r *http.Request) {
		next := ""
		for _, s := range list() {
			if s.Version == "1.0" && (next == "" || !s.Jobs) {
				next = s.Name
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"safe": true, "servers": list(), "next": next})
	})
	mux.HandleFunc("GET /api/cluster", func(w http.ResponseWriter, r *http.Request) {
		var out []map[string]string
		for _, s := range list() {
			out = append(out, map[string]string{"name": s.Name, "state": s.State, "version": s.Version})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"servers": out})
	})
	for _, action := range []string{"drain", "resume"} {
		mux.HandleFunc("POST /api/cluster/servers/{id}/"+action, func(w http.ResponseWriter, r *http.Request) {
			name := strings.TrimPrefix(r.PathValue("id"), "id-")
			f.mu.Lock()
			f.calls = append(f.calls, action+" "+name)
			f.state[name] = map[string]string{"drain": "draining", "resume": "ready"}[action]
			f.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{}`))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func upgradeRunner(t *testing.T, cmd string) (*runner, *fakeUpgradeCluster, Fault) {
	f := &fakeUpgradeCluster{dir: t.TempDir(), state: map[string]string{"a": "ready", "b": "ready"}}
	srv := f.serve(t)
	r := &runner{m: newMetrics(), report: &Report{}, admin: []*Session{newSession(srv.URL, http.DefaultTransport, "admin", "pw")}}
	r.s = &Scenario{Criteria: []Criterion{{Name: "servers_not_upgraded"}}}
	return r, f, Fault{Kind: "upgrade", Cmd: fmt.Sprintf(cmd, filepath.Join(f.dir, "{server}"))}
}

func TestUpgradeAllStandbyFirst(t *testing.T) {
	r, f, fault := upgradeRunner(t, "echo x> %s")
	res := FaultResult{Kind: "upgrade"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r.upgradeAll(ctx, fault, &res)
	if res.Error != "" || res.Skipped != "" || len(res.Upgrades) != 2 {
		t.Fatalf("%+v", res)
	}
	if res.Upgrades[0].Server != "b" || res.Upgrades[1].Server != "a" {
		t.Errorf("order %+v: the server that runs the jobs goes last", res.Upgrades)
	}
	for _, u := range res.Upgrades {
		if u.From != "1.0" || u.To != "1.1" || !u.Drained {
			t.Errorf("%+v", u)
		}
	}
	want := "drain b,resume b,drain a,resume a"
	if got := strings.Join(f.calls, ","); got != want {
		t.Errorf("calls %s, want %s", got, want)
	}
	r.report.Faults = []FaultResult{res}
	if v, skip := r.measure(Criterion{Name: "servers_not_upgraded"}); skip != "" || v != 0 {
		t.Errorf("servers_not_upgraded %v %q", v, skip)
	}
	if _, skip := r.measure(Criterion{Name: "upgrade_server_seconds"}); skip != "" {
		t.Errorf("upgrade_server_seconds skipped: %q", skip)
	}
	var b strings.Builder
	r.report.WriteText(&b)
	if !strings.Contains(b.String(), "b: 1.0 to 1.1") {
		t.Errorf("report text:\n%s", b.String())
	}
}

func TestUpgradeAllStopsAtAFailedInstall(t *testing.T) {
	r, f, fault := upgradeRunner(t, "echo broken %s& exit 1")
	if os.PathSeparator == '/' {
		fault.Cmd = "echo broken; exit 1"
	}
	res := FaultResult{Kind: "upgrade"}
	r.upgradeAll(context.Background(), fault, &res)
	if len(res.Upgrades) != 1 || res.Upgrades[0].Error == "" || !strings.HasPrefix(res.Error, "b: ") {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(res.Upgrades[0].Output, "broken") {
		t.Errorf("output %q", res.Upgrades[0].Output)
	}
	if strings.Join(f.calls, ",") != "drain b" {
		t.Errorf("calls %v: the failed server stays drained for a person to look at", f.calls)
	}
	r.report.Faults = []FaultResult{res}
	if v, _ := r.measure(Criterion{Name: "servers_not_upgraded"}); v != 2 {
		t.Errorf("servers_not_upgraded %v, want 2", v)
	}
	r.report.Faults = nil
	if _, skip := r.measure(Criterion{Name: "servers_not_upgraded"}); skip != "no upgrade fault" {
		t.Errorf("no fault: %q", skip)
	}
}

func TestUpgradePick(t *testing.T) {
	var v upgradeView
	_ = json.Unmarshal([]byte(`{"servers":[{"name":"a","jobs":true},{"name":"c"},{"name":"b"}],"next":"z"}`), &v)
	if got := v.pick(map[string]string{"a": "", "c": "", "b": ""}); got != "b" {
		t.Errorf("pick %s, want b (no jobs, first by name)", got)
	}
	if got := v.pick(map[string]string{"a": ""}); got != "a" {
		t.Errorf("pick %s", got)
	}
	v.Next = "c"
	if got := v.pick(map[string]string{"a": "", "c": "", "b": ""}); got != "c" {
		t.Errorf("pick %s, want the check's next", got)
	}
}

func TestLeaseMoves(t *testing.T) {
	var l leaseMoves
	steps := []struct {
		epoch  int64
		holder string
		moved  bool
	}{
		{3, "a", false}, // the first holder seen
		{3, "a", false},
		{2, "b", false}, // an older answer
		{4, "", false},  // released, not taken yet
		{5, "a", false}, // taken back by the same server
		{6, "b", true},
		{6, "b", false},
	}
	for i, s := range steps {
		if got := l.seen(s.epoch, s.holder); got != s.moved {
			t.Errorf("step %d (%d %q): moved %v", i, s.epoch, s.holder, got)
		}
	}
}

func TestOpenPageReloadsOnce(t *testing.T) {
	var p openPage
	at := time.Unix(1_000_000, 0)
	if p.answered("1.0", at) || p.answered("", at) || p.answered("1.0", at) {
		t.Fatal("reloaded without another version")
	}
	if !p.answered("1.1", at.Add(time.Second)) || p.reloads != 1 {
		t.Fatal("no reload when a newer server answered")
	}
	// Both versions answer just after the reload: a warning, no reload.
	if p.answered("1.0", at.Add(30*time.Second)) || p.answered("1.0", at.Add(10*time.Minute)) || p.reloads != 1 {
		t.Errorf("reloaded again during the upgrade: %+v", p)
	}
	q := openPage{version: "1.0", lastReload: at}
	if !q.answered("1.1", at.Add(3*time.Minute)) {
		t.Error("a mismatch long after the last reload reloads")
	}
}
