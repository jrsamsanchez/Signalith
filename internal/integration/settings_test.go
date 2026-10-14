//go:build integration && linux

package integration

// One Settings page for the servers of a cluster (multi-server design,
// PR 6), with real `signalith serve` processes: a sign-out time changed
// on one server is used by the other without a restart; servers that wait
// for a restart are restarted one at a time behind a round-robin proxy,
// which never finds a server that does not answer; a listen address of
// another server changed on this one moves that server, and the server
// that asked confirms the move at the new address; and a server killed in
// the middle of its restart fails its part, so the servers after it are
// not restarted.
//
// The unit tests in internal/config, internal/clustercfg, internal/api and
// cmd/signalith cover the rest against the in-memory fake (see the PR 6
// plan's list).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// settingsView is GET /api/settings as the tests need it.
type settingsView struct {
	Shared   bool `json:"shared"`
	Sections []struct {
		Fields []struct {
			Key     string `json:"key"`
			Value   any    `json:"value"`
			Pending bool   `json:"pending"`
		} `json:"fields"`
	} `json:"sections"`
	Servers []struct {
		NodeID        string   `json:"node_id"`
		Name          string   `json:"name"`
		Self          bool     `json:"self"`
		RestartNeeded []string `json:"restart_needed"`
		Restart       *struct {
			Last *struct {
				At time.Time `json:"at"`
				OK bool      `json:"ok"`
			} `json:"last"`
		} `json:"restart"`
	} `json:"servers"`
}

// settings reads the server's GET /api/settings; ok is false when it did
// not answer.
func (s *testServer) settings() (v settingsView, ok bool) {
	return v, s.call(http.MethodGet, "/api/settings", nil, &v) == http.StatusOK
}

// field returns a setting of the view.
func (v settingsView) field(key string) (value any, pending, found bool) {
	for _, sec := range v.Sections {
		for _, f := range sec.Fields {
			if f.Key == key {
				return f.Value, f.Pending, true
			}
		}
	}
	return nil, false, false
}

// nodeID returns the node id of the server named name, as v lists it.
func (v settingsView) nodeID(name string) string {
	for _, sv := range v.Servers {
		if sv.Name == name {
			return sv.NodeID
		}
	}
	return ""
}

// nodeIDs waits until the server lists the servers named, from their
// heartbeats, and returns their node ids.
func (s *testServer) nodeIDs(names ...string) []string {
	s.h.t.Helper()
	ids := make([]string, len(names))
	waitUntil(s.h.t, 30*time.Second, s.name+" lists "+strings.Join(names, ", "), func() bool {
		v, ok := s.settings()
		if !ok {
			return false
		}
		for i, n := range names {
			if ids[i] = v.nodeID(n); ids[i] == "" {
				return false
			}
		}
		return true
	})
	return ids
}

// waitsFor reports whether v lists the server named name as waiting for a
// restart to apply key.
func (v settingsView) waitsFor(name, key string) bool {
	for _, sv := range v.Servers {
		if sv.Name == name {
			return slices.Contains(sv.RestartNeeded, key)
		}
	}
	return false
}

// waitSettingsShared waits until every server shares its settings, which
// a new cluster does from the start.
func waitSettingsShared(t *testing.T, servers ...*testServer) {
	t.Helper()
	waitUntil(t, 120*time.Second, "the servers share their settings", func() bool {
		for _, s := range servers {
			if v, ok := s.settings(); !ok || !v.Shared {
				return false
			}
		}
		return true
	})
}

// saveSettings saves a change on the server's Settings page, of server's
// own settings when server is not "", and fails the test unless it was
// saved.
func (s *testServer) saveSettings(server string, values map[string]any) {
	t := s.h.t
	t.Helper()
	body := map[string]any{"values": values}
	if server != "" {
		body["server"] = server
	}
	if code, _, b := s.request(http.MethodPut, "/api/settings", body, nil); code != http.StatusOK {
		t.Fatalf("saving %v on %s: %d %s", values, s.name, code, b)
	}
}

// restartRequest is GET /api/requests/{id} of a restart of servers.
type restartRequest struct {
	State  string            `json:"state"`
	Status map[string]string `json:"status"`
	Error  string            `json:"error"`
	Result map[string]struct {
		OK         bool   `json:"ok"`
		RolledBack bool   `json:"rolled_back"`
		Error      string `json:"error"`
		Move       *struct {
			To        string `json:"to"`
			Confirmed bool   `json:"confirmed"`
		} `json:"move"`
	} `json:"result"`
}

// restartServers asks the server to restart servers (node ids) one at a
// time, and returns the request's id.
func (s *testServer) restartServers(ids ...string) string {
	t := s.h.t
	t.Helper()
	var out struct {
		RequestID string `json:"request_id"`
	}
	code, _, b := s.request(http.MethodPost, "/api/cluster/restart", map[string]any{"servers": ids, "sequential": true}, nil)
	if code != http.StatusAccepted || json.Unmarshal(b, &out) != nil || out.RequestID == "" {
		t.Fatalf("restart of %v on %s: %d %s", ids, s.name, code, b)
	}
	return out.RequestID
}

// restartRequest reads a restart request; ok is false when the server did
// not answer.
func (s *testServer) restartRequest(id string) (r restartRequest, ok bool) {
	return r, s.call(http.MethodGet, "/api/requests/"+id, nil, &r) == http.StatusOK
}

// waitRequestOver waits until the request is done or failed, and returns
// it.
func (s *testServer) waitRequestOver(id string, within time.Duration) restartRequest {
	t := s.h.t
	t.Helper()
	var r restartRequest
	waitUntil(t, within, "the restart request is over", func() bool {
		var ok bool
		r, ok = s.restartRequest(id)
		return ok && (r.State == "done" || r.State == "failed")
	})
	return r
}

// A sign-out time changed on one server's page applies on the other within
// seconds, with no restart.
func TestClusterSharedSettingsApplyEverywhere(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	waitSettingsShared(t, a, b)

	a.saveSettings("", map[string]any{"auth.session_timeout": "30m"})
	waitUntil(t, 20*time.Second, "siem-b uses the new sign-out time", func() bool {
		v, ok := b.settings()
		if !ok {
			return false
		}
		val, pending, found := v.field("auth.session_timeout")
		return found && val == "30m" && !pending
	})
}

// Servers that wait for a restart are restarted one at a time: behind a
// round-robin proxy every request is answered by a server throughout, and
// the second server restarts only after the first.
func TestClusterSequentialRestartBehindProxy(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	waitSettingsShared(t, a, b)

	// Replicas is shared and waits for each server's restart.
	a.saveSettings("", map[string]any{"opensearch.replicas": "1"})
	var v settingsView
	waitUntil(t, 60*time.Second, "both servers wait for a restart", func() bool {
		var ok bool
		v, ok = a.settings()
		return ok && v.waitsFor("siem-a", "opensearch.replicas") && v.waitsFor("siem-b", "opensearch.replicas")
	})

	lb := newRoundRobin(t, a, b)
	client := lb.srv.Client()
	client.Timeout = 30 * time.Second
	var stop atomic.Bool
	var mu sync.Mutex
	var bad []string
	var asked atomic.Int64
	var wg sync.WaitGroup
	wg.Go(func() {
		for !stop.Load() {
			req, _ := http.NewRequest(http.MethodGet, lb.srv.URL+"/api/me", nil)
			req.SetBasicAuth("admin", clusterPassword)
			resp, err := client.Do(req)
			asked.Add(1)
			switch {
			case err != nil:
				mu.Lock()
				bad = append(bad, err.Error())
				mu.Unlock()
			case resp.StatusCode == http.StatusBadGateway:
				mu.Lock()
				bad = append(bad, resp.Status)
				mu.Unlock()
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(20 * time.Millisecond)
		}
	})

	ids := a.nodeIDs("siem-b", "siem-a")
	id := a.restartServers(ids...)
	r := a.waitRequestOver(id, 3*time.Minute)
	stop.Store(true)
	wg.Wait()
	if r.State != "done" {
		t.Fatalf("the restart request ended %s: %s %+v", r.State, r.Error, r.Status)
	}
	if asked.Load() < 10 {
		t.Fatalf("only %d requests went through the proxy during the restart", asked.Load())
	}
	if len(bad) > 0 {
		t.Fatalf("the proxy found no server to answer %d of %d requests: %v", len(bad), asked.Load(), bad)
	}

	// siem-b restarted first, then siem-a, and neither waits any more.
	waitUntil(t, 60*time.Second, "both servers report their restart", func() bool {
		var ok bool
		v, ok = a.settings()
		if !ok || v.waitsFor("siem-a", "opensearch.replicas") || v.waitsFor("siem-b", "opensearch.replicas") {
			return false
		}
		for _, sv := range v.Servers {
			if sv.Restart == nil || sv.Restart.Last == nil || !sv.Restart.Last.OK {
				return false
			}
		}
		return true
	})
	var at = map[string]time.Time{}
	for _, sv := range v.Servers {
		at[sv.Name] = sv.Restart.Last.At
	}
	if !at["siem-b"].Before(at["siem-a"]) {
		t.Errorf("siem-a restarted at %v, before siem-b at %v", at["siem-a"], at["siem-b"])
	}
}

// A listen address of siem-b changed on siem-a's page moves siem-b when
// siem-a asks it to restart, and siem-a confirms the move at the new
// address, so siem-b stays there.
func TestClusterRemoteListenMove(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	waitSettingsShared(t, a, b)
	idB := a.nodeIDs("siem-b")[0]

	port := freePort(t)
	a.saveSettings(idB, map[string]any{"server.listen": fmt.Sprintf("127.0.0.1:%d", port)})
	waitUntil(t, 60*time.Second, "siem-b waits for a restart", func() bool {
		v, ok := a.settings()
		return ok && v.waitsFor("siem-b", "server.listen")
	})
	id := a.restartServers(idB)
	r := a.waitRequestOver(id, 4*time.Minute)
	if r.State != "done" {
		t.Fatalf("the restart request ended %s: %s %+v %+v", r.State, r.Error, r.Status, r.Result)
	}
	res := r.Result[idB]
	if res.Move == nil || !res.Move.Confirmed || !strings.Contains(res.Move.To, fmt.Sprint(port)) {
		t.Fatalf("the move was not confirmed at the new address: %+v", res)
	}
	old := b.port
	b.port = port
	if code := b.readyz(); code != http.StatusOK {
		t.Fatalf("siem-b at its new address: /readyz %d", code)
	}
	// It stays there: it does not go back once the move is confirmed.
	time.Sleep(5 * time.Second)
	if code := b.readyz(); code != http.StatusOK {
		t.Fatalf("siem-b left its new address: /readyz %d", code)
	}
	// The old address answers a while longer, for pages open there to
	// learn where it went, then closes.
	b.port = old
	waitUntil(t, 90*time.Second, "siem-b's old address closes", func() bool { return b.readyz() == 0 })
	b.port = port
}

// A server killed in the middle of its part of a restart fails that part
// once it starts again, and the servers after it are not restarted.
func TestClusterKilledDuringRestart(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	waitSettingsShared(t, a, b)
	ids := a.nodeIDs("siem-a", "siem-b")
	idA, idB := ids[0], ids[1]

	// A restart can be over before it is seen running: then try again with
	// another value.
	var id string
	for try := range 3 {
		a.saveSettings("", map[string]any{"opensearch.replicas": fmt.Sprint(try + 1)})
		waitUntil(t, 60*time.Second, "both servers wait for a restart", func() bool {
			v, ok := a.settings()
			return ok && v.waitsFor("siem-a", "opensearch.replicas") && v.waitsFor("siem-b", "opensearch.replicas")
		})
		id = a.restartServers(idB, idA)
		seen := ""
		deadline := time.Now().Add(2 * time.Minute)
		for seen == "" || seen == "queued" {
			if time.Now().After(deadline) {
				t.Fatal("siem-b never started its part of the restart")
			}
			if r, ok := a.restartRequest(id); ok {
				seen = r.Status[idB]
			}
			time.Sleep(5 * time.Millisecond)
		}
		if seen == "running" {
			b.kill9()
			break
		}
		a.waitRequestOver(id, 3*time.Minute)
		id = ""
	}
	if id == "" {
		t.Skip("siem-b's restart was over each time before it could be killed")
	}
	b.start()
	r := a.waitRequestOver(id, 3*time.Minute)
	if r.State != "failed" || r.Status[idB] != "failed" {
		t.Fatalf("the request after siem-b was killed: %s %+v %+v", r.State, r.Status, r.Result)
	}
	if st := r.Status[idA]; st == "done" || st == "running" {
		t.Errorf("siem-a restarted after siem-b failed: %s", st)
	}
}
