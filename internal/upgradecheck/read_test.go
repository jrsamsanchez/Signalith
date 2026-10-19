package upgradecheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeOpenSearch answers the reads Read makes. fail names a request kind
// (search, get, tasks) to answer with an error.
func fakeOpenSearch(t *testing.T, fail string, lease string) *store.Client {
	t.Helper()
	now := time.Now()
	hb := func(id, name string) json.RawMessage {
		b, _ := json.Marshal(cluster.Heartbeat{Kind: "node", NodeID: id, Name: name, State: cluster.StateReady, Version: "0.3.0", HeartbeatAt: now.Add(-time.Second)})
		return b
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		kind := "tasks"
		switch {
		case strings.HasSuffix(r.URL.Path, "/_search"):
			kind = "search"
		case strings.Contains(r.URL.Path, "/_doc/"):
			kind = "get"
		}
		if kind == fail {
			http.Error(w, `{"error":{"type":"boom","reason":"boom"}}`, http.StatusInternalServerError)
			return
		}
		switch kind {
		case "search":
			if r.URL.Path != "/sig_runtime/_search" {
				t.Errorf("search path %s", r.URL.Path)
			}
			hits := []map[string]any{
				{"_index": "sig_runtime", "_id": "1", "_source": hb("n_b", "siem-b")},
				{"_index": "sig_runtime", "_id": "2", "_source": hb("n_a", "siem-a")},
				{"_index": "sig_runtime", "_id": "3", "_source": map[string]any{"kind": "node"}},
				{"_index": "sig_runtime", "_id": "4", "_source": 5},
			}
			json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"total": map[string]any{"value": len(hits)}, "hits": hits}})
		case "get":
			if lease == "" {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"found":false}`))
				return
			}
			w.Write([]byte(`{"found":true,"_seq_no":1,"_primary_term":1,"_version":1,"_source":` + lease + `}`))
		default:
			if r.URL.Path != "/_tasks" || !strings.Contains(r.URL.RawQuery, "detailed") {
				t.Errorf("tasks request %s", r.URL)
			}
			w.Write([]byte(`{"nodes":{"x":{"tasks":{
				"1":{"action":"indices:data/write/delete/byquery","description":"delete-by-query [sig-events-*]"},
				"2":{"action":"indices:data/write/reindex","description":"reindex from [other-events] to [other-x]"},
				"3":{"action":"cluster:admin/snapshot/create","description":"snapshot [repo:nightly]"}}}}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return store.New(store.Config{URL: srv.URL})
}

func TestRead(t *testing.T) {
	ctx := context.Background()
	in, err := Read(ctx, fakeOpenSearch(t, "", `{"kind":"lease","holder":"n_a","holder_name":"siem-a","epoch":4}`), "sig", "n_a", nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, hb := range in.Heartbeats {
		names = append(names, hb.Name)
	}
	if !slices.Equal(names, []string{"siem-a", "siem-b"}) || in.Self != "n_a" {
		t.Errorf("heartbeats = %v", names)
	}
	if in.Lease == nil || in.Lease.Holder != "n_a" || in.Lease.Epoch != 4 {
		t.Errorf("lease = %+v", in.Lease)
	}
	want := []string{"cluster:admin/snapshot/create snapshot [repo:nightly]", "indices:data/write/delete/byquery delete-by-query [sig-events-*]"}
	if !in.TasksOK || !slices.Equal(in.Tasks, want) {
		t.Errorf("tasks = %v %v", in.Tasks, in.TasksOK)
	}

	// No lease, a lease that is not one, and no task list.
	in, err = Read(ctx, fakeOpenSearch(t, "tasks", ""), "sig", "n_a", nil)
	if err != nil || in.Lease != nil || in.TasksOK || in.Tasks != nil {
		t.Errorf("no lease = %+v %v", in, err)
	}
	if in, err = Read(ctx, fakeOpenSearch(t, "", `"not a lease"`), "sig", "n_a", nil); err != nil || in.Lease != nil {
		t.Errorf("odd lease = %+v %v", in.Lease, err)
	}

	if _, err := Read(ctx, fakeOpenSearch(t, "search", ""), "sig", "n_a", nil); err == nil || !strings.Contains(err.Error(), "heartbeats") {
		t.Errorf("search failure = %v", err)
	}
	if _, err := Read(ctx, fakeOpenSearch(t, "get", ""), "sig", "n_a", nil); err == nil || !strings.Contains(err.Error(), "runs the jobs") {
		t.Errorf("get failure = %v", err)
	}
}

func TestJudgeOldAndBrokenServers(t *testing.T) {
	now := time.Now()
	hb := func(id string, mod func(*cluster.Heartbeat)) cluster.Heartbeat {
		h := cluster.Heartbeat{Kind: "node", NodeID: "n_" + id, Name: "siem-" + id, State: cluster.StateReady, Version: "0.3.0",
			HeartbeatAt: now.Add(-time.Second), LeaderEligible: true}
		if mod != nil {
			mod(&h)
		}
		return h
	}
	v := Judge(Inputs{Now: now, Self: "n_a", TasksOK: true, Heartbeats: []cluster.Heartbeat{
		hb("a", nil),
		hb("b", func(h *cluster.Heartbeat) { h.State = cluster.StateDown }),
		hb("c", func(h *cluster.Heartbeat) { h.HeartbeatAt = now.Add(-8 * 24 * time.Hour) }),
		hb("d", func(h *cluster.Heartbeat) { h.State = cluster.StateConflict; h.Version = "" }),
	}})
	var blocked []string
	for _, n := range v.Blockers {
		if n.Code == "not_ready" {
			blocked = append(blocked, n.Server)
		}
	}
	if v.Safe || !slices.Equal(blocked, []string{"siem-b", "siem-d"}) {
		t.Errorf("blockers = %+v", v.Blockers)
	}
	for _, s := range v.Servers {
		if s.Name == "siem-c" {
			t.Error("a server not seen for a week was listed")
		}
	}
	if !slices.Contains(v.Versions, "unknown") {
		t.Errorf("versions = %v", v.Versions)
	}
	// No server runs the jobs: the first by name goes first.
	if v.Next != "To upgrade, start with siem-a." && !strings.HasPrefix(v.Next, "Upgrade siem-") {
		t.Errorf("next = %q", v.Next)
	}
}

func TestNextEdges(t *testing.T) {
	if got := Next(nil, nil, nil); got != "" {
		t.Errorf("no servers = %q", got)
	}
	a := cluster.Heartbeat{NodeID: "n_a", Name: "siem-a", Version: "0.4.0", Leader: true}
	b := cluster.Heartbeat{NodeID: "n_b", Name: "siem-b", Version: "0.3.0"}
	c := cluster.Heartbeat{NodeID: "n_c", Name: "siem-c", Version: "0.3.0"}
	// The leader sorts after the others even when it comes first.
	got := Next([]cluster.Heartbeat{a, b, c}, nil, map[string]int{"0.3.0": 0})
	if got != "To upgrade, start with siem-b." {
		t.Errorf("one version = %q", got)
	}
	// Every live server already runs the newest version.
	only := cluster.Heartbeat{NodeID: "n_a", Name: "siem-a", Version: "0.4.0"}
	if got := Next([]cluster.Heartbeat{only}, nil, map[string]int{"0.4.0": 0, "0.3.0": 0}); got != "" {
		t.Errorf("all upgraded = %q", got)
	}
}

func TestTextHelpers(t *testing.T) {
	if VersionText("") != "unknown" || VersionText("0.3.0") != "0.3.0" {
		t.Error("VersionText")
	}
	for d, want := range map[time.Duration]string{
		1500 * time.Millisecond:      "2s",
		90 * time.Second:             "2m0s",
		5*time.Hour + 20*time.Minute: "5h0m0s",
	} {
		if got := Ago(d); got != want {
			t.Errorf("Ago(%s) = %s, want %s", d, got, want)
		}
	}
}
