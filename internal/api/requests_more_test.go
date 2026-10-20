// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// reqShared is the shared configuration of a member of a cluster that
// keeps the requests made of it; submitErr, readErr and paused make it
// fail.
type reqShared struct {
	mu        sync.Mutex
	reqs      map[string]*shared.Request
	submitted []string
	submitErr error
	readErr   error
	paused    bool
}

func newReqShared() *reqShared { return &reqShared{reqs: map[string]*shared.Request{}} }

func (f *reqShared) Content() bool { return true }

func (f *reqShared) Writable() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.paused {
		return &shared.PausedError{Why: "OpenSearch cannot be reached"}
	}
	return nil
}

func (f *reqShared) Submit(_ context.Context, typ string, _ any, by string) (*shared.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.submitErr != nil {
		return nil, f.submitErr
	}
	req := &shared.Request{Kind: "request", ID: "req-" + typ, Type: typ, RequestedBy: by}
	f.reqs[req.ID] = req
	f.submitted = append(f.submitted, typ)
	return req, nil
}

func (f *reqShared) Request(_ context.Context, id string) (*shared.Request, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return nil, false, f.readErr
	}
	req, ok := f.reqs[id]
	return req, ok, nil
}

func (f *reqShared) set(change func(f *reqShared)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *reqShared) types() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.submitted...)
}

// A request is followed by its id; a server outside a cluster has none.
func TestHandleRequest(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, out := do(t, ts, "GET", "/api/requests/x", "", true); code != http.StatusNotFound || out["error"] != errNoRequests.Error() {
		t.Errorf("no cluster: %d %v", code, out)
	}

	sh := newReqShared()
	ts, _ = newTestServerWith(t, func(s *Server) { s.Shared = sh })
	if _, err := sh.Submit(context.Background(), "feed.refresh", nil, "admin"); err != nil {
		t.Fatal(err)
	}
	code, out := do(t, ts, "GET", "/api/requests/req-feed.refresh", "", true)
	if code != http.StatusOK || out["id"] != "req-feed.refresh" || out["type"] != "feed.refresh" {
		t.Errorf("found: %d %v", code, out)
	}
	if code, out := do(t, ts, "GET", "/api/requests/nope", "", true); code != http.StatusNotFound || !strings.Contains(out["error"].(string), "kept for 7 days") {
		t.Errorf("missing: %d %v", code, out)
	}
	sh.set(func(f *reqShared) { f.readErr = errDown })
	if code, _ := do(t, ts, "GET", "/api/requests/req-feed.refresh", "", true); code != http.StatusServiceUnavailable {
		t.Errorf("unreadable: %d", code)
	}
}

// newSharedRetentionServer is a member of a cluster whose retention
// policies are shared and which does not run the background jobs: runs
// and changes are asked of siem-a.
func newSharedRetentionServer(t *testing.T, change func(s *Server)) (*reqShared, func(method, path, body string) (int, map[string]any)) {
	t.Helper()
	dir := t.TempDir()
	mem := retention.NewMemory()
	mem.DiskTotal, mem.DiskBase = 100*retention.GB, 30*retention.GB
	m := &retention.Manager{
		Cluster: mem, Prefix: "signalith", Config: retention.Config{Days: 30},
		Store:       retention.NewStore(filepath.Join(dir, "retention.yaml")),
		Archive:     &retention.Archive{Dir: filepath.Join(dir, "archive")},
		HistoryFile: filepath.Join(dir, "retention_history.json"),
	}
	t.Cleanup(m.Wait)
	sh := newReqShared()
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Retention = m
		s.Shared = sh
		s.Cluster = &fakeCluster{holder: "siem-a"}
		if change != nil {
			change(s)
		}
	})
	return sh, func(method, path, body string) (int, map[string]any) {
		t.Helper()
		return do(t, ts, method, path, body, true)
	}
}

func TestRetentionSubmittedToTheJobServer(t *testing.T) {
	sh, call := newSharedRetentionServer(t, nil)

	code, out := call("POST", "/api/retention/run", "")
	if code != http.StatusAccepted || out["request_id"] != "req-"+clustercfg.RequestRetentionRun || out["queued_on"] != "siem-a" {
		t.Fatalf("run: %d %v", code, out)
	}
	// A change is saved here and applied by siem-a.
	code, out = call("PUT", "/api/retention/default", `{"keep_days":20}`)
	if code != http.StatusOK || out["run_started"] != false || out["run_queued"] != false || out["request_id"] == nil || out["queued_on"] != "siem-a" {
		t.Fatalf("change: %d %v", code, out)
	}
	if got := sh.types(); len(got) != 2 || got[1] != clustercfg.RequestRetentionRun {
		t.Errorf("requests made: %v", got)
	}

	// siem-a cannot be asked: the run is refused, the change still saved.
	sh.set(func(f *reqShared) { f.submitErr = errDown })
	if code, out := call("POST", "/api/retention/run", ""); code != http.StatusServiceUnavailable {
		t.Errorf("run with requests failing: %d %v", code, out)
	}
	code, out = call("PUT", "/api/retention/default", `{"keep_days":25}`)
	if code != http.StatusOK || out["request_id"] != nil {
		t.Errorf("change with requests failing: %d %v", code, out)
	}

	// The shared settings cannot be changed now: every change is 503.
	sh.set(func(f *reqShared) { f.paused = true })
	for _, rt := range []struct{ method, path, body string }{
		{"PUT", "/api/retention/default", `{"keep_days":10}`},
		{"PUT", "/api/retention/policies/endpoint", `{"keep_days":5}`},
		{"POST", "/api/retention/policies/confirm", ""},
	} {
		if code, out := call(rt.method, rt.path, rt.body); code != http.StatusServiceUnavailable || !strings.Contains(out["error"].(string), "OpenSearch cannot be reached") {
			t.Errorf("%s %s while paused: %d %v", rt.method, rt.path, code, out)
		}
	}
	sh.set(func(f *reqShared) { f.paused = false })
	// Nothing waits to be confirmed.
	if code, out := call("POST", "/api/retention/policies/confirm", ""); code < 400 {
		t.Errorf("confirm with nothing held: %d %v", code, out)
	}
}

// Where the archives are shared and siem-a runs restores, a restore is
// asked of it once confirmed; days that are not archived are a 404.
func TestRestoreQueued(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	sh, call := newSharedRetentionServer(t, func(s *Server) {
		s.Audit = &Audit{Client: cl, Prefix: "signalith", Shared: func() bool { return true }}
	})
	if _, out := call("GET", "/api/retention", ""); out["restore_queued"] != true {
		t.Errorf("overview: %v", out["restore_queued"])
	}
	if code, out := call("POST", "/api/retention/archive/restore", `{"ids":["nope"]}`); code != http.StatusNotFound {
		t.Errorf("unknown archive: %d %v", code, out)
	}
	code, out := call("POST", "/api/retention/archive/restore", `{"ids":["nope"],"confirm":true}`)
	if code != http.StatusAccepted || out["queued_on"] != "siem-a" {
		t.Fatalf("confirmed: %d %v", code, out)
	}
	if got := sh.types(); len(got) != 1 || !strings.Contains(got[0], "restore") {
		t.Errorf("requests made: %v", got)
	}
}

// The audit page's server filter lists the servers with records, and is
// empty while records are only in each server's log.
func TestAuditServers(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, out := do(t, ts, "GET", "/api/audit/servers", "", true); code != http.StatusOK || len(out["servers"].([]any)) != 0 {
		t.Errorf("off: %d %v", code, out)
	}

	// OpenSearch answers the terms aggregation over the audit indices
	// (a stand-in: the fake does not aggregate).
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() || !strings.HasSuffix(r.URL.Path, "/_search") {
			http.Error(w, `{"error":"unavailable"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":{"total":{"value":2},"hits":[]},"aggregations":{"servers":{"buckets":[{"key":"siem-a","doc_count":1},{"key":"siem-b","doc_count":1}]}}}`))
	}))
	defer srv.Close()
	cl := store.New(store.Config{URL: srv.URL})
	ts, _ = newTestServerWith(t, func(s *Server) {
		s.Audit = &Audit{Client: cl, Prefix: "signalith", Shared: func() bool { return true }}
	})
	code, out := do(t, ts, "GET", "/api/audit/servers", "", true)
	if list, _ := out["servers"].([]any); code != http.StatusOK || len(list) != 2 || list[1] != "siem-b" {
		t.Errorf("servers: %d %v", code, out)
	}
	down.Store(true)
	if code, out := do(t, ts, "GET", "/api/audit/servers", "", true); code != http.StatusServiceUnavailable {
		t.Errorf("OpenSearch down: %d %v", code, out)
	}
}

// A feed of shared intel is downloaded by the server that runs the
// background jobs: the refresh is asked of it.
func TestIntelRefreshSubmitted(t *testing.T) {
	st := intel.NewStore(intel.NewMemory())
	if err := st.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	sh := newReqShared()
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Intel = st
		s.Engine.Intel = st
		s.Feeds = &intel.Feeds{Store: st, Log: s.Log, List: []intel.Feed{
			{Name: "test-feed", URL: "https://feeds.example.invalid/list.txt", Format: "lines", Type: "auto", Interval: time.Hour, MaxAge: 24 * time.Hour, Enabled: true},
		}}
		s.Shared = sh
		s.Cluster = &fakeCluster{holder: "siem-a"}
	})
	if code, out := do(t, ts, "POST", "/api/intel/feeds/nope/refresh", "", true); code != http.StatusNotFound {
		t.Errorf("unknown feed: %d %v", code, out)
	}
	code, out := do(t, ts, "POST", "/api/intel/feeds/test-feed/refresh", "", true)
	if code != http.StatusAccepted || out["feed"] != "test-feed" || out["request_id"] != "req-"+clustercfg.RequestFeedRefresh || out["queued_on"] != "siem-a" {
		t.Errorf("refresh: %d %v", code, out)
	}
}
