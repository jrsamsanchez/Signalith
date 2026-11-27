// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeSignalith is a cluster of stand-in servers sharing one state: the
// accounts, settings, cases and job lease the load generator reads and
// writes, with sign-in limits and version headers as the real ones have.
type fakeSignalith struct {
	t  *testing.T
	mu sync.Mutex
	// passwords by user; fails counts wrong passwords by user.
	passwords map[string]string
	fails     map[string]int
	// settings values and revisions by key.
	values   map[string]any
	versions map[string]int64
	// leader holds the job lease, at epoch.
	leader string
	epoch  int64
	// windows names the server that runs on Windows.
	windows string
	cases   map[string]string
	nextID  int
	// upgrade, when false, answers GET /api/cluster/upgrade with 404.
	upgrade bool
	// requests counts requests by "METHOD path-pattern".
	requests map[string]int
	patches  atomic.Int64
	// failUsers makes POST /api/users fail.
	failUsers bool
	servers   []*httptest.Server
	names     []string
}

func newFakeSignalith(t *testing.T, names ...string) *fakeSignalith {
	f := &fakeSignalith{t: t, passwords: map[string]string{"admin": "pw", "ana": "apw"}, fails: map[string]int{},
		values:   map[string]any{"search.max_events": 5000, "server.proxy_protocol": false},
		versions: map[string]int64{"search.max_events": 1, "server.proxy_protocol": 1},
		leader:   names[0], epoch: 1, cases: map[string]string{}, requests: map[string]int{}, names: names}
	if len(names) > 1 {
		f.windows = names[1]
	}
	for i, name := range names {
		srv := httptest.NewServer(f.handler(name, i))
		t.Cleanup(srv.Close)
		f.servers = append(f.servers, srv)
	}
	return f
}

func (f *fakeSignalith) urls() []string {
	var out []string
	for _, s := range f.servers {
		out = append(out, s.URL)
	}
	return out
}

func (f *fakeSignalith) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[key]
}

// takeOver moves the job lease to the next server, as a cut leader's
// standby takes it.
func (f *fakeSignalith) takeOver() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, n := range f.names {
		if n == f.leader {
			f.leader = f.names[(i+1)%len(f.names)]
			break
		}
	}
	f.epoch++
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeSignalith) handler(name string, idx int) http.Handler {
	mux := http.NewServeMux()
	var answers atomic.Int64
	user := func(r *http.Request) string {
		c, err := r.Cookie("fake_session")
		if err != nil {
			return ""
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, ok := f.passwords[c.Value]; !ok {
			return ""
		}
		return c.Value
	}
	authed := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.requests[pattern]++
			f.mu.Unlock()
			// The second server answers as another version every
			// other time, as during an upgrade.
			v := "v1"
			if idx > 0 && answers.Add(1)%2 == 0 {
				v = "v2"
			}
			w.Header().Set("X-Signalith-Version", v)
			if user(r) == "" {
				http.Error(w, `{"error":"sign in required"}`, http.StatusUnauthorized)
				return
			}
			h(w, r)
		})
	}
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Username, Password string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.requests["POST /api/login"]++
		pw, ok := f.passwords[in.Username]
		switch {
		case f.fails[in.Username] >= 2:
			f.mu.Unlock()
			http.Error(w, `{"error":"too many attempts"}`, http.StatusTooManyRequests)
			return
		case !ok || pw != in.Password:
			if ok {
				f.fails[in.Username]++
			}
			f.mu.Unlock()
			http.Error(w, `{"error":"wrong password"}`, http.StatusUnauthorized)
			return
		}
		f.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "fake_session", Value: in.Username, Path: "/"})
		writeJSON(w, map[string]string{"user": in.Username})
	})
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests["POST /api/logout"]++
		f.mu.Unlock()
		writeJSON(w, map[string]bool{"ok": true})
	})
	authed("GET /api/cluster", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var servers []map[string]any
		for _, n := range f.names {
			os := "linux"
			if n == f.windows {
				os = "windows"
			}
			servers = append(servers, map[string]any{"name": n, "self": n == name, "state": "ready", "os": os, "version": "v1"})
		}
		writeJSON(w, map[string]any{"self": name, "servers": servers,
			"lease": map[string]any{"holder_name": f.leader, "epoch": f.epoch, "mine": f.leader == name}})
	})
	authed("GET /api/cluster/upgrade", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		up := f.upgrade
		f.mu.Unlock()
		if !up {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{"safe": true})
	})
	authed("GET /api/findings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"findings": []map[string]string{{"id": "f1"}, {"id": "f/2"}, {"id": "f3"}, {"id": "f4"}}})
	})
	authed("PATCH /api/findings/{id}", func(w http.ResponseWriter, r *http.Request) {
		// Every other write is refused as busy.
		if f.patches.Add(1)%2 == 0 {
			http.Error(w, `{"error":"busy"}`, http.StatusConflict)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	authed("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]string{"status": "ok"}) })
	authed("POST /api/search", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["query"] == "" {
			http.Error(w, `{"error":"no query"}`, http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"rows": []any{}})
	})
	authed("POST /api/cases", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.nextID++
		id := fmt.Sprintf("case-%d", f.nextID)
		f.cases[id] = in["title"]
		f.mu.Unlock()
		writeJSON(w, map[string]any{"case": map[string]string{"id": id}})
	})
	authed("GET /api/cases", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var out []map[string]string
		for id, title := range f.cases {
			out = append(out, map[string]string{"id": id, "title": title})
		}
		// One more with a similar title, which is not the run's.
		out = append(out, map[string]string{"id": "other", "title": r.URL.Query().Get("q") + " (copy)"})
		writeJSON(w, map[string]any{"cases": out})
	})
	authed("PATCH /api/cases/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.cases, r.PathValue("id"))
		writeJSON(w, map[string]bool{"ok": true})
	})
	authed("POST /api/cases/{id}/entries", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]bool{"ok": true}) })
	authed("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var out []map[string]string
		for u := range f.passwords {
			out = append(out, map[string]string{"username": u})
		}
		writeJSON(w, map[string]any{"users": out})
	})
	authed("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Username, Password, Role string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failUsers || in.Username == "" || in.Role == "" {
			http.Error(w, `{"error":"no"}`, http.StatusBadRequest)
			return
		}
		f.passwords[in.Username] = in.Password
		writeJSON(w, map[string]bool{"ok": true})
	})
	authed("DELETE /api/users/{name}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		n := r.PathValue("name")
		if strings.HasSuffix(n, "-stuck") {
			http.Error(w, `{"error":"in use"}`, http.StatusConflict)
			return
		}
		if _, ok := f.passwords[n]; !ok {
			http.NotFound(w, r)
			return
		}
		delete(f.passwords, n)
		writeJSON(w, map[string]bool{"ok": true})
	})
	authed("GET /api/settings", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var fields []map[string]any
		for k, v := range f.values {
			fields = append(fields, map[string]any{"key": k, "value": v, "version": f.versions[k]})
		}
		writeJSON(w, map[string]any{"sections": []any{map[string]any{"fields": fields}}})
	})
	authed("PUT /api/settings", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Values    map[string]any   `json:"values"`
			IfVersion map[string]int64 `json:"if_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		for k, v := range in.Values {
			if want, ok := in.IfVersion[k]; ok && want != f.versions[k] {
				http.Error(w, `{"error":"changed"}`, http.StatusConflict)
				return
			}
			f.values[k] = v
			f.versions[k]++
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	authed("POST /api/seed/{n}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if len(b) > 0 && !json.Valid(b) || r.PathValue("n") == "2" {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	authed("POST /api/broken", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"broken"}`, http.StatusInternalServerError)
	})
	return mux
}

// fakeOpenSearch answers the reads the load generator makes of
// OpenSearch: node and index statistics, the servers' indices' health,
// and a search of a run's events.
func fakeOpenSearch(t *testing.T, health string) *httptest.Server {
	var ops atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_nodes/stats/indices/indexing,search,get", func(w http.ResponseWriter, r *http.Request) {
		n := ops.Add(100)
		writeJSON(w, map[string]any{"nodes": map[string]any{"a": map[string]any{"indices": map[string]any{
			"indexing": map[string]int64{"index_total": n, "delete_total": 1},
			"search":   map[string]int64{"query_total": 2}, "get": map[string]int64{"total": 3}}}}})
	})
	// Every index's statistics are refused, as for a certificate allowed
	// only Signalith's indices.
	mux.HandleFunc("GET /_stats/indexing,search,get", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	})
	mux.HandleFunc("GET /signalith*/_stats/indexing,search,get", func(w http.ResponseWriter, r *http.Request) {
		n := ops.Add(10)
		writeJSON(w, map[string]any{"indices": map[string]any{
			"signalith-events-1": map[string]any{"total": map[string]any{"indexing": map[string]int64{"index_total": n}}},
			"signalith_settings": map[string]any{"total": map[string]any{"search": map[string]int64{"query_total": 5}}},
		}})
	})
	mux.HandleFunc("GET /_cluster/health/{index}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": health})
	})
	mux.HandleFunc("POST /{index}/_search", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("index") != "signalith-*" {
			http.Error(w, "unexpected index "+r.PathValue("index"), http.StatusBadRequest)
			return
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["search_after"] != nil {
			writeJSON(w, map[string]any{"hits": map[string]any{"hits": []any{}}})
			return
		}
		hit := func(agent, seq any) map[string]any {
			return map[string]any{"_source": map[string]any{"loadgen_agent": agent, "loadgen_seq": seq}, "sort": []any{fmt.Sprint(agent, seq)}}
		}
		// Agent 0 has 1, 2 and 2 again, and 4 (3 is missing); agent 1 has
		// 1; one hit has no numbers.
		writeJSON(w, map[string]any{"hits": map[string]any{"hits": []any{
			hit("0", "1"), hit(0, 2), hit("0", "2"), hit("0", 4), hit(1, "1"),
			map[string]any{"_source": map[string]any{"message": "x"}},
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// files writes name: content files in a new folder and returns its path.
func files(t *testing.T, fs map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range fs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
