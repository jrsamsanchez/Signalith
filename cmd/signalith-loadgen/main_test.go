package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRunCommands(t *testing.T) {
	var out, errOut strings.Builder
	if code := run(context.Background(), nil, &out, &errOut); code != exitError {
		t.Errorf("no command: %d", code)
	}
	if code := run(context.Background(), []string{"nope"}, &out, &errOut); code != exitError {
		t.Errorf("unknown command: %d", code)
	}
	files, _ := filepath.Glob(filepath.Join("..", "..", "loadtest", "*.yaml"))
	if code := run(context.Background(), append([]string{"check"}, files...), &out, &errOut); code != exitPass {
		t.Errorf("check: %d %s", code, errOut.String())
	}
	if code := run(context.Background(), []string{"run"}, &out, &errOut); code != exitError {
		t.Errorf("run without -f: %d", code)
	}
}

// A one-server stand-in that takes agent batches and answers sign-in and
// the cluster API as a server that is not part of a cluster does.
func standIn(t *testing.T, stored *atomic.Int64) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ingest", func(w http.ResponseWriter, r *http.Request) {
		var events []map[string]any
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &events); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		stored.Add(int64(len(events)))
		_ = json.NewEncoder(w).Encode(map[string]int{"received": len(events), "indexed": len(events)})
	})
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "signalith_session", Value: "s", Path: "/"})
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("GET /api/cluster", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("signalith_session"); err != nil || c.Value != "s" {
			http.Error(w, `{"error":"sign in required"}`, http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"self":"n1","lease":{"holder_name":"one","mine":true},"servers":[{"name":"one","self":true,"state":"ready"}]}`))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestAgentsCommand(t *testing.T) {
	var stored atomic.Int64
	srv := standIn(t, &stored)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "token.txt")
	admin := filepath.Join(dir, "admin.txt")
	_ = os.WriteFile(token, []byte("tok\n"), 0o600)
	_ = os.WriteFile(admin, []byte("admin:pw\n"), 0o600)
	report := filepath.Join(dir, "report.json")
	var out, errOut strings.Builder
	code := run(context.Background(), []string{"agents", "-q", "-target", srv.URL, "-ca", ca, "-token-file", token,
		"-admin-file", admin, "-n", "3", "-rate", "300", "-for", "500ms", "-json", report}, &out, &errOut)
	if code != exitPass {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errOut.String())
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Cluster || len(rep.Phases) == 0 || stored.Load() == 0 {
		t.Errorf("report %+v, stored %d", rep, stored.Load())
	}
	sent := int64(0)
	for _, p := range rep.Phases {
		sent += p.Counts["agent_events_stored"]
	}
	if sent != stored.Load() {
		t.Errorf("report says %d stored, server stored %d", sent, stored.Load())
	}
}
