// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/retention"
)

// TestArchiveRestoreInstallsTheTemplate checks that the CLI restore puts
// the index template in place before it creates the index, so restored
// days get keyword fields even on a new OpenSearch.
func TestArchiveRestoreInstallsTheTemplate(t *testing.T) {
	dir := t.TempDir()
	index := "signalith-endpoint-2026.07.01"
	mem := retention.NewMemory()
	mem.AddIndex(index, 1, retention.Doc{ID: "a", Source: []byte(`{"user":"CORP\\Alice Smith"}`)})
	arch := &retention.Archive{Dir: filepath.Join(dir, "archive")}
	if _, err := arch.Write(context.Background(), mem, retention.Source{Index: index, Category: "endpoint", Day: "2026-07-01"}, 1); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var calls []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/_cluster/health":
			w.Write([]byte(`{"status":"green"}`))
		case strings.HasPrefix(r.URL.Path, "/_cat/indices/"):
			w.Write([]byte(`[]`))
		case r.URL.Path == "/_bulk":
			w.Write([]byte(`{"errors":false,"items":[]}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	cfg := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(cfg, []byte("opensearch:\n  url: "+ts.URL+"\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	stdout := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	err := cmdArchive([]string{"restore", "-c", cfg, "-dir", arch.Dir, index})
	os.Stdout = stdout
	if err != nil {
		t.Fatal(err)
	}
	tmpl := slices.Index(calls, "PUT /_index_template/signalith")
	create := slices.Index(calls, "PUT /"+index)
	if tmpl < 0 || create < 0 || tmpl > create || !slices.Contains(calls, "POST /_bulk") {
		t.Errorf("calls = %v", calls)
	}
}
