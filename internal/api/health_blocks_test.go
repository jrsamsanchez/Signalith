// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// TestHealthDiskBlock checks that Health says OpenSearch refuses writes
// when its disk passed the high watermark, though the cluster is green
// (LP-11).
func TestHealthDiskBlock(t *testing.T) {
	blocks := `{"blocks":{}}`
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/_cluster/health":
			io.WriteString(w, `{"status":"green"}`)
		case "/_cluster/state/blocks":
			io.WriteString(w, blocks)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	defer fake.Close()
	ts, _ := newTestServerWith(t, func(s *Server) { s.Backend = store.New(store.Config{URL: fake.URL}) })
	osOf := func() map[string]any {
		t.Helper()
		code, out := do(t, ts, "GET", "/api/health", "", true)
		if code != 200 {
			t.Fatalf("health = %d %v", code, out)
		}
		return out["opensearch"].(map[string]any)
	}
	if os := osOf(); os["status"] != "green" || os["problem"] != nil {
		t.Fatalf("no blocks: %v", os)
	}
	blocks = `{"blocks":{"global":{"10":{"description":"cluster create-index blocked (api)","retryable":false,"levels":["create_index"]}}}}`
	os := osOf()
	if os["status"] != "refused" || os["problem"] != "blocked" || !strings.Contains(os["advice"].(string), "high watermark") {
		t.Errorf("disk past the high watermark: %v", os)
	}
}
