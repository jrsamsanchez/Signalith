// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// TestIngestAsksForResendWhenStorageRefuses: when OpenSearch turns events
// away for a reason that may pass (here a full disk's write block), the
// agent gets 503 with Retry-After, so Fluent Bit sends the batch again
// instead of dropping it; a resend of events already stored counts them
// as duplicates instead of storing them twice.
func TestIngestAsksForResendWhenStorageRefuses(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	ts, _ := newTestServerWith(t, func(s *Server) { s.Pipeline = &ingest.Pipeline{Store: cl} })
	batch := `[{"message":"one","host":"web-1"},{"message":"one","host":"web-1"}]`
	send := func() (int, string, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(batch))
		req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
		req.Header.Set("X-Signalith-Tag", "app.log")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, resp.Header.Get("Retry-After"), out
	}

	fake.Block(true)
	code, retry, out := send()
	if code != http.StatusServiceUnavailable || retry == "" || out["temporary"] != float64(2) || out["indexed"] != float64(0) {
		t.Fatalf("blocked write = %d Retry-After %q %v", code, retry, out)
	}
	fake.Block(false)
	// Two identical records in one batch are two events.
	if code, _, out = send(); code != 200 || out["indexed"] != float64(2) || out["duplicates"] != nil {
		t.Fatalf("resend = %d %v", code, out)
	}
	// The same batch again (a resend after a lost answer) stores nothing new.
	if code, _, out = send(); code != 200 || out["indexed"] != float64(2) || out["duplicates"] != float64(2) || out["rejected"] != nil {
		t.Fatalf("second resend = %d %v", code, out)
	}
}
