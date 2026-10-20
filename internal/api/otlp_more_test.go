// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// OTLP senders retry what is answered 503 with Retry-After: a store that
// is down, tokens not read yet. A body that is not gzip as it says is
// 400 and not retried.
func TestOTLPFailures(t *testing.T) {
	var bulker *modeBulker
	ts, _ := newTestServerWith(t, func(s *Server) {
		bulker = &modeBulker{fakeOS: &fakeOS{}}
		s.Pipeline = &ingest.Pipeline{Store: bulker}
	})
	body := otlpProtoRequest("hello")
	if resp, raw := postOTLP(t, ts.URL, []byte("not gzip"), map[string]string{"Content-Encoding": "gzip"}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad gzip: %d %s", resp.StatusCode, raw)
	}
	bulker.set("down")
	resp, raw := postOTLP(t, ts.URL, body, nil)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "5" || !strings.Contains(string(raw), "could not be stored right now") {
		t.Errorf("store down: %d %s", resp.StatusCode, raw)
	}
	bulker.set("")
	// An agent token before the tokens are read: send again later.
	resp, raw = postOTLP(t, ts.URL, body, map[string]string{"Authorization": "Bearer sgl_" + strings.Repeat("c", 52)})
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Errorf("tokens not read: %d %s", resp.StatusCode, raw)
	}
}

// A tenant's token sends to that tenant's server; while another server
// runs the tenants the Collector is told to send again.
func TestOTLPTenantToken(t *testing.T) {
	_, _, rt, url := tenantFront(t)
	auth := map[string]string{"Authorization": "Bearer " + acmeToken}
	if resp, raw := postOTLP(t, url, otlpProtoRequest("for acme"), auth); resp.StatusCode != http.StatusOK {
		t.Errorf("acme's logs: %d %s", resp.StatusCode, raw)
	}
	notNow := errors.New("another server runs the tenants")
	rt.ready.Store(&notNow)
	resp, raw := postOTLP(t, url, otlpProtoRequest("for acme"), auth)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != tenantAgentRetry {
		t.Errorf("while another server runs acme: %d %s", resp.StatusCode, raw)
	}
}
