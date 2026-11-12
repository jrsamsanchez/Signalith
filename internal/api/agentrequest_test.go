// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// TestSenderBehindTrustedProxy: events record the client a trusted proxy
// names, not the proxy; a client header from anyone else is ignored
// (ING-209).
func TestSenderBehindTrustedProxy(t *testing.T) {
	cfg := config.Default()
	cfg.Server.TrustedProxies = []string{"10.0.0.5"}
	cfg.Server.ClientHeader = config.ClientHeaderXFF
	s := &Server{Config: cfg}
	for _, c := range []struct{ peer, xff, want string }{
		{"10.0.0.5:4000", "192.0.2.7", "192.0.2.7"},
		{"10.0.0.5:4000", "", "10.0.0.5"},
		{"198.51.100.9:4000", "192.0.2.7", "198.51.100.9"},
	} {
		r := httptest.NewRequest("POST", "/api/ingest", nil)
		r.RemoteAddr = c.peer
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		o := ingest.OriginFrom(s.withOrigin(r, ingest.IntakeAgent, agenttokens.Identity{ID: "t"}))
		if o.Sender != c.want {
			t.Errorf("%s via %s: sender %q, want %q", c.xff, c.peer, o.Sender, c.want)
		}
	}
}

// TestOTLPStalledBatchIsRetryable: a batch that took too long to arrive
// is answered 503 with Retry-After on the OTLP route, which the
// OpenTelemetry Collector retries, and still 408 for agents (ING-210).
func TestOTLPStalledBatchIsRetryable(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("POST", "/api/otlp/v1/logs", nil)
	stalled := fmt.Errorf("read: %w", &batchError{err: os.ErrDeadlineExceeded, received: 2048})
	if status, retry, err := s.otlpBatchFailure(r, stalled); status != http.StatusServiceUnavailable || retry == "" || err == nil {
		t.Errorf("otlp: %d %q %v", status, retry, err)
	}
	if status, _, _ := s.batchFailure(r, stalled); status != http.StatusRequestTimeout {
		t.Errorf("agent: %d", status)
	}
	if status, retry, _ := s.otlpBatchFailure(r, &http.MaxBytesError{Limit: 1}); status != http.StatusRequestEntityTooLarge || retry != "" {
		t.Errorf("too big: %d %q", status, retry)
	}
}

// TestBearerSchemeAnyCase: the agent routes take the Bearer scheme in any
// case, as HTTP's schemes are (ING-212).
func TestBearerSchemeAnyCase(t *testing.T) {
	for h, want := range map[string]string{
		"Bearer tok-1":   "tok-1",
		"bearer tok-1":   "tok-1",
		"BEARER  tok-1 ": "tok-1",
		"tok-1":          "tok-1",
		"Basic abc":      "Basic abc",
		"":               "",
	} {
		r := httptest.NewRequest("POST", "/api/ingest", nil)
		r.Header.Set("Authorization", h)
		if got := bearerToken(r); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", h, got, want)
		}
	}
}
