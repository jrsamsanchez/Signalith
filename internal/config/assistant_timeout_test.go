// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

// TestAssistantTimeouts: the AI model's time limits default to 3m and 6m,
// take durations from 30s up to 1h and 2h, and reach the client.
func TestAssistantTimeouts(t *testing.T) {
	for _, tc := range []struct {
		request, investigate string
		wantReq, wantInv     time.Duration
		bad                  string
	}{
		{"", "", 3 * time.Minute, 6 * time.Minute, ""},
		{"15m", "45m", 15 * time.Minute, 45 * time.Minute, ""},
		{"30s", "2h", 30 * time.Second, 2 * time.Hour, ""},
		{"1h", "", time.Hour, 6 * time.Minute, ""},
		{"10s", "", 0, 0, `assistant.request_timeout "10s" must be a duration from 30s to 1h`},
		{"2h", "", 0, 0, `assistant.request_timeout "2h" must be a duration from 30s to 1h`},
		{"", "3h", 0, 0, `assistant.investigate_timeout "3h" must be a duration from 30s to 2h`},
		{"", "soon", 0, 0, `assistant.investigate_timeout "soon" must be a duration`},
	} {
		c := validConfig(t)
		c.Assistant.RequestTimeout, c.Assistant.InvestigateTimeout = tc.request, tc.investigate
		err := c.Validate()
		if tc.bad != "" {
			if err == nil || !strings.Contains(err.Error(), tc.bad) {
				t.Errorf("%q/%q: got %v, want %q", tc.request, tc.investigate, err, tc.bad)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q/%q: %v", tc.request, tc.investigate, err)
		}
		if got := c.AssistantRequestTimeout(); got != tc.wantReq {
			t.Errorf("%q: request timeout %s, want %s", tc.request, got, tc.wantReq)
		}
		if got := c.AssistantInvestigateTimeout(); got != tc.wantInv {
			t.Errorf("%q: investigate timeout %s, want %s", tc.investigate, got, tc.wantInv)
		}
	}

	c := validConfig(t)
	if c.AssistantClient() != nil {
		t.Error("no provider: want no client")
	}
	c.Assistant.Provider, c.Assistant.Model, c.Assistant.RequestTimeout = "openai", "llama3.1", "15m"
	if cl := c.AssistantClient(); cl == nil || cl.HTTP.Timeout != 15*time.Minute {
		t.Errorf("client timeout: got %+v, want 15m", cl)
	}
}
