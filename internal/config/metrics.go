// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/netip"
	"strings"
)

// Metrics is the scrape endpoint for Prometheus and other OpenMetrics
// scrapers, GET /metrics, set on the Metrics tab of Settings or in
// signalith.yaml (metrics). It is off until turned on, and then answers
// only a scraper that sends the scrape token, from an allowed address
// when Allow lists any. See docs/metrics.md.
type Metrics struct {
	Enabled bool `yaml:"enabled,omitempty"`
	// TokenSHA256 is the SHA-256, in hex, of the bearer token scrapers
	// send. Only the hash is kept: the token is shown once, when it is
	// made.
	TokenSHA256 string `yaml:"token_sha256,omitempty"`
	// Allow lists the addresses and ranges scrapers may come from; empty
	// is any address that has the token.
	Allow []string `yaml:"allow,omitempty"`
}

// MetricsOn reports whether GET /metrics answers: turned on, with a
// scrape token, and never in demo mode.
func (c *Config) MetricsOn() bool {
	return c.Metrics.Enabled && !c.DemoOn() && sha256Pattern.MatchString(c.Metrics.TokenSHA256)
}

// MetricsToken reports whether token is the scrape token, in constant
// time.
func (c *Config) MetricsToken(token string) bool {
	want, err := hex.DecodeString(c.Metrics.TokenSHA256)
	if err != nil || len(want) != sha256.Size || token == "" {
		return false
	}
	got := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

// MetricsAllowList is metrics.allow as ranges; entries that are not an
// address or a range are left out (Validate reports them).
func (c *Config) MetricsAllowList() []netip.Prefix {
	var out []netip.Prefix
	for _, a := range c.Metrics.Allow {
		if p, err := parseAllow(a); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// metricsProblems checks metrics.
func (c *Config) metricsProblems() []string {
	m := c.Metrics
	var p []string
	if h := strings.TrimSpace(m.TokenSHA256); h != "" && !sha256Pattern.MatchString(h) {
		p = append(p, "metrics.token_sha256: must be the SHA-256 of the scrape token, 64 lower-case hex digits; create a new token on the Metrics tab of Settings")
	} else if m.Enabled && h == "" {
		p = append(p, "metrics.token_sha256: create a scrape token for Prometheus to send")
	}
	if msg := addressListProblem(m.Allow); msg != "" {
		p = append(p, "metrics.allow: "+msg)
	}
	return p
}
