// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// SCIM lets the identity provider of single sign-on add, change, disable
// and remove single sign-on users ahead of their sign-ins (provisioning,
// SCIM 2.0), set on the Single sign-on tab of Settings or in
// signalith.yaml (auth.scim). See docs/sso.md.
type SCIM struct {
	Enabled bool `yaml:"enabled,omitempty"`
	// TokenSHA256 is the SHA-256, in hex, of the bearer token the
	// provider sends. Only the hash is kept: the token is shown once, when
	// it is made.
	TokenSHA256 string `yaml:"token_sha256,omitempty"`
}

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SCIMOn reports whether provisioning is on with a token: never in demo
// mode.
func (c *Config) SCIMOn() bool {
	return c.Auth.SCIM.Enabled && !c.DemoOn() && sha256Pattern.MatchString(c.Auth.SCIM.TokenSHA256)
}

// SCIMToken reports whether token is the provisioning token, in constant
// time.
func (c *Config) SCIMToken(token string) bool {
	want, err := hex.DecodeString(c.Auth.SCIM.TokenSHA256)
	if err != nil || len(want) != sha256.Size || token == "" {
		return false
	}
	got := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

// scimProblems checks auth.scim.
func (c *Config) scimProblems() []string {
	s := c.Auth.SCIM
	var p []string
	if h := strings.TrimSpace(s.TokenSHA256); h != "" && !sha256Pattern.MatchString(h) {
		p = append(p, "auth.scim.token_sha256: must be the SHA-256 of the token, 64 lower-case hex digits; create a new token on the Single sign-on tab")
	} else if s.Enabled && h == "" {
		p = append(p, "auth.scim.token_sha256: create a token for the identity provider to send")
	}
	return p
}

// sha256Hex checks the page's value of auth.scim.token_sha256.
func sha256Hex(v any) error {
	if s, _ := v.(string); s != "" && !sha256Pattern.MatchString(s) {
		return errors.New("create the token with the Create token button")
	}
	return nil
}
