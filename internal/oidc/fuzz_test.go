// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"testing"
)

// FuzzSplitToken feeds the ID token parser anything: it must refuse
// what it can't read, never panic.
func FuzzSplitToken(f *testing.F) {
	f.Add("eyJhbGciOiJSUzI1NiIsImtpZCI6ImEifQ.eyJzdWIiOiIxIn0.c2ln")
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add("..")
	f.Add("a.b.c.d")
	f.Fuzz(func(t *testing.T, token string) {
		_, _, _, _, _ = splitToken(token)
	})
}

// FuzzParseKeys feeds the key set parser any JSON.
func FuzzParseKeys(f *testing.F) {
	f.Add(`{"keys":[{"kty":"RSA","kid":"a","n":"AQAB","e":"AQAB"}]}`)
	f.Add(`{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`)
	f.Add(`{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`)
	f.Fuzz(func(t *testing.T, raw string) {
		var set JWKS
		if json.Unmarshal([]byte(raw), &set) != nil {
			return
		}
		_ = parseKeys(set)
	})
}

// FuzzClaims reads claims of any shape by dotted path.
func FuzzClaims(f *testing.F) {
	f.Add(`{"groups":["a","b"],"realm_access":{"roles":["x"]},"email_verified":"true"}`, "realm_access.roles")
	f.Add(`{"groups":"a"}`, "groups")
	f.Fuzz(func(t *testing.T, raw, path string) {
		var c Claims
		if json.Unmarshal([]byte(raw), &c) != nil {
			return
		}
		_ = c.String(path)
		_ = c.Strings(path)
		_ = c.Has(path)
		_, _ = c.EmailVerified()
	})
}
