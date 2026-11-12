// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// WEB-04: the test lab's Caddy closes every route that works without
// signing in, except those its testers need to sign in. A route added to
// publicRoutes fails here until it is closed in
// deploy/testlab/testlab-setup.sh or listed below.
func TestLabClosesEveryTokenRoute(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "testlab", "testlab-setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`(?m)^\s*@closed path (.+)$`).FindStringSubmatch(strings.ReplaceAll(string(b), "\r\n", "\n"))
	if line == nil {
		t.Fatal("testlab-setup.sh has no @closed path line")
	}
	matchers := strings.Fields(line[1])
	// Caddy's path matcher: a trailing * matches any rest, otherwise the
	// path must be equal.
	closed := func(path string) bool {
		for _, m := range matchers {
			if prefix, ok := strings.CutSuffix(m, "*"); ok && strings.HasPrefix(path, prefix) || m == path {
				return true
			}
		}
		return false
	}
	// What testers use to sign in and out, and the CA certificate they
	// may need to trust the lab.
	open := map[string]bool{
		"POST /api/login": true, "POST /api/logout": true, "GET /api/tls/ca.pem": true, "POST /api/demo": true,
		"POST /api/login/passkey/options": true, "POST /api/login/passkey": true,
	}
	for _, route := range publicRoutes {
		if open[route] {
			continue
		}
		_, path, _ := strings.Cut(route, " ")
		// A wildcard segment such as {id} stands for any value.
		if i := strings.Index(path, "{"); i >= 0 {
			path = path[:i] + "x"
		}
		if !closed(path) {
			t.Errorf("the test lab leaves %s open: close it in deploy/testlab/testlab-setup.sh (@closed) or list it here as one testers need", route)
		}
	}
	for _, p := range []string{"/api/auth/oidc/start", "/api/auth/oidc/callback", "/api/auth/saml/acs"} {
		if !closed(p) {
			t.Errorf("single sign-on path %s is open on the lab", p)
		}
	}
}
