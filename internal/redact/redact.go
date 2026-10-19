// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package redact hides secrets in values Signalith shows or logs, such as
// a password or API key someone put in a configured URL.
package redact

import (
	"net/url"
	"strings"
)

// Mask replaces a hidden value.
const Mask = "***"

// secretParams are fragments of query parameter names whose values are
// hidden: api_key, apikey, access_token, X-Amz-Signature, password and
// the like.
var secretParams = []string{"key", "token", "secret", "pass", "pwd", "auth", "sig", "credential", "session", "cookie", "jwt", "bearer", "code"}

// URL returns s safe to show or log: any user name and password become
// "***", and so do the values of query parameters whose names suggest a
// secret (key, token, password, signature and so on). Everything else,
// including the scheme, host and path, is kept so the URL stays useful
// for troubleshooting. Text that is not a URL is cut to its scheme and
// host, or hidden entirely.
func URL(s string) string {
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		// A string that does not parse may still hold a secret, so keep
		// only what is plainly the scheme and host.
		if i := strings.Index(s, "://"); i > 0 {
			rest := s[i+3:]
			if j := strings.IndexAny(rest, "/?#"); j >= 0 {
				rest = rest[:j]
			}
			if k := strings.LastIndex(rest, "@"); k >= 0 {
				rest = Mask + "@" + rest[k+1:]
			}
			return s[:i+3] + rest
		}
		return Mask
	}
	if u.Host == "" && strings.Contains(s, "@") {
		// No "scheme://", as in user:password@host:9200: the parser reads
		// the user name as the scheme and keeps the password in the rest.
		// Keep only the host.
		rest := s[strings.LastIndex(s, "@")+1:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		return Mask + "@" + rest
	}
	if u.User != nil {
		u.User = url.User(Mask)
	}
	if u.RawQuery != "" {
		q := u.Query()
		changed := false
		for name, vals := range q {
			if !SecretName(name) {
				continue
			}
			for i := range vals {
				vals[i] = Mask
			}
			changed = true
		}
		if changed {
			u.RawQuery = q.Encode()
		}
	}
	if u.Fragment != "" && strings.Contains(u.Fragment, "=") {
		// Fragments such as #access_token=... carry tokens in OAuth flows.
		u.Fragment = Mask
	}
	// url.String escapes the "*"s; show them plainly.
	return strings.ReplaceAll(u.String(), "%2A%2A%2A", Mask)
}

// SecretName reports whether a parameter or header name suggests that its
// value is a secret.
func SecretName(name string) bool {
	n := strings.ToLower(name)
	for _, p := range secretParams {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// Strip returns s without its user name and password, for a URL whose
// credentials have been moved elsewhere. It returns the user name and
// password it removed (ok is false when there were none) and leaves s as
// it is when it does not parse.
func Strip(s string) (out, user, password string, ok bool) {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s, "", "", false
	}
	user = u.User.Username()
	password, _ = u.User.Password()
	u.User = nil
	return u.String(), user, password, true
}
