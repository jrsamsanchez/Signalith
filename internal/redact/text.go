// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"regexp"
	"strings"
)

var (
	// urlInText finds URLs inside free text, such as an error message.
	urlInText = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	// pairInText finds name=value, name: value, name<tab>value and JSON
	// "name": "value" pairs whose names suggest a secret (password,
	// passphrase, token, api_key and the like), but not a file name such
	// as keys/master.key: a name starts the text or follows a character
	// that is not part of a name or path. It is narrower than
	// secretParams, so words such as "code" or "auth" in a message keep
	// their values. A value in quotes ends at its closing quote; any
	// other runs to the end of the field (a comma, semicolon, ampersand,
	// closing brace or the end of the line), so a password with a space
	// in it is hidden whole.
	pairInText = regexp.MustCompile(`(?i)(^|[^/A-Za-z0-9_.-])(["']?[A-Za-z0-9_.-]*(?:pass|pwd|secret|token|key|bearer|cookie|credential)[A-Za-z0-9_.-]*["']?)([ \t]*[=:][ \t]*|\t+)("(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*'|[^,;&}\r\n]+)`)
	// schemeInText finds Authorization header values: Bearer, Basic and
	// Token credentials.
	schemeInText = regexp.MustCompile(`\b((?i:bearer|basic)|Token)[ \t]+[A-Za-z0-9._~+/=-]{8,}`)
)

// Text returns free text, such as an error message, safe to log: URLs as
// URL shows them, the values of pairs whose names suggest a secret
// (password, passphrase, token, api_key and the like) and Bearer, Basic
// or Token credentials become "***". A secret with no name in front of
// it cannot be told from other words and stays.
func Text(s string) string {
	s = urlInText.ReplaceAllStringFunc(s, URL)
	s = schemeInText.ReplaceAllStringFunc(s, func(m string) string {
		i := strings.IndexAny(m, " \t")
		if m[:i] == "Token" && !strings.ContainsAny(m[i:], "0123456789") {
			// "Token validation failed": a word, not a credential.
			return m
		}
		return m[:i] + " " + Mask
	})
	return pairInText.ReplaceAllStringFunc(s, func(m string) string {
		p := pairInText.FindStringSubmatch(m)
		v := strings.TrimSpace(p[4])
		if v == Mask || strings.HasPrefix(v, "//") {
			return m
		}
		if q := v[0]; (q == '"' || q == '\'') && len(v) > 1 {
			// Keep the quotes, so JSON stays JSON.
			return p[1] + p[2] + p[3] + string(q) + Mask + string(q)
		}
		return p[1] + p[2] + p[3] + Mask
	})
}
