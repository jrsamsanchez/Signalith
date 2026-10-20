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
	// pairInText finds name=value and name: value pairs whose names
	// suggest a secret (password, passphrase, token, api_key and the
	// like), but not a file name such as keys/master.key: a name starts
	// the text or follows a character that is not part of a name or path.
	// It is narrower than secretParams, so words such as "code" or "auth"
	// in a message keep their values.
	pairInText = regexp.MustCompile(`(?i)(^|[^/A-Za-z0-9_.-])([A-Za-z0-9_.-]*(?:pass|pwd|secret|token|key|bearer|cookie|credential)[A-Za-z0-9_.-]*)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&)]+)`)
	// schemeInText finds Authorization header values.
	schemeInText = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
)

// Text returns free text, such as an error message, safe to log: URLs as
// URL shows them, the values of name=value and name: value pairs whose
// names suggest a secret (password, passphrase, token, api_key and the
// like) and Bearer or Basic credentials become "***". A secret with no
// name in front of it cannot be told from other words and stays.
func Text(s string) string {
	s = urlInText.ReplaceAllStringFunc(s, URL)
	s = schemeInText.ReplaceAllStringFunc(s, func(m string) string {
		return m[:strings.IndexAny(m, " \t")] + " " + Mask
	})
	return pairInText.ReplaceAllStringFunc(s, func(m string) string {
		p := pairInText.FindStringSubmatch(m)
		if p[4] == Mask || strings.HasPrefix(p[4], "//") {
			return m
		}
		return p[1] + p[2] + p[3] + Mask
	})
}
