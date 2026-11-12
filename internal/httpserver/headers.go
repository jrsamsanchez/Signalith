// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package httpserver

import "net/http"

// ContentSecurityPolicy lets pages load only Signalith's own scripts,
// styles, fonts and images, never be framed, and never submit forms or
// change their base URL to another site. Trusted Types keep the pages
// from ever writing HTML from text (they build every element through the
// DOM; browsers without Trusted Types ignore the directive).
//
// style-src keeps 'unsafe-inline': the pages set style attributes in
// their markup and through setAttribute, which a policy without it would
// block. Scripts, which are what an injection would need, stay 'self'.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'"

// PermissionsPolicy turns off browser features no page of Signalith
// uses, for the pages and anything they could be made to load. Features
// the pages do use (passkeys, copying to the clipboard) are left out, so
// they keep their default: this site only.
const PermissionsPolicy = "accelerometer=(), autoplay=(), browsing-topics=(), camera=(), display-capture=(), geolocation=(), " +
	"gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=()"

// SecurityHeaders sets the browser protections that do not depend on the
// request on h. The API sets them on every response it makes (with HSTS
// over HTTPS, which needs the request); the answers made before a
// request reaches it (health probes, "restarting", "too many requests")
// set them here, so no response goes out without them.
//
// HSTS has no includeSubDomains: Signalith is self-hosted, often at a
// name under a domain whose other hosts it knows nothing about, and the
// directive would hold every host under that name to HTTPS for a year.
func SecurityHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", ContentSecurityPolicy)
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", PermissionsPolicy)
}
