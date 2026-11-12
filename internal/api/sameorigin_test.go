// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http/httptest"
	"testing"
)

// WEB-03: Origin must name this very site, scheme included; an https://
// public_url makes its host HTTPS-only; requests without browser headers
// still pass (API clients; the session cookie is SameSite=Strict).
func TestSameOriginComparesSchemeAndHost(t *testing.T) {
	for _, c := range []struct {
		name   string
		method string
		host   string
		https  bool
		public string
		site   string
		origin string
		want   bool
	}{
		{"read", "GET", "lab", true, "", "cross-site", "https://evil.example", true},
		{"same site over HTTPS", "POST", "lab", true, "", "same-origin", "https://lab", true},
		{"no headers", "POST", "lab", true, "", "", "", true},
		{"Sec-Fetch-Site only", "POST", "lab", true, "", "same-origin", "", true},
		{"cross-site", "POST", "lab", true, "", "cross-site", "", false},
		{"same-site", "POST", "lab", true, "", "same-site", "https://lab", false},
		{"http page to the HTTPS site", "POST", "lab", true, "", "", "http://lab", false},
		{"http page, Sec-Fetch-Site same-origin", "POST", "lab", true, "", "same-origin", "http://lab", false},
		{"another host", "POST", "lab", true, "", "", "https://evil.example", false},
		{"another port", "POST", "lab", true, "", "", "https://lab:8443", false},
		{"default port in Host", "POST", "lab:443", true, "", "", "https://lab", true},
		{"upper case", "POST", "LAB", true, "", "", "https://Lab", true},
		{"null origin", "POST", "lab", true, "", "", "null", false},
		{"not a web origin", "POST", "lab", true, "", "", "file://lab", false},
		{"IPv6", "POST", "[::1]:9443", true, "", "", "https://[::1]:9443", true},
		{"plain HTTP", "POST", "lab:8080", false, "", "", "http://lab:8080", true},
		// A proxy that adds HTTPS but is not trusted: the request looks
		// like plain HTTP, the page is HTTPS.
		{"untrusted HTTPS proxy", "POST", "lab", false, "", "", "https://lab", true},
		{"HTTPS public_url pins the scheme", "POST", "siem.example", false, "https://siem.example/", "", "http://siem.example", false},
		{"HTTPS public_url, https page", "POST", "siem.example", false, "https://siem.example/", "", "https://siem.example", true},
		{"public_url does not lock out the server's own address", "POST", "10.0.0.5:8443", true, "https://siem.example", "", "https://10.0.0.5:8443", true},
		// A proxy that rewrites Host: nginx's $host drops the port, and a
		// proxy with no Host line sends its upstream address.
		{"proxy dropped the port", "POST", "siem.example", true, "https://siem.example:8443", "", "https://siem.example:8443", true},
		{"proxy sent its upstream address", "POST", "127.0.0.1:9000", true, "https://siem.example", "same-origin", "https://siem.example", true},
		{"public_url origin over untrusted proxy", "POST", "127.0.0.1:9000", false, "https://siem.example", "", "https://siem.example", true},
		{"rewritten Host, another port than public_url", "POST", "siem.example", true, "https://siem.example:8443", "", "https://siem.example:9443", false},
		{"rewritten Host, another site", "POST", "127.0.0.1:9000", true, "https://siem.example", "", "https://evil.example", false},
		{"rewritten Host, http page of an HTTPS public_url", "POST", "127.0.0.1:9000", false, "https://siem.example", "", "http://siem.example", false},
		{"rewritten Host, https request, http public_url", "POST", "127.0.0.1:9000", true, "http://siem.example", "", "http://siem.example", false},
	} {
		r := httptest.NewRequest(c.method, "/api/login", nil)
		r.Host = c.host
		if c.site != "" {
			r.Header.Set("Sec-Fetch-Site", c.site)
		}
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		r = r.WithContext(context.WithValue(r.Context(), originKey{}, requestOrigin{https: c.https, public: originOf(c.public)}))
		if got := sameOrigin(r); got != c.want {
			t.Errorf("%s: sameOrigin = %v, want %v", c.name, got, c.want)
		}
	}
}
