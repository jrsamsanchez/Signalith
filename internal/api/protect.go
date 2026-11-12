// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/httpserver"
)

// securityHeaders sets the browser protections on every response,
// including the sign-in page and errors: those of
// httpserver.SecurityHeaders (CSP, framing, Permissions-Policy and the
// rest), and HSTS over HTTPS.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		httpserver.SecurityHeaders(h)
		https := s.overHTTPS(r)
		if mutating(r.Method) {
			// What sameOrigin compares the browser's Origin with.
			r = r.WithContext(context.WithValue(r.Context(), originKey{}, requestOrigin{https: https, public: originOf(s.conf().Server.PublicURL)}))
		}
		if https && hstsHost(r.Host) {
			// Browsers then use only HTTPS for this site for a year. Sent
			// only over HTTPS, directly or through a trusted proxy;
			// browsers ignore it over plain HTTP or with a certificate
			// they had to be told to accept.
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// API replies carry events, cases and the ingest token; keep
			// them out of the browser's disk cache.
			h.Set("Cache-Control", "no-store")
			if r.Method+" "+r.URL.Path == "POST /api/logout" {
				// Signing out also empties the browser's cache of this
				// site. Stored preferences such as the theme stay.
				h.Set("Clear-Site-Data", `"cache"`)
			}
		}
		next.ServeHTTP(s.withErrorLog(w, r), r)
	})
}

// mutating reports whether a request of this method may change something.
func mutating(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// originKey is the request context key of requestOrigin.
type originKey struct{}

// requestOrigin is what sameOrigin compares a browser's Origin with,
// set by securityHeaders.
type requestOrigin struct {
	// https: the request reached Signalith over HTTPS, itself or through
	// a trusted proxy (overHTTPS).
	https bool
	// public is server.public_url's origin, "" when it is not set.
	public string
}

// sameOrigin rejects state-changing requests a browser sent from another
// site (WEB-03):
//
//   - Sec-Fetch-Site, when sent, must say same-origin or none.
//   - Origin, when sent, must be this very site: the same host and port
//     as the request, and the same scheme. A request that came over
//     HTTPS refuses an http:// page, which anyone on the network can
//     change. A request that came over plain HTTP also takes an https://
//     page of its host, which is what a proxy that adds HTTPS but is not
//     listed in server.trusted_proxies sends on.
//   - With an https:// server.public_url, a request for its host must
//     come from an https:// page, whatever the proxy says. Other hosts
//     (a server's own address, say) are not refused: a public_url set
//     wrong must not lock everyone out of signing in, and a page of
//     another host (DNS rebinding) never has the session cookie, which
//     is bound to the host it was set by.
//   - An Origin equal to server.public_url's origin (scheme, host and
//     port) passes whatever the Host header says, so a proxy that
//     rewrites Host (nginx's $host drops the port; a proxy with no Host
//     line sends its upstream's 127.0.0.1:9000) does not refuse every
//     sign-in. public_url is the operator's own statement of the site's
//     address, so this lets in no other site.
//
// Requests with neither header pass. They come from API clients, and
// from no browser that keeps cookies to one site: the session cookie is
// SameSite=Strict, so a cross-site request from a browser never carries
// it, and every browser that honours SameSite sends Sec-Fetch-Site or
// Origin on these requests anyway.
func sameOrigin(r *http.Request) bool {
	if !mutating(r.Method) {
		return true
	}
	site := r.Header.Get("Sec-Fetch-Site")
	if site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	got := originOf(origin)
	if got == "" {
		return false // "null", or not a web origin
	}
	ro, ok := r.Context().Value(originKey{}).(requestOrigin)
	if !ok {
		ro = requestOrigin{https: r.TLS != nil}
	}
	if strings.HasPrefix(ro.public, "https://") && sameHost(hostOfOrigin(ro.public), r.Host, ro.public) {
		// Every page of an HTTPS public address is HTTPS, whatever the
		// proxy in front says.
		ro.https = true
	}
	scheme, _, _ := strings.Cut(got, "://")
	if ro.https && scheme != "https" {
		return false
	}
	if ro.public != "" && got == ro.public {
		return true
	}
	return sameHost(hostOfOrigin(got), r.Host, got)
}

// originOf returns the origin of an absolute http or https URL, as a
// browser writes it in Origin (lower case, without a default port),
// and "" for anything else.
func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" && !(scheme == "http" && p == "80" || scheme == "https" && p == "443") {
		host += ":" + p
	}
	return scheme + "://" + host
}

// hostOfOrigin is the host[:port] part of an origin from originOf.
func hostOfOrigin(origin string) string {
	_, h, _ := strings.Cut(origin, "://")
	return h
}

// sameHost reports whether host (from an origin, without a default port)
// names the same host and port as hostHeader, a request's Host, whose
// default port is that of origin's scheme.
func sameHost(host, hostHeader, origin string) bool {
	if hostHeader == "" {
		return false
	}
	scheme, _, _ := strings.Cut(origin, "://")
	return originOf(scheme+"://"+hostHeader) == scheme+"://"+host
}

// hstsHost reports whether browsers should be told to use only HTTPS for
// host (a Host header). Not for localhost or an IP address: HSTS covers
// every port of a host, so after https://localhost:9000 the browser would
// force HTTPS on every other local tool and dev server for a year, and
// browsers ignore it for IP addresses anyway.
func hstsHost(hostport string) bool {
	h := hostport
	if hh, _, err := net.SplitHostPort(hostport); err == nil {
		h = hh
	}
	h = strings.ToLower(strings.TrimSuffix(strings.Trim(h, "[]"), "."))
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return false
	}
	_, err := netip.ParseAddr(h)
	return err != nil
}

// revalidate makes browsers check with the server before reusing a cached
// copy of a signed-in file, so after signing out the app sends them to the
// sign-in page instead of showing a stale copy. Pages themselves are not
// stored at all, so Back after signing out cannot bring one up.
// staticFiles serves the web UI's files from fsys. It never lists a
// folder, and it refuses a path with an encoded slash, backslash or dot or
// a ".." segment, so a path can't reach outside the files a route is meant
// to serve (/assets/..%2fapp.js is not app.js). With index, / serves
// index.html.
func staticFiles(fsys fs.FS, index bool) http.Handler {
	files := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.ToLower(r.URL.EscapedPath())
		p := r.URL.Path
		if strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") || strings.Contains(raw, "%2e") ||
			strings.Contains(p, "\\") || slices.Contains(strings.Split(p, "/"), "..") ||
			(strings.HasSuffix(p, "/") && !(index && p == "/")) {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func revalidate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p == "/" || strings.HasSuffix(p, ".html") {
			w.Header().Set("Cache-Control", "no-store")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

// Request body deadlines. The http.Server has no ReadTimeout because, once
// it passes, net/http also cancels the request's context, which would stop
// long searches; instead each request body gets its own deadline here.
var (
	// bodyTimeout is how long a client has to send a request body: ample
	// for any JSON request, and short enough that a client trickling a
	// body (to the sign-in form, say) cannot hold a connection for long.
	bodyTimeout = time.Minute
	// uploadTimeout is how long a signed-in upload (asset lists,
	// indicators) may take to arrive over a slow link. Agent batches have
	// their own deadlines, which stretch while a batch keeps arriving
	// (ingestReadTimeout and the rest in server.go).
	uploadTimeout = 10 * time.Minute
)

// limitBodies gives each request body bodyTimeout to arrive.
func limitBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			rc := http.NewResponseController(w)
			if rc.SetReadDeadline(time.Now().Add(bodyTimeout)) == nil {
				r.Body = &deadlineBody{ReadCloser: r.Body, rc: rc}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// allowSlowUpload gives the request body uploadTimeout to arrive. Call it
// only once the client has proved who it is.
func allowSlowUpload(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(uploadTimeout))
}

// maxUploadBytes caps an uploaded file (asset lists, indicators).
const maxUploadBytes = 16 << 20

// uploadBody gives a signed-in upload uploadTimeout to arrive and caps it
// at maxUploadBytes; a larger body fails to read with *http.MaxBytesError.
func uploadBody(w http.ResponseWriter, r *http.Request) io.Reader {
	allowSlowUpload(w)
	return http.MaxBytesReader(w, r.Body, maxUploadBytes)
}

// uploadFailed answers an upload that could not be read: 413 when it is
// too large, 400 otherwise.
func uploadFailed(w http.ResponseWriter, err error) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("the file is larger than %d MB, the most one upload takes; split it into smaller files", maxUploadBytes>>20))
		return
	}
	writeError(w, http.StatusBadRequest, err)
}

// deadlineBody lifts the read deadline once the whole body has arrived.
// After the body, net/http keeps reading the connection in the background
// to notice a client that goes away, and a deadline passing there would
// cancel a long-running request.
type deadlineBody struct {
	io.ReadCloser
	rc   *http.ResponseController
	done bool
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF && !b.done {
		b.done = true
		_ = b.rc.SetReadDeadline(time.Time{})
	}
	return n, err
}
