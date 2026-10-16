package api

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// contentSecurityPolicy lets pages load only Signalith's own scripts,
// styles, fonts and images, never be framed, and never submit forms or
// change their base URL to another site.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// securityHeaders sets the browser protections on every response,
// including the sign-in page and errors.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if s.overHTTPS(r) && hstsHost(r.Host) {
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
		next.ServeHTTP(w, r)
	})
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
