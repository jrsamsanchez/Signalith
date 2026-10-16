package api

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// Headers of read-your-writes behind a load balancer, and of the web UI
// during an upgrade (docs/servers.md#several-servers-behind-one-address).
const (
	// headerVersion is this server's version, on every response: a page
	// from another version reloads once when it sees it.
	headerVersion = "X-Signalith-Version"
	// headerConfig is how far this server has read the shared settings
	// ("<config index uuid>.<seq>"); after a change, how far it must be
	// read to see the change.
	headerConfig = "X-Signalith-Config"
	// headerConfigMin is the highest headerConfig the page has seen. A
	// server that is behind reads the shared settings once before it
	// answers, and sets headerStale when it is still behind.
	headerConfigMin = "X-Signalith-Config-Min"
	headerStale     = "X-Signalith-Stale"
)

// ConfigToken is how far this server has read the shared settings (see
// shared.Hub, which implements it).
type ConfigToken interface {
	// Token is this server's configuration token, "" before it read the
	// config index.
	Token() string
	// Written is the highest _seq_no this server wrote to the shared
	// settings, -1 when none.
	Written() int64
	// TokenAfter is the token of an answer to a write that made seq.
	TokenAfter(seq int64) string
	// Wait reads the shared settings once when this server is behind min,
	// and reports whether it still is.
	Wait(ctx context.Context, min string) (stale bool)
}

// configHeaders sets headerVersion on every response. The version is
// no secret from someone not signed in: the sign-in page names it in its
// script paths, as every server of one version must.
func (s *Server) configHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Version != "" {
			w.Header().Set(headerVersion, s.Version)
		}
		next.ServeHTTP(w, r)
	})
}

// configToken sets headerConfig, which names the config index, on the
// responses of signed-in requests (inside requireUser), and with okOnly
// on a successful sign-in. The token is taken when the response starts,
// so a request that changed the shared settings reports its own write.
func (s *Server) configToken(okOnly bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := s.ConfigToken
		if ct == nil {
			next.ServeHTTP(w, r)
			return
		}
		cw := &configWriter{ResponseWriter: w, ct: ct, before: -1, okOnly: okOnly}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			cw.writes, cw.before = true, ct.Written()
		}
		next.ServeHTTP(cw, r)
		cw.stamp(http.StatusOK)
	})
}

// awaitConfig honours headerConfigMin, for signed-in requests only: a
// request that waits costs a read of OpenSearch.
func (s *Server) awaitConfig(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if min := r.Header.Get(headerConfigMin); min != "" && s.ConfigToken != nil && strings.HasPrefix(r.URL.Path, "/api/") {
			if s.ConfigToken.Wait(r.Context(), min) {
				// Still behind after one read: the page asks again (only
				// a read; a change is checked against the shared
				// settings in OpenSearch anyway).
				w.Header().Set(headerStale, "1")
			}
		}
		next.ServeHTTP(w, r)
	})
}

// configWriter sets headerConfig when the response starts.
type configWriter struct {
	http.ResponseWriter
	ct      ConfigToken
	writes  bool
	before  int64
	stamped bool
	// okOnly sets the token only on a successful answer.
	okOnly bool
}

func (c *configWriter) stamp(code int) {
	if c.stamped {
		return
	}
	c.stamped = true
	if c.okOnly && code >= 300 {
		return
	}
	tok := ""
	if after := c.ct.Written(); c.writes && after > c.before {
		tok = c.ct.TokenAfter(after)
	} else {
		tok = c.ct.Token()
	}
	if tok != "" {
		c.Header().Set(headerConfig, tok)
	}
}

func (c *configWriter) WriteHeader(code int) {
	c.stamp(code)
	c.ResponseWriter.WriteHeader(code)
}

func (c *configWriter) Write(b []byte) (int, error) {
	c.stamp(http.StatusOK)
	return c.ResponseWriter.Write(b)
}

// Flush keeps streamed answers (Investigate with AI) streaming.
func (c *configWriter) Flush() {
	c.stamp(http.StatusOK)
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack is http.Hijacker's, for completeness.
func (c *configWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := c.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.ErrUnsupported
}

// Unwrap lets http.ResponseController reach the connection.
func (c *configWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// Versioned static files (4.9): behind a load balancer, a page from one
// version may ask a server of another for its scripts. index.html and
// login.html name every script and stylesheet under /v/<version>/, which
// only a server of that version serves, and which browsers keep for a
// year; a page whose files fail to load reloads (assets/loader.js). The
// unversioned paths keep working, for pages of the version before.

// versionSegment is the path segment of this server's version, "" when
// it has none that can be a path segment.
func versionSegment(v string) string {
	if v == "" || v == "." || v == ".." {
		return ""
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._+-", r)) {
			return ""
		}
	}
	return v
}

// versionedFiles serves a folder of the web UI under /v/<version>/: with
// a year's cache lifetime, except in a development build, whose files
// change without a new version.
func versionedFiles(version string, private bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".html") {
			// Pages are rendered and never cached (see page).
			http.NotFound(w, r)
			return
		}
		switch {
		case version == "dev":
			w.Header().Set("Cache-Control", "no-cache")
		case private:
			w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
		default:
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		next.ServeHTTP(w, r)
	})
}

// assetRef finds the relative script and stylesheet paths of a page:
// src or href of a <script> or <link> tag, not an API path.
var assetRef = regexp.MustCompile(`(<(?:script|link)\b[^>]*?\b(?:src|href)=")([A-Za-z0-9][^"#:]*)("[^>]*>)`)

// renderPage returns a page of the web UI with its scripts and
// stylesheets under /v/<version>/ and the version in its
// signalith-version meta tag. A tag marked data-unversioned keeps its
// path: the loader must load from a server of any version.
func renderPage(page []byte, version string) []byte {
	seg := versionSegment(version)
	page = bytes.Replace(page, []byte(`<meta name="signalith-version" content="">`),
		[]byte(`<meta name="signalith-version" content="`+htmlAttr(version)+`">`), 1)
	if seg == "" {
		return page
	}
	return assetRef.ReplaceAllFunc(page, func(m []byte) []byte {
		sub := assetRef.FindSubmatch(m)
		if bytes.Contains(m, []byte("data-unversioned")) || bytes.HasPrefix(sub[2], []byte("api/")) {
			return m
		}
		return []byte(string(sub[1]) + "v/" + seg + "/" + string(sub[2]) + string(sub[3]))
	})
}

// htmlAttr escapes s for an HTML attribute value in double quotes.
func htmlAttr(s string) string {
	return strings.NewReplacer(`&`, "&amp;", `"`, "&quot;", `<`, "&lt;", `>`, "&gt;").Replace(s)
}

// pages are the rendered pages of the web UI, made once per process.
type pages struct {
	mu   sync.Mutex
	done map[string][]byte
}

// page returns the rendered page name of the web UI.
func (s *Server) page(name string) ([]byte, error) {
	s.pageCache.mu.Lock()
	defer s.pageCache.mu.Unlock()
	if b, ok := s.pageCache.done[name]; ok {
		return b, nil
	}
	b, err := fs.ReadFile(s.UI, name)
	if err != nil {
		return nil, err
	}
	b = renderPage(b, s.Version)
	if s.pageCache.done == nil {
		s.pageCache.done = map[string][]byte{}
	}
	s.pageCache.done[name] = b
	return b, nil
}

// indexPage serves the rendered index.html at /, and every other path
// from next.
func (s *Server) indexPage(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			next.ServeHTTP(w, r)
			return
		}
		b, err := s.page("index.html")
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(b)
	})
}
