package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// viaTrustedProxy reports whether a request came through a reverse proxy
// listed in server.trusted_proxies that says the browser used HTTPS.
// X-Forwarded-Proto from anyone else is ignored, since any client can
// send it; except that a config from before HTTPS was the default, with
// no trusted_proxies, believes it from this machine and private networks
// (see config.Server.LegacyProxy), so a proxy set up the old way keeps
// working. The Health page then names the proxy to list.
func (s *Server) viaTrustedProxy(r *http.Request) bool {
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	if !strings.EqualFold(strings.TrimSpace(proto), "https") {
		return false
	}
	from := clientaddr.Parse(r.RemoteAddr)
	if !from.IsValid() {
		return false
	}
	if s.conf().Server.TrustsProxy(from) {
		return true
	}
	if s.conf().Server.LegacyProxy(from) {
		s.legacyProxies.note(from)
		return true
	}
	return false
}

// maxLegacyProxies caps the proxies the legacy proxy list remembers.
const maxLegacyProxies = 16

// addrSeen remembers addresses and when each was last seen, up to max
// of them (maxLegacyProxies when 0): the reverse proxies believed only
// because the config predates HTTPS by default, for the Health page, and
// the computers that signed in over plain HTTP, for the Security page.
type addrSeen struct {
	max int
	mu  sync.Mutex
	m   map[netip.Addr]time.Time
}

func (l *addrSeen) note(a netip.Addr) {
	a = a.Unmap().WithZone("")
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[netip.Addr]time.Time{}
	}
	if _, ok := l.m[a]; !ok {
		switch {
		case l.max == 0 && len(l.m) >= maxLegacyProxies:
			return
		case l.max > 0 && len(l.m) >= l.max:
			// Make room by forgetting the one seen longest ago.
			var oldest netip.Addr
			for k, v := range l.m {
				if !oldest.IsValid() || v.Before(l.m[oldest]) {
					oldest = k
				}
			}
			delete(l.m, oldest)
		}
	}
	l.m[a] = time.Now()
}

// since lists the addresses seen since t, in address order.
func (l *addrSeen) since(t time.Time) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []netip.Addr
	for a, seen := range l.m {
		if !seen.Before(t) {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	names := make([]string, len(out))
	for i, a := range out {
		names[i] = a.String()
	}
	return names
}

// overHTTPS reports whether the browser reached Signalith over HTTPS:
// directly, or through a trusted proxy.
func (s *Server) overHTTPS(r *http.Request) bool {
	return r.TLS != nil || s.viaTrustedProxy(r)
}

type plaintextKey struct{}

// plaintextIngest reports whether an ingest request came over plain HTTP
// to the HTTPS port (see PlainHandler).
func plaintextIngest(r *http.Request) bool {
	v, _ := r.Context().Value(plaintextKey{}).(bool)
	return v
}

// PlainHandler answers plain HTTP on the port that serves HTTPS, so
// http:// addresses keep working without ever handling a password or
// session in clear text. secure is the handler from Handler.
//
//   - Browsers asking for a page are sent to the same address over HTTPS.
//   - Sign-in, and any request carrying a password (HTTP Basic) or a
//     session for the API, is refused with a message to use https://.
//   - Agents (Fluent Bit to /api/ingest, OpenTelemetry Collectors to
//     OTLP) may still send events when server.tls.plaintext_ingest is
//     allow; each one is noted so the Health page can name it. Only the
//     ingest handlers see those requests, never the rest of the API.
//     Otherwise the batch of an agent that holds a token is refused with
//     503, which both agents keep and send again (they drop a batch
//     refused with 4xx), and the Health page names the agent to update
//     from the Add data page. A wrong token, or none, is refused with
//     401, as over HTTPS: only agents with a token count.
//   - A trusted reverse proxy that says the browser used HTTPS is served
//     as usual.
func (s *Server) PlainHandler(secure http.Handler) http.Handler {
	ingestOnly := map[string]http.Handler{
		"POST /api/ingest": limitBodies(s.securityHeaders(http.HandlerFunc(s.handleIngest))),
		otlpLogsRoute:      limitBodies(s.securityHeaders(http.HandlerFunc(s.handleOTLPLogs))),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.viaTrustedProxy(r) {
			secure.ServeHTTP(w, r)
			return
		}
		target := s.httpsURL(r)
		route := r.Method + " " + r.URL.Path
		// The escaped path, so /api%2Fingest, which the API's router would
		// not take for ingest, is not taken for it here either.
		if h, ok := ingestOnly[r.Method+" "+r.URL.EscapedPath()]; ok {
			if s.conf().Server.PlaintextIngest() {
				h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), plaintextKey{}, true)))
				return
			}
			if !s.validToken(r) && !s.oldTokenAgent(r) {
				s.Pipeline.NoteRefused(clientaddr.Parse(r.RemoteAddr), ingest.RefusedToken)
				plainRefusal(w, r, http.StatusUnauthorized, "missing or invalid ingest token")
				return
			}
			s.Pipeline.NoteRefused(clientaddr.Parse(r.RemoteAddr), ingest.RefusedPlaintext)
			w.Header().Set("Retry-After", "60")
			plainRefusal(w, r, http.StatusServiceUnavailable, "This server only accepts events over HTTPS, so this batch was refused; the agent keeps it and sends it again. "+
				"Get a new configuration for this agent from the Add data page (it sends to "+s.httpsBase(r)+"), or, until every agent has one, accept agents on plain HTTP for now on the Settings page, under HTTPS (server.tls.plaintext_ingest: allow).")
			return
		}
		_, _, basic := r.BasicAuth()
		_, err1 := r.Cookie(sessionCookie)
		_, err2 := r.Cookie(secureSessionCookie)
		hasSession := err1 == nil || err2 == nil
		switch {
		case basic || route == "POST /api/login":
			plainRefusal(w, r, http.StatusForbidden, "Signalith only accepts passwords over HTTPS, so this was refused. Use "+target+" instead.")
		case hasSession && strings.HasPrefix(r.URL.Path, "/api/"):
			plainRefusal(w, r, http.StatusForbidden, "Signalith only accepts sessions over HTTPS, so this was refused. Use "+target+" instead.")
		case r.Method == http.MethodGet || r.Method == http.MethodHead:
			if hasSession {
				// A session cookie from when this server spoke plain HTTP:
				// it is no use now, so the browser forgets it.
				http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			}
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
		default:
			plainRefusal(w, r, http.StatusForbidden, "Signalith only answers this over HTTPS. Use "+target+" instead.")
		}
	})
}

// plainRefusal answers a plain-HTTP request that must use HTTPS, as JSON
// for the API and as text otherwise.
func plainRefusal(w http.ResponseWriter, r *http.Request, status int, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeError(w, status, errors.New(msg))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg + "\n"))
}

// httpsBase is https:// and the host and port the client asked for, the
// same port serving HTTPS; or public_url's when the Host header is not a
// usable host and port.
func (s *Server) httpsBase(r *http.Request) string {
	if host := r.Host; validHostHeader(host) {
		if _, _, err := net.SplitHostPort(host); err != nil {
			// No port: the client used port 80, which serves HTTPS now,
			// and https:// alone would mean 443.
			host = net.JoinHostPort(host, "80")
		}
		return "https://" + host
	}
	if u, err := url.Parse(s.conf().Server.PublicURL); err == nil && u.Host != "" {
		return "https://" + u.Host
	}
	return "https://localhost"
}

// httpsURL is the address of the request over HTTPS.
func (s *Server) httpsURL(r *http.Request) string {
	return s.httpsBase(r) + r.URL.RequestURI()
}

// validHostHeader accepts host or host:port made of the characters host
// names and IP addresses use, so a redirect cannot be bent elsewhere.
func validHostHeader(h string) bool {
	if h == "" || len(h) > 300 {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-_:[]", c)) {
			return false
		}
	}
	host := h
	if strings.Count(h, ":") > 1 && !strings.HasPrefix(h, "[") {
		return false // an IPv6 address needs brackets
	}
	if strings.HasPrefix(h, "[") || strings.Count(h, ":") == 1 {
		hh, port, err := net.SplitHostPort(h)
		if err != nil || port == "" {
			return false
		}
		host = hh
	}
	return host != ""
}
