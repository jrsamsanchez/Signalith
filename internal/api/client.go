package api

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/clientaddr"
)

// clientInfo is who a request comes from, for the sign-in limits and the
// audit log.
type clientInfo struct {
	// Peer is the address of the connection's other end.
	Peer netip.Addr
	// Addr is the client: the address a trusted reverse proxy forwarded
	// the request for, or else Peer.
	Addr netip.Addr
	// Proxied is set when Peer is a trusted reverse proxy that named the
	// client.
	Proxied bool
	// Unnamed is what a trusted reverse proxy sent in the client address
	// header that named no client Signalith can use, for the log.
	Unnamed string
	// Shared is set when Addr stands for many people, by configuration
	// only: it is listed in server.shared_addresses, or it is a trusted
	// reverse proxy and server.client_header is empty, or the request
	// came from one without that header. Nothing a client sends makes it
	// shared.
	Shared bool
	// raw is RemoteAddr when it is not an IP address.
	raw string
}

// String is the client's address for the log.
func (c clientInfo) String() string {
	if c.Addr.IsValid() {
		return c.Addr.String()
	}
	return c.raw
}

// key is what the sign-in limits count the client under: its IPv4
// address, or its IPv6 /64 network, since an IPv6 host can usually pick
// any address in its /64 and would otherwise get a fresh allowance of
// guesses with each one.
func (c clientInfo) key() string {
	if c.Addr.IsValid() {
		return clientaddr.Key(c.Addr).String()
	}
	return c.raw
}

// logAttrs are the log fields that say where a request came from: client,
// and peer (the reverse proxy) when a trusted proxy named the client, or
// forwarded when it sent something Signalith could not use.
func (c clientInfo) logAttrs() []any {
	attrs := []any{"client", c.String()}
	if c.Proxied {
		attrs = append(attrs, "peer", c.Peer.String())
	}
	if c.Unnamed != "" {
		attrs = append(attrs, "forwarded", c.Unnamed)
	}
	return attrs
}

// client works out who a request comes from. The client address header
// (server.client_header: X-Forwarded-For or Forwarded) is read only when
// the connection comes from a reverse proxy listed in
// server.trusted_proxies, since anyone else can send it, and only that one
// header: a proxy writes one and passes the other on from the client
// unchanged. The client is the right-most address in it that is not a
// trusted proxy: each proxy adds the address it got the request from on
// the right, so that one was written by a proxy Signalith trusts, while
// those to its left may have come from the client itself.
//
// Without server.client_header, or when a trusted proxy sends no such
// header (a request it did not forward, or a proxy that does not set
// it), the proxy stands for everyone behind it and counts as shared:
// nobody can lock the others out through it.
func (s *Server) client(r *http.Request) clientInfo {
	srv := s.conf().Server
	c := clientInfo{Peer: clientaddr.Parse(r.RemoteAddr)}
	c.Addr = c.Peer
	if !c.Peer.IsValid() {
		c.raw = r.RemoteAddr
		return c
	}
	if trusted := srv.TrustedProxyList(); inPrefixes(c.Peer, trusted) {
		name := srv.ClientAddressHeader()
		values := r.Header.Values(name)
		if name == "" || len(values) == 0 {
			c.Shared = true
		} else {
			var entries []string
			if name == "Forwarded" {
				entries = forwardedFor(values)
			} else {
				entries = splitXFF(values)
			}
			a, ok := rightmostUntrusted(entries, trusted)
			if a.IsValid() {
				c.Addr, c.Proxied = a, true
			}
			if !ok {
				c.Unnamed = logForwarded(name, values)
			}
		}
	}
	if !c.Shared && inPrefixes(c.Addr, srv.SharedList()) {
		c.Shared = true
	}
	return c
}

func inPrefixes(a netip.Addr, list []netip.Prefix) bool {
	a = a.Unmap().WithZone("")
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// maxForwardedLog bounds how much of a forwarding header is logged.
const maxForwardedLog = 200

// logForwarded is what a client address header held, for the log.
func logForwarded(name string, values []string) string {
	sent := name + ": " + strings.Join(values, ", ")
	if len(sent) > maxForwardedLog {
		sent = strings.ToValidUTF8(sent[:maxForwardedLog], "") + "…"
	}
	return sent
}

// rightmostUntrusted returns the right-most entry that is not a trusted
// proxy, and true. Otherwise, when it meets an entry that is not an
// address (such as "unknown") or runs out of entries, it returns the last
// address it passed, which is a trusted proxy that got the request from
// there, and false; or no address and false when there was none.
func rightmostUntrusted(entries []string, trusted []netip.Prefix) (netip.Addr, bool) {
	var last netip.Addr
	for i := len(entries) - 1; i >= 0; i-- {
		a, ok := parseForwardedAddr(entries[i])
		if !ok {
			return last, false
		}
		if !inPrefixes(a, trusted) {
			return a, true
		}
		last = a
	}
	return last, false
}

// splitXFF splits X-Forwarded-For header lines into their entries, in
// order; several lines are one list.
func splitXFF(values []string) []string {
	var out []string
	for _, v := range values {
		for _, e := range strings.Split(v, ",") {
			if e = strings.TrimSpace(e); e != "" {
				out = append(out, e)
			}
		}
	}
	return out
}

// forwardedFor returns the for= value of each element of Forwarded header
// lines (RFC 7239), in order; "" for an element without one.
func forwardedFor(values []string) []string {
	var out []string
	for _, v := range values {
		for _, elem := range splitQuoted(v, ',') {
			if strings.TrimSpace(elem) == "" {
				continue
			}
			found := ""
			for _, pair := range splitQuoted(elem, ';') {
				k, val, ok := strings.Cut(strings.TrimSpace(pair), "=")
				if ok && strings.EqualFold(strings.TrimSpace(k), "for") {
					found = unquote(strings.TrimSpace(val))
				}
			}
			out = append(out, found)
		}
	}
	return out
}

// splitQuoted splits s at sep outside double-quoted strings.
func splitQuoted(s string, sep byte) []string {
	var out []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && quoted:
			i++
		case c == '"':
			quoted = !quoted
		case c == sep && !quoted:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// unquote removes the double quotes around a quoted string and its
// backslash escapes.
func unquote(s string) string {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	s = s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseForwardedAddr reads one forwarded address: 192.0.2.1,
// 192.0.2.1:4711, 2001:db8::1, [2001:db8::1] or [2001:db8::1]:4711.
// Names such as "unknown" or "_hidden" are not addresses.
func parseForwardedAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().WithZone(""), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if a, err := netip.ParseAddr(s[1 : len(s)-1]); err == nil {
			return a.Unmap().WithZone(""), true
		}
	}
	return netip.Addr{}, false
}
