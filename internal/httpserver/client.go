// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package httpserver

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/clientaddr"
)

// requestClient is the address a request is counted under: the client
// that a trusted proxy names in its header (ClientProxies), or else the
// connection's own peer. The rules are those of the API's sign-in limits and audit
// log: the header is read only from a trusted proxy, and the client is
// the right-most address in it that is not a trusted proxy, since each
// proxy adds the address it got the request from on the right and the
// entries to its left may have come from the client itself. A header
// with nothing usable leaves the proxy, which stays exempt when it is on
// this machine or Shared.
func (l Limits) requestClient(r *http.Request) netip.Addr {
	peer := clientaddr.Parse(r.RemoteAddr)
	if l.ClientProxies == nil || !peer.IsValid() {
		return peer
	}
	trusted, header := l.ClientProxies()
	if header == "" || !inPrefixes(peer, trusted) {
		return peer
	}
	values := r.Header.Values(header)
	if len(values) == 0 {
		return peer
	}
	var entries []string
	for _, v := range values {
		for _, e := range strings.Split(v, ",") {
			if strings.TrimSpace(e) == "" {
				continue
			}
			if strings.EqualFold(header, "Forwarded") {
				// An element without for= is no address: it stops the
				// search below, as an unknown entry does.
				e = forwardedFor(e)
			}
			entries = append(entries, strings.TrimSpace(e))
		}
	}
	for i := len(entries) - 1; i >= 0; i-- {
		a, ok := parseAddr(entries[i])
		if !ok {
			break
		}
		if !inPrefixes(a, trusted) {
			return a
		}
	}
	return peer
}

// forwardedFor returns the for= value of one Forwarded element (RFC
// 7239), "" when it has none. A quoted value with a comma in it is not
// an address, so splitting the header at commas first loses nothing.
func forwardedFor(elem string) string {
	for _, pair := range strings.Split(elem, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "for") {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// parseAddr reads one forwarded address: 192.0.2.1, 192.0.2.1:4711,
// 2001:db8::1, [2001:db8::1] or [2001:db8::1]:4711.
func parseAddr(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a.Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
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
