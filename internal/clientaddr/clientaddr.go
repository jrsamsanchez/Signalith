// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package clientaddr decides which client a network address belongs to,
// for limits that give each client a share of something (connections,
// requests in progress, memory for agent batches) so that one client
// cannot take all of it.
package clientaddr

import (
	"net"
	"net/netip"
)

// IPv6Prefix is the size of the IPv6 network one client is counted by.
// An IPv6 host is usually given a whole /64 and can pick any address in
// it, so counting single addresses would give it billions of shares.
const IPv6Prefix = 64

// Key returns what a client at a is counted under: an IPv4 address as it
// is, and an IPv6 address by its /64 network. a is unmapped first, so an
// IPv4 client reaching a dual-stack listener counts as itself.
func Key(a netip.Addr) netip.Addr {
	a = a.Unmap().WithZone("")
	if a.Is6() {
		if p, err := a.Prefix(IPv6Prefix); err == nil {
			return p.Addr()
		}
	}
	return a
}

// Of returns the address of a connection's remote end, unmapped and
// without a zone; the zero Addr when it is not an IP address.
func Of(remote net.Addr) netip.Addr {
	if a, ok := remote.(*net.TCPAddr); ok {
		return a.AddrPort().Addr().Unmap().WithZone("")
	}
	if remote == nil {
		return netip.Addr{}
	}
	return Parse(remote.String())
}

// Parse returns the address in host:port text such as
// http.Request.RemoteAddr, unmapped and without a zone; the zero Addr when
// there is none.
func Parse(hostport string) netip.Addr {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	if a, err := netip.ParseAddr(hostport); err == nil {
		return a.Unmap().WithZone("")
	}
	return netip.Addr{}
}

// Shared reports whether a is not limited as one client: this machine
// (such as a reverse proxy beside Signalith), an address that is not an
// IP address, or one inside a network in shared, which the operator has
// listed as standing for many clients (a proxy, load balancer or NAT on
// another machine).
func Shared(a netip.Addr, shared []netip.Prefix) bool {
	a = a.Unmap().WithZone("")
	if !a.IsValid() || a.IsLoopback() {
		return true
	}
	for _, p := range shared {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
