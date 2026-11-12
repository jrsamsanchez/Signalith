// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	neturl "net/url"
	"strings"
	"syscall"
	"time"
)

// The model's address is set by an admin, and Test and the model list
// reach it with values from a form that is not saved yet, so the server
// itself makes the requests. These checks keep that from being a way to
// reach what no model server is: cloud metadata services and other
// link-local addresses.

// blockedPrefixes are address ranges no model server uses: link-local
// (where cloud metadata services answer, such as 169.254.169.254) and
// AWS's IPv6 metadata range.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fd00:ec2::/32"),
}

// Blocked reports whether a is an address the model is never reached at.
func Blocked(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// CheckURL refuses a model address with a query or a fragment, which
// would cut off the paths Signalith adds to it, or with a host in a
// range no model server uses (see Blocked). An empty address is the
// provider's own.
func CheckURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := neturl.Parse(raw)
	if err != nil {
		return errors.New("the address is not a URL")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "?#") {
		return errors.New("the address cannot have a ? or # part; give the model server's base address, such as http://localhost:11434/v1")
	}
	if a, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil && Blocked(a) {
		return fmt.Errorf("%s is a link-local or cloud metadata address, which no model server uses", u.Hostname())
	}
	return nil
}

// PlainRemote reports whether raw is plain http to a host other than
// this computer, where the events, the model's replies and the API key
// cross the network unencrypted and could be changed on the way.
func PlainRemote(raw string) bool {
	u, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	h := u.Hostname()
	if strings.EqualFold(h, "localhost") {
		return false
	}
	a, err := netip.ParseAddr(h)
	return err != nil || !a.Unmap().IsLoopback()
}

// Insecure reports whether raw is plain http beyond the local network:
// to a public address or a dotted name, which is refused unless allowed.
// Plain http to this computer, to a private address (RFC 1918, or an IPv6
// unique local address in fd00::/8) or to a single-label name (such as
// ollama, a Docker service or a LAN host) is the usual way to reach a
// model on your own hardware, and only warned about (PlainRemote).
func Insecure(raw string) bool {
	if !PlainRemote(raw) {
		return false
	}
	u, _ := neturl.Parse(strings.TrimSpace(raw))
	h := strings.TrimSuffix(u.Hostname(), ".")
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.Unmap()
		return !a.IsPrivate()
	}
	return strings.Contains(h, ".")
}

// refuseBlocked stops a connection to a blocked address, whatever name
// resolved to it.
func refuseBlocked(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if a, err := netip.ParseAddr(host); err == nil && Blocked(a) {
		return fmt.Errorf("%s is a link-local or cloud metadata address, which no model server uses", host)
	}
	return nil
}

// transport is the model client's transport: Go's default, with
// connections to blocked addresses refused.
func transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: refuseBlocked}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
	return t
}
