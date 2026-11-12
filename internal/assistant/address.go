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
	"sync"
	"syscall"
	"time"
)

// The model's address is set by an admin, and Test and the model list
// reach it with values from a form that is not saved yet, so the server
// itself makes the requests. These checks keep that from being a way to
// reach what no model server is: cloud metadata services and other
// link-local addresses.

// blockedPrefixes are address ranges no model server uses: link-local
// (where cloud metadata services answer, such as 169.254.169.254), AWS's
// IPv6 metadata range, Google Cloud's IPv6 metadata address and Alibaba
// Cloud's metadata address.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fd00:ec2::/32"),
	netip.MustParsePrefix("fd20:ce::254/128"),
	netip.MustParsePrefix("100.100.100.200/32"),
}

// metadataNames are host names of cloud metadata services, refused when
// a proxy is used and this server cannot resolve them itself.
var metadataNames = []string{"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal"}

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

// Insecure reports whether raw is plain http to a public IP address,
// which is refused unless allowed. Plain http to this computer or to a
// private address (RFC 1918, or an IPv6 unique local address in fd00::/8)
// is the usual way to reach a model on your own hardware, and only warned
// about (PlainRemote). A name (ollama, ollama.lan,
// gpu01.corp.example, ollama.svc.cluster.local) cannot be judged from the
// address: the model client decides on the address it resolves to, each
// time it connects (LocalOnly), and refuses a public one.
func Insecure(raw string) bool {
	if !PlainRemote(raw) {
		return false
	}
	u, _ := neturl.Parse(strings.TrimSpace(raw))
	h := strings.TrimSuffix(u.Hostname(), ".")
	if a, err := netip.ParseAddr(h); err == nil {
		return !localAddr(a)
	}
	return false
}

// PlainName reports whether raw is plain http to a name other than
// localhost, which the model client allows only while it resolves to
// this computer or a private address.
func PlainName(raw string) bool {
	if !PlainRemote(raw) {
		return false
	}
	u, _ := neturl.Parse(strings.TrimSpace(raw))
	_, err := netip.ParseAddr(strings.TrimSuffix(u.Hostname(), "."))
	return err != nil
}

// localAddr reports whether a is this computer or a private address,
// where plain http to a model is allowed.
func localAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate()
}

// ErrPlainPublic refuses plain http to a model at a public address.
var ErrPlainPublic = errors.New("is a public address, and the AI model's address is plain http: questions, events and the model's answers " +
	"would cross the internet unencrypted. Use https://, or, to accept the risk, turn on Allow plain http (assistant.allow_insecure_http)")

// plainPublic is ErrPlainPublic for host.
func plainPublic(host string) error { return fmt.Errorf("%s %w", host, ErrPlainPublic) }

// refuseBlocked stops a connection to a blocked address, whatever name
// resolved to it, and with localOnly one to an address that is not this
// computer or a private one.
func refuseBlocked(localOnly bool) func(_, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		a, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("unexpected address %q", address)
		}
		if Blocked(a) {
			return fmt.Errorf("%s is a link-local or cloud metadata address, which no model server uses", host)
		}
		if localOnly && !localAddr(a) {
			return plainPublic(host)
		}
		return nil
	}
}

// transport is the model client's transport: Go's default, with
// connections to blocked addresses refused, and with localOnly (a plain
// http model address, AI-02) connections to anything but this computer
// and private addresses, as resolved when connecting. Through a proxy
// (HTTPS_PROXY, HTTP_PROXY and NO_PROXY, see docs/outbound.md) the
// connection is to the proxy, so the model's host is resolved and checked
// before the proxy is used (AI-03).
func transport(localOnly bool) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: refuseBlocked(localOnly)}
	// The proxy itself may be anywhere: checkedProxy checked the model's
	// host before it was used.
	toProxy := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: refuseBlocked(false)}
	var mu sync.Mutex
	proxies := map[string]bool{}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		viaProxy := proxies[strings.ToLower(addr)]
		mu.Unlock()
		if viaProxy {
			return toProxy.DialContext(ctx, network, addr)
		}
		return d.DialContext(ctx, network, addr)
	}
	check := checkedProxy(http.ProxyFromEnvironment, net.DefaultResolver.LookupNetIP, localOnly)
	t.Proxy = func(req *http.Request) (*neturl.URL, error) {
		u, err := check(req)
		if err == nil && u != nil {
			mu.Lock()
			proxies[strings.ToLower(proxyHostPort(u))] = true
			mu.Unlock()
		}
		return u, err
	}
	return t
}

// proxyHostPort is the host:port a proxy URL is dialed at.
func proxyHostPort(u *neturl.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// checkedProxy returns a Proxy function that uses the proxy from proxy
// only once the request's host is not a blocked address, as written or
// as resolved with lookup. A name this server cannot resolve (only the
// proxy can, say) passes, unless it is a cloud metadata service's name.
// With localOnly the host must be this computer or a private address,
// and a name this server cannot resolve is refused.
func checkedProxy(proxy func(*http.Request) (*neturl.URL, error),
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error), localOnly bool) func(*http.Request) (*neturl.URL, error) {
	return func(req *http.Request) (*neturl.URL, error) {
		u, err := proxy(req)
		if err != nil || u == nil {
			return u, err
		}
		host := strings.TrimSuffix(strings.ToLower(req.URL.Hostname()), ".")
		blocked := fmt.Errorf("%s is a link-local or cloud metadata address, which no model server uses", host)
		if a, err := netip.ParseAddr(host); err == nil {
			if Blocked(a) {
				return nil, blocked
			}
			if localOnly && !localAddr(a) {
				return nil, plainPublic(host)
			}
			return u, nil
		}
		ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
		defer cancel()
		addrs, err := lookup(ctx, "ip", host)
		if err != nil {
			for _, n := range metadataNames {
				if host == n {
					return nil, blocked
				}
			}
			if localOnly {
				return nil, fmt.Errorf("%s could not be looked up here, so it cannot be told whether it is on your network; "+
					"the AI model's address is plain http, which is allowed only to this computer and private addresses: %w", host, err)
			}
			return u, nil
		}
		for _, a := range addrs {
			if Blocked(a) {
				return nil, blocked
			}
			if localOnly && !localAddr(a) {
				return nil, plainPublic(host + " (" + a.String() + ")")
			}
		}
		return u, nil
	}
}
