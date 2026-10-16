package okta

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/jrsamsanchez/signalith/internal/intel"
)

// An Okta organization is on the internet, so the poller only connects to
// public addresses: a domain that leads to this machine, the local
// network or a cloud metadata service is refused after DNS, so the
// domain setting cannot be used to reach services inside the network.

var (
	sharedSpace = netip.MustParsePrefix("100.64.0.0/10") // carrier-grade NAT
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
)

// checkPublic reports whether the poller may connect to ip.
func checkPublic(ip netip.Addr) error {
	ip = ip.Unmap()
	if nat64Prefix.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if err := intel.CheckAddr(ip, false); err != nil {
		return fmt.Errorf("Signalith does not connect to %s for Okta: it is not an internet address", ip.WithZone(""))
	}
	if ip.IsPrivate() || sharedSpace.Contains(ip) || !ip.IsGlobalUnicast() {
		return fmt.Errorf("Signalith does not connect to %s for Okta: it is a private network address, not Okta", ip.WithZone(""))
	}
	return nil
}

// publicDialer connects only to public addresses, except to the proxy
// the environment names: the proxy makes the real connection, and a
// proxy on the local network is a normal setup.
type publicDialer struct {
	plain *net.Dialer
	proxy func(*http.Request) (*url.URL, error)
}

func (d *publicDialer) isProxy(addr string) bool {
	u, err := d.proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "okta.invalid"}})
	if err != nil || u == nil {
		return false
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443", "socks5": "1080"}[strings.ToLower(u.Scheme)]
	}
	return strings.EqualFold(net.JoinHostPort(u.Hostname(), port), addr)
}

func (d *publicDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.isProxy(addr) {
		return d.plain.DialContext(ctx, network, addr)
	}
	checked := *d.plain
	checked.Control = func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("unexpected address %q", address)
		}
		return checkPublic(ap.Addr())
	}
	return checked.DialContext(ctx, network, addr)
}

func newPublicDialer() *publicDialer {
	return &publicDialer{
		plain: &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second},
		proxy: http.ProxyFromEnvironment,
	}
}
