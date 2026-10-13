package notify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jrsamsanchez/signalith/internal/intel"
)

// Channels may reach the internet and the local network: firewalls, SOAR
// tools and mail relays live there. The server checks every address it
// connects to, after DNS, so a channel cannot be used to reach cloud
// metadata services, or services on the Signalith machine itself unless
// the channel allows it (Channel.AllowLoopback). The rules are those of
// threat intel feed downloads (intel.CheckAddr).

// SendTimeout bounds one message: connecting, sending and the answer.
const SendTimeout = 10 * time.Second

// MailTimeout bounds one email, which takes a few round trips more.
const MailTimeout = 30 * time.Second

// maxAnswer is how much of a receiver's answer is read.
const maxAnswer = 64 << 10

// BlockedError says a channel's address is not allowed.
type BlockedError struct {
	Addr     string
	Why      string
	Loopback bool // allowed with Channel.AllowLoopback
}

func (e *BlockedError) Error() string {
	msg := fmt.Sprintf("Signalith does not send notifications to %s, %s.", e.Addr, e.Why)
	if e.Loopback {
		msg += " To send to a receiver on this machine, tick \"Allow this server's own addresses\" on the channel."
	}
	return msg
}

// CheckAddr reports whether a channel may connect to ip.
func CheckAddr(ip netip.Addr, allowLoopback bool) error {
	err := intel.CheckAddr(ip, allowLoopback)
	var be *intel.BlockedError
	if errors.As(err, &be) {
		return &BlockedError{Addr: be.Addr, Why: be.Why, Loopback: be.Loopback}
	}
	return err
}

// Protected names a service channels must never reach, such as the
// OpenSearch Signalith keeps its data in, as host:port.
type Protected []string

func protectedError(addr string) error {
	return &BlockedError{Addr: addr, Why: "the OpenSearch database Signalith keeps its data in"}
}

// check refuses a URL whose host:port is protected, or whose host is an
// address channels may not reach.
func (p Protected) check(u *url.URL, allowLoopback bool) error {
	hp := hostPort(u)
	for _, x := range p {
		if strings.EqualFold(x, hp) {
			return protectedError(x)
		}
	}
	if ip, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil {
		return CheckAddr(ip, allowLoopback)
	}
	if isLocalhost(u.Hostname()) && !allowLoopback {
		return &BlockedError{Addr: u.Hostname(), Why: "this machine", Loopback: true}
	}
	return nil
}

// dialer connects only to allowed addresses. A connection to the proxy
// the transport chose for a request is not checked: the proxy makes the
// real connection, and the request's URL was checked before it was sent.
type dialer struct {
	allowLoopback bool
	protected     Protected
	plain         *net.Dialer
	// proxy is the host:port of the proxy of the request being sent, or
	// "" for a direct connection.
	mu    sync.Mutex
	proxy string
}

func newDialer(allowLoopback bool, protected Protected) *dialer {
	return &dialer{allowLoopback: allowLoopback, protected: protected, plain: &net.Dialer{Timeout: SendTimeout, KeepAlive: 30 * time.Second}}
}

func (d *dialer) setProxy(p string) {
	d.mu.Lock()
	d.proxy = p
	d.mu.Unlock()
}

func (d *dialer) isProxy(addr string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.proxy != "" && strings.EqualFold(d.proxy, addr)
}

// DialContext connects to addr when it, after DNS, is an address the
// channel may reach.
func (d *dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.isProxy(addr) {
		return d.plain.DialContext(ctx, network, addr)
	}
	_, port, _ := net.SplitHostPort(addr)
	var deny []netip.Addr
	for _, p := range d.protected {
		host, pport, err := net.SplitHostPort(p)
		if err != nil || pport != port {
			continue
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			deny = append(deny, ip.Unmap())
			continue
		}
		if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host); err == nil {
			for _, ip := range ips {
				deny = append(deny, ip.Unmap())
			}
		}
	}
	checked := *d.plain
	checked.Control = func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("unexpected address %q", address)
		}
		if slices.Contains(deny, ap.Addr().Unmap()) {
			return protectedError(addr)
		}
		return CheckAddr(ap.Addr(), d.allowLoopback)
	}
	return checked.DialContext(ctx, network, addr)
}

// tlsConfig returns the TLS settings of a channel: certificates are
// always checked, against the system's authorities and the channel's
// own (Channel.CAPEM).
func tlsConfig(c Channel, serverName string) (*tls.Config, error) {
	conf := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if c.CAPEM == "" {
		return conf, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(c.CAPEM)) {
		return nil, errors.New("the channel's certificate authority is not a PEM certificate")
	}
	conf.RootCAs = pool
	return conf, nil
}

// httpClient returns the client a channel posts with: one request at a
// time, SendTimeout in all, the proxy from HTTPS_PROXY, HTTP_PROXY and
// NO_PROXY, only allowed addresses, and no redirect to another server.
// Each message gets a client of its own, so a channel's settings apply at
// once.
func httpClient(c Channel, protected Protected) (*http.Client, error) {
	conf, err := tlsConfig(c, "")
	if err != nil {
		return nil, err
	}
	d := newDialer(c.AllowLoopback, protected)
	tr := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			u, err := http.ProxyFromEnvironment(req)
			p := ""
			if err == nil && u != nil {
				p = hostPort(u)
			}
			d.setProxy(p)
			return u, err
		},
		DialContext:           d.DialContext,
		TLSClientConfig:       conf,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1,
		IdleConnTimeout:       time.Second,
		TLSHandshakeTimeout:   SendTimeout,
		ResponseHeaderTimeout: SendTimeout,
		DisableKeepAlives:     true,
	}
	return &http.Client{Transport: tr, Timeout: SendTimeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errRedirect
		}
		if !sameServer(via[0].URL.String(), req.URL.String()) {
			return errRedirect
		}
		return protected.check(req.URL, c.AllowLoopback)
	}}, nil
}

var errRedirect = errors.New("the receiver redirected to another address; Signalith only follows redirects on the same server. Check the URL")
