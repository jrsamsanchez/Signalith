package intel

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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jrsamsanchez/signalith/internal/redact"
)

// Feed downloads may only reach the internet and the local network. The
// server checks every address it connects to, after DNS and on every
// redirect, so a feed URL cannot be used to read cloud metadata services
// or services on the Signalith machine itself.

// MaxRedirects is how many redirects a download follows.
const MaxRedirects = 5

// BlockedError says a feed address is not allowed.
type BlockedError struct {
	Addr     string
	Why      string
	Loopback bool // allowed with intel.allow_loopback_feeds
}

func (e *BlockedError) Error() string {
	msg := fmt.Sprintf("Signalith does not download feeds from %s, %s.", e.Addr, e.Why)
	if e.Loopback {
		msg += " To use a feed server on this machine, set intel.allow_loopback_feeds: true in signalith.yaml."
	}
	return msg
}

var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	nat64       = netip.MustParsePrefix("64:ff9b::/96")
	// Cloud metadata services outside the link-local ranges.
	metadataAddrs = []netip.Addr{
		netip.MustParseAddr("fd00:ec2::254"),   // AWS over IPv6
		netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
	}
)

// CheckAddr reports whether a feed download may connect to ip.
func CheckAddr(ip netip.Addr, allowLoopback bool) error {
	ip = ip.Unmap()
	if nat64.Contains(ip) {
		// 64:ff9b::a.b.c.d reaches the IPv4 address a.b.c.d.
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	addr := ip.WithZone("").String()
	switch {
	case ip.IsLoopback():
		if allowLoopback {
			return nil
		}
		return &BlockedError{Addr: addr, Why: "a loopback address on this machine", Loopback: true}
	case ip.IsUnspecified() || (ip.Is4() && thisNetwork.Contains(ip)):
		return &BlockedError{Addr: addr, Why: "an unspecified address"}
	case ip.IsLinkLocalUnicast():
		return &BlockedError{Addr: addr, Why: "a link-local address, such as a cloud metadata service"}
	case ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return &BlockedError{Addr: addr, Why: "a multicast or broadcast address"}
	}
	for _, m := range metadataAddrs {
		if ip == m {
			return &BlockedError{Addr: addr, Why: "a cloud metadata service"}
		}
	}
	return nil
}

// checkHost checks a URL's host when it is an IP address, and refuses the
// protected addresses by name, so they are refused even when a proxy
// makes the connection.
func checkHost(u *url.URL, allowLoopback bool, protected []string) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return plain("Feeds can only be downloaded over http or https.")
	}
	if p := protectedAddr(u, protected); p != "" {
		return protectedError(p)
	}
	if ip, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil {
		return CheckAddr(ip, allowLoopback)
	}
	return nil
}

// hostPort returns a URL's lowercase host:port, with the scheme's default
// port when it has none, the way the HTTP transport dials it.
func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}[strings.ToLower(u.Scheme)]
	}
	return strings.ToLower(net.JoinHostPort(strings.TrimSuffix(u.Hostname(), "."), port))
}

// protectedAddr returns the protected host:port a URL names, or "".
func protectedAddr(u *url.URL, protected []string) string {
	hp := hostPort(u)
	for _, p := range protected {
		if strings.EqualFold(p, hp) {
			return p
		}
	}
	return ""
}

func protectedError(addr string) error {
	return &BlockedError{Addr: addr, Why: "the OpenSearch database Signalith keeps its data in"}
}

// ProtectedAddr returns the host:port of a service URL that feeds must
// never reach, such as Signalith's own OpenSearch, or "" if it has none.
func ProtectedAddr(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return hostPort(u)
}

// dialTrack records the proxy the transport chose for a download's
// current request (see newFeedClientWith), so the dialer leaves only
// that connection unchecked.
type dialTrack struct {
	mu    sync.Mutex
	proxy string // host:port, or "" for a direct connection
}

type dialTrackKey struct{}

func (t *dialTrack) set(p string) {
	t.mu.Lock()
	t.proxy = p
	t.mu.Unlock()
}

func (t *dialTrack) isProxy(addr string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.proxy != "" && strings.EqualFold(t.proxy, addr)
}

// safeDialer connects only to allowed addresses. A connection to the proxy
// the transport chose for the request is not checked: the proxy makes the
// real connection, and pointing HTTPS_PROXY at a proxy on this machine is
// a normal setup. A download to that same address without the proxy, such
// as http://localhost:3128/ (which Go never sends through a proxy), is
// checked like any other.
type safeDialer struct {
	allowLoopback bool
	protected     []string
	plain         *net.Dialer
	resolver      *net.Resolver
}

func newSafeDialer(allowLoopback bool, protected []string) *safeDialer {
	return &safeDialer{
		allowLoopback: allowLoopback,
		protected:     protected,
		plain:         &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second},
		resolver:      net.DefaultResolver,
	}
}

func (d *safeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if t, ok := ctx.Value(dialTrackKey{}).(*dialTrack); ok && t.isProxy(addr) {
		return d.plain.DialContext(ctx, network, addr)
	}
	// The protected services' addresses on this port, looked up now so a
	// name that leads to them is refused too.
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
		if ips, err := d.resolver.LookupNetIP(ctx, "ip", host); err == nil {
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

// newFeedClient returns the HTTP client feeds download with. It uses the
// proxy from HTTPS_PROXY, HTTP_PROXY and NO_PROXY, refuses blocked and
// protected addresses at connect time, and follows at most MaxRedirects
// redirects. Timeouts come from each request's context.
func newFeedClient(allowLoopback bool, protected []string) *http.Client {
	return newFeedClientWith(allowLoopback, protected, http.ProxyFromEnvironment)
}

// NewDownloadClient returns an HTTP client with the rules of feed
// downloads, for other files Signalith downloads from an address an
// admin can set, such as the behavior baselines' IP database.
func NewDownloadClient(allowLoopback bool, protected []string) *http.Client {
	return newFeedClientWith(allowLoopback, protected, http.ProxyFromEnvironment)
}

func newFeedClientWith(allowLoopback bool, protected []string, proxy func(*http.Request) (*url.URL, error)) *http.Client {
	d := newSafeDialer(allowLoopback, protected)
	tr := &http.Transport{
		// Record the proxy chosen for each request (redirects included),
		// so the dialer knows which connection is the proxy's.
		Proxy: func(req *http.Request) (*url.URL, error) {
			u, err := proxy(req)
			if t, ok := req.Context().Value(dialTrackKey{}).(*dialTrack); ok {
				p := ""
				if err == nil && u != nil {
					p = hostPort(u)
				}
				t.set(p)
			}
			return u, err
		},
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return checkRedirect(req, via, allowLoopback, protected)
	}}
}

// checkRedirect limits redirects and checks the new address. It never
// sends a Referer (the feed URL's query may hold a key), and it drops the
// feed's secret headers and its sign-in (Authorization) unless the
// redirect stays on the original server, or only moves it from http to
// https.
func checkRedirect(req *http.Request, via []*http.Request, allowLoopback bool, protected []string) error {
	if len(via) >= MaxRedirects {
		return errTooManyRedirects
	}
	if err := checkHost(req.URL, allowLoopback, protected); err != nil {
		return err
	}
	req.Header.Del("Referer")
	if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
		req.Header.Del("Authorization")
		if names, ok := req.Context().Value(secretHeadersKey{}).([]string); ok {
			for _, n := range names {
				req.Header.Del(n)
			}
		}
	}
	return nil
}

// sameOrigin reports whether a redirect from a to b stays on the same
// server: the same host and port, and the same scheme or http to https.
func sameOrigin(a, b *url.URL) bool {
	if !strings.EqualFold(strings.TrimSuffix(a.Hostname(), "."), strings.TrimSuffix(b.Hostname(), ".")) {
		return false
	}
	as, bs := strings.ToLower(a.Scheme), strings.ToLower(b.Scheme)
	if as == bs {
		return hostPort(a) == hostPort(b)
	}
	// An upgrade to https on the default ports keeps the secrets; a
	// downgrade to http never does.
	return as == "http" && bs == "https" && (a.Port() == "" || a.Port() == "80") && (b.Port() == "" || b.Port() == "443")
}

var errTooManyRedirects = fmt.Errorf("the server redirected more than %d times", MaxRedirects)

// secretHeadersKey marks the request headers that hold secrets.
type secretHeadersKey struct{}

// plainError is a message already written for people.
type plainError struct{ msg string }

func (e *plainError) Error() string { return e.msg }

func plain(format string, args ...any) error { return &plainError{fmt.Sprintf(format, args...)} }

// HTTPError is a download the server answered with an error status.
type HTTPError struct {
	Code   int
	Status string
	// Said is a short message from the server's response, if it sent one.
	Said string
}

func (e *HTTPError) Error() string { return "the server answered " + e.Status }

// describe turns a download error into plain words that never include
// the URL (whose query may hold a key) or a secret value.
func describe(err error, fd Feed, timeout time.Duration) string {
	msg := describeErr(err, fd, timeout)
	return scrub(msg, fd)
}

func describeErr(err error, fd Feed, timeout time.Duration) string {
	var pe *plainError
	if errors.As(err, &pe) {
		return pe.msg
	}
	var tb *TooBigError
	if errors.As(err, &tb) {
		return tb.Error()
	}
	var he *HTTPError
	if errors.As(err, &he) {
		return describeStatus(he, fd)
	}
	var be *BlockedError
	if errors.As(err, &be) {
		return be.Error()
	}
	if errors.Is(err, errTooManyRedirects) {
		return "The server redirected more than 5 times. Check the URL."
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("The server did not answer within %s. Check that this Signalith server can reach it: firewalls must allow outbound HTTPS, and a proxy is set with HTTPS_PROXY.", fmtWait(timeout))
	}
	if errors.Is(err, context.Canceled) {
		return "The download was canceled."
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return fmt.Sprintf("Could not find the server %s. Check the URL, and that this Signalith server can look up internet names (DNS).", dnsErr.Name)
		}
		return fmt.Sprintf("Could not look up the server %s (DNS). Check this Signalith server's network settings.", dnsErr.Name)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "The server did not answer in time. Check that this Signalith server can reach it: firewalls must allow outbound HTTPS, and a proxy is set with HTTPS_PROXY."
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "The server refused the connection. Check the URL and port."
	}
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var rh tls.RecordHeaderError
	switch {
	case errors.As(err, &ua):
		return "The server's HTTPS certificate is not from a trusted authority. If your network inspects HTTPS, add its certificate to this server's trusted certificates."
	case errors.As(err, &hn):
		return "The server's HTTPS certificate is for another name. Check the URL."
	case errors.As(err, &ci):
		return "The server's HTTPS certificate is not valid (" + ci.Error() + ")."
	case errors.As(err, &rh):
		return "The server did not answer with HTTPS. Check whether the URL should start with http:// instead."
	}
	// Drop the URL the HTTP client puts in its errors.
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return "Download failed: " + err.Error()
}

func describeStatus(he *HTTPError, fd Feed) string {
	creds := len(fd.Headers) > 0 || fd.Username != ""
	msg := "The server answered " + he.Status + "."
	switch {
	case he.Code == http.StatusUnauthorized || he.Code == http.StatusForbidden:
		switch {
		case creds:
			msg += " Check that the API key or password is right and allowed to read this feed."
		case fd.Kind == KindTAXII:
			msg += " This server needs you to sign in: enter a user name and password, or an API key."
		default:
			msg += " This feed may need an API key."
		}
	case he.Code == http.StatusNotFound:
		if fd.Kind == KindTAXII {
			msg += " Check the API root URL and the collection ID."
		} else {
			msg += " Check the URL."
		}
	case he.Code == http.StatusTooManyRequests:
		msg += " The server limits how often it can be downloaded; use a longer interval."
	case he.Code == http.StatusNotAcceptable && fd.Kind == KindTAXII:
		msg += " The server may not support TAXII 2.1."
	case he.Code >= 500:
		msg += " The feed's server has a problem; try again later."
	}
	// Skip a message that only repeats the status, such as "Unauthorized"
	// or "404 page not found".
	if he.Said != "" && !onlyStatus(he.Said, he.Code) {
		msg += fmt.Sprintf(" It said: %q", he.Said)
	}
	return msg
}

// onlyStatus reports whether a server's message says no more than its
// status: the code, the status text, and filler words.
func onlyStatus(said string, code int) bool {
	allowed := map[string]bool{"page": true, "error": true, "http": true, "status": true, "the": true, "is": true, "was": true}
	for _, w := range strings.Fields(strings.ToLower(http.StatusText(code))) {
		allowed[w] = true
	}
	words := strings.FieldsFunc(strings.ToLower(said), func(r rune) bool { return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') })
	for _, w := range words {
		if w != strconv.Itoa(code) && !allowed[w] {
			return false
		}
	}
	return true
}

func fmtWait(d time.Duration) string {
	if d <= 0 {
		return "the time allowed"
	}
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d == time.Minute {
		return "a minute"
	}
	return fmt.Sprintf("%d minutes", int(d.Minutes()))
}

// secretValues returns a feed's secret values, as sent.
func secretValues(fd Feed) []string {
	var out []string
	for _, v := range fd.Headers {
		out = append(out, v, fd.expand(v))
	}
	if fd.Password != "" {
		out = append(out, fd.Password, fd.expand(fd.Password))
	}
	return out
}

// scrub hides a feed's secret values in a message.
func scrub(msg string, fd Feed) string {
	for _, s := range secretValues(fd) {
		if len(s) >= 4 {
			msg = strings.ReplaceAll(msg, s, "[hidden]")
		}
	}
	return msg
}

// RedactURL returns a URL safe to log: without a user name or password,
// and with the query (which may hold an API key) replaced by "…".
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// Unparsable text may still hold a password before the host, as
		// in "https://user:pa ss@host/": keep only the scheme and host.
		if i := strings.IndexAny(raw, "?#"); i >= 0 {
			return redact.URL(raw[:i]) + "?…"
		}
		return redact.URL(raw)
	}
	u.User = nil
	if u.RawQuery != "" || u.ForceQuery {
		u.RawQuery, u.ForceQuery = "", false
		u.Fragment, u.RawFragment = "", ""
		return u.String() + "?…"
	}
	return u.String()
}
