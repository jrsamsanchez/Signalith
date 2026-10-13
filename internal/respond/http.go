package respond

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/redact"
)

// HTTP actions reach firewalls and SOAR servers, which usually sit on the
// local network, so private addresses are allowed. Every address is
// checked when the connection is made, after DNS: link-local and cloud
// metadata addresses are always refused, and this server's own loopback
// addresses unless the action allows them, so an action cannot be used to
// read cloud credentials or services on the Signalith machine. Requests
// go straight to the server (no HTTPS_PROXY), follow redirects only on the
// same server, and read at most MaxResponse bytes of the answer.

// MaxResponse is how much of an answer is read.
const MaxResponse = 64 << 10

// maxRedirects is how many same-server redirects are followed.
const maxRedirects = 3

// userAgent is sent with every request.
const userAgent = "Signalith-response/1"

// newHTTPClient returns the client of one action.
func newHTTPClient(c Connector, protected []string) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CACert != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(c.CACert)) {
			return nil, errors.New("the action's CA certificate could not be read")
		}
		cfg.RootCAs = pool
	}
	d := &guardedDialer{allowLoopback: c.AllowLoopback, protected: protected}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSClientConfig:       cfg,
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   HTTPTimeout * time.Second,
		ResponseHeaderTimeout: HTTPTimeout * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: HTTPTimeout * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("the server redirected more than %d times", maxRedirects)
			}
			if origin(req.URL.String()) != origin(via[0].URL.String()) {
				return &redirectError{to: req.URL.Scheme + "://" + req.URL.Host}
			}
			return nil
		}}, nil
}

type redirectError struct{ to string }

func (e *redirectError) Error() string {
	return "the server redirected to " + e.to + "; Signalith only follows redirects on the same server. Use the final address in the action's URL"
}

// guardedDialer connects only to allowed addresses.
type guardedDialer struct {
	allowLoopback bool
	protected     []string
}

func (d *guardedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
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
	dialer := net.Dialer{Timeout: HTTPTimeout * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("unexpected address %q", address)
		}
		if slices.Contains(deny, ap.Addr().Unmap()) {
			return &blockedError{msg: fmt.Sprintf("%s is the OpenSearch database Signalith keeps its data in; actions never send to it", addr)}
		}
		if err := intel.CheckAddr(ap.Addr(), d.allowLoopback); err != nil {
			var be *intel.BlockedError
			if errors.As(err, &be) {
				msg := fmt.Sprintf("Signalith does not send response actions to %s, %s.", be.Addr, be.Why)
				if be.Loopback {
					msg += " To reach a service on this server, tick \"Allow this server's own addresses\" in the action."
				}
				return &blockedError{msg: msg}
			}
			return err
		}
		return nil
	}}
	return dialer.DialContext(ctx, network, addr)
}

type blockedError struct{ msg string }

func (e *blockedError) Error() string { return e.msg }

// buildRequest fills an action's URL and body for one run.
func buildRequest(ctx context.Context, c Connector, v Values) (*http.Request, string, error) {
	target := expandURL(c.URL, v)
	var body io.Reader
	text := ""
	if strings.TrimSpace(c.Body) != "" {
		text = expandBody(c.Body, c.BodyFormat, v)
		body = strings.NewReader(text)
	}
	req, err := http.NewRequestWithContext(ctx, c.Method, target, body)
	if err != nil {
		return nil, "", fmt.Errorf("the action's URL is not valid once filled in: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", bodyContentType[c.BodyFormat])
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.5")
	for k, val := range c.Headers {
		req.Header.Set(k, val)
	}
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	return req, text, nil
}

// runHTTP sends an action's request. A 2xx answer succeeds.
func (r *Runner) runHTTP(ctx context.Context, c Connector, v Values) result {
	ctx, cancel := context.WithTimeout(ctx, HTTPTimeout*time.Second)
	defer cancel()
	client, err := newHTTPClient(c, r.Protected)
	if err != nil {
		return result{err: err}
	}
	req, _, err := buildRequest(ctx, c, v)
	if err != nil {
		return result{err: err}
	}
	shown := redact.URL(req.URL.String())
	resp, err := client.Do(req)
	if err != nil {
		return result{summary: fmt.Sprintf("%s %s did not get an answer.", c.Method, shown), err: errors.New(describeHTTPError(err))}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	more := len(data) > MaxResponse
	if more {
		data = data[:MaxResponse]
	}
	out := resp.Status
	if len(data) > 0 {
		out += "\n\n" + string(data)
	}
	if more {
		out += "\n[… answer cut at 64 KB]"
	}
	summary := fmt.Sprintf("%s %s answered %s.", c.Method, shown, resp.Status)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := "The server answered " + resp.Status + "."
		switch {
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			msg += " Check the action's API key, user name or password, and that the account may do this."
		case resp.StatusCode == http.StatusNotFound:
			msg += " Check the action's URL."
		case resp.StatusCode >= 500:
			msg += " The server had a problem; try again, or check its logs."
		}
		return result{summary: summary, output: out, err: errors.New(msg)}
	}
	return result{summary: summary, output: out}
}

// describeHTTPError turns a request error into plain words that never
// include the URL, whose query may hold a key.
func describeHTTPError(err error) string {
	var be *blockedError
	var re *redirectError
	switch {
	case errors.As(err, &be):
		return be.msg
	case errors.As(err, &re):
		return re.Error() + "."
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("The server did not answer within %d seconds. Check the address, and that no firewall blocks this Signalith server.", HTTPTimeout)
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return fmt.Sprintf("Could not find the server %s. Check the URL, and that this Signalith server can look it up (DNS).", dnsErr.Name)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Sprintf("The server did not answer within %d seconds. Check the address, and that no firewall blocks this Signalith server.", HTTPTimeout)
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
		return "The server's HTTPS certificate is not from a trusted authority. Paste the CA certificate that issued it in the action."
	case errors.As(err, &hn):
		return "The server's HTTPS certificate is for another name. Use a name on the certificate in the URL."
	case errors.As(err, &ci):
		return "The server's HTTPS certificate is not valid (" + ci.Error() + ")."
	case errors.As(err, &rh):
		return "The server did not answer with HTTPS. Check whether the URL should start with http://."
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return "The request failed: " + err.Error()
}
