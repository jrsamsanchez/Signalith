package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/jrsamsanchez/signalith/internal/redact"
)

// Report is what a connection test found, in plain words.
type Report struct {
	OK bool `json:"ok"`
	// Reached is true when something answered at the address.
	Reached bool   `json:"reached"`
	URL     string `json:"url"`
	// Problem is a code for what went wrong: unreachable, tls, http
	// (plain HTTP where HTTPS was expected, or the other way round), auth,
	// forbidden, not_opensearch, not_initialized (OpenSearch's security
	// settings aren't loaded), busy (OpenSearch too busy to answer in
	// time), timeout (it took the request but didn't answer in time) or
	// error.
	Problem string `json:"problem,omitempty"`
	// Message says what was found and, on a problem, what to do.
	Message      string `json:"message"`
	ClusterName  string `json:"cluster_name,omitempty"`
	Version      string `json:"version,omitempty"`
	Distribution string `json:"distribution,omitempty"`
	// Health is green, yellow or red.
	Health string `json:"health,omitempty"`
	TookMS int64  `json:"took_ms"`
}

// CheckTimeout bounds a connection test.
const CheckTimeout = 10 * time.Second

// checkMaxResponse caps each answer a connection test reads: OpenSearch's
// own are a few hundred bytes.
const checkMaxResponse = 1 << 20

// Check connects to OpenSearch with cfg and reports what it found: whether
// it answered, the cluster's name, version and health, or what went wrong
// and how to fix it.
func Check(ctx context.Context, cfg Config) Report {
	start := time.Now()
	if cfg.Timeout == 0 || cfg.Timeout > CheckTimeout {
		cfg.Timeout = CheckTimeout
	}
	cfg.MaxResponseBytes = checkMaxResponse
	rep := Report{URL: redact.URL(cfg.URL)}
	defer func() { rep.TookMS = time.Since(start).Milliseconds() }()
	c := New(cfg)
	defer c.CloseIdleConnections()
	var root struct {
		Name        string `json:"name"`
		ClusterName string `json:"cluster_name"`
		Version     struct {
			Number       string `json:"number"`
			Distribution string `json:"distribution"`
		} `json:"version"`
	}
	err := c.Do(ctx, http.MethodGet, "/", nil, &root)
	var se *Error
	switch {
	case errors.Is(err, ErrResponseTooLarge):
		rep.Reached, rep.Problem = true, "not_opensearch"
		rep.Message = fmt.Sprintf("Something answered at %s with far more than OpenSearch would, so it is not OpenSearch. Check the address and port.", redact.URL(cfg.URL))
		return rep
	case errors.As(err, &se) && se.Status == http.StatusForbidden:
		// A user limited to Signalith's indices may not read the root;
		// cluster health below tells whether it signed in.
	case err != nil:
		explainCheck(&rep, cfg, err)
		return rep
	case root.Version.Number == "":
		rep.Reached, rep.Problem = true, "not_opensearch"
		rep.Message = fmt.Sprintf("Something answered at %s, but it is not OpenSearch. Check the address and port.", redact.URL(cfg.URL))
		return rep
	}
	rep.Reached = true
	rep.ClusterName, rep.Version, rep.Distribution = root.ClusterName, root.Version.Number, root.Version.Distribution
	health, err := c.Health(ctx)
	if errors.Is(err, ErrResponseTooLarge) {
		rep.Problem = "not_opensearch"
		rep.Message = fmt.Sprintf("Something answered at %s with far more than OpenSearch would, so it is not OpenSearch. Check the address and port.", redact.URL(cfg.URL))
		return rep
	}
	if err != nil {
		explainCheck(&rep, cfg, err)
		return rep
	}
	rep.OK, rep.Health = true, health
	name := "OpenSearch"
	if rep.Distribution != "" && rep.Distribution != "opensearch" {
		name = rep.Distribution
	}
	switch {
	case rep.Version != "" && rep.ClusterName != "":
		rep.Message = fmt.Sprintf("Connected to %s %s, cluster %q. Health: %s.", name, rep.Version, rep.ClusterName, health)
	default:
		rep.Message = fmt.Sprintf("Connected to OpenSearch. Health: %s.", health)
	}
	return rep
}

// explainCheck words a failed connection test.
func explainCheck(rep *Report, cfg Config, err error) {
	u, _ := url.Parse(cfg.URL)
	host := redact.URL(cfg.URL)
	if u != nil && u.Host != "" {
		host = u.Host
	}
	https := u != nil && strings.EqualFold(u.Scheme, "https")
	var se *Error
	if errors.As(err, &se) {
		rep.Reached = true
		// These two are about OpenSearch itself, whatever the settings
		// here: changing them would not help.
		switch RefusalOf(se) {
		case RefusedNotInitialized:
			rep.Problem = "not_initialized"
			rep.Message = "OpenSearch is running, but its security settings aren't loaded, so it refuses every request, whatever the sign-in. " +
				NotInitializedFix + " Then test again."
			return
		case RefusedBusy:
			rep.Problem = "busy"
			rep.Message = "OpenSearch answered, but is too busy to do the request in time (" + strings.TrimPrefix(se.Error(), "opensearch returned ") + "). " +
				"Test again in a minute. " + BusyFix
			return
		}
		switch se.Status {
		case http.StatusUnauthorized:
			rep.Problem = "auth"
			if cfg.Username == "" {
				rep.Message = "OpenSearch asks for a username and password. Enter them."
			} else {
				rep.Message = "OpenSearch refused the username and password. Check them."
			}
		case http.StatusBadRequest:
			if strings.Contains(strings.ToLower(se.Error()), "http request to an https server") {
				rep.Problem = "http"
				rep.Message = fmt.Sprintf("%s uses HTTPS. Start the address with https:// instead.", host)
				return
			}
			rep.Problem = "error"
			rep.Message = "OpenSearch answered with an error: " + strings.TrimPrefix(se.Error(), "opensearch returned ")
		case http.StatusForbidden:
			rep.Problem = "forbidden"
			rep.Message = "OpenSearch accepted the sign-in, but this user may not read the cluster's health. Give it the cluster_monitor permission, or use another user."
		default:
			rep.Problem = "error"
			rep.Message = "OpenSearch answered with an error: " + strings.TrimPrefix(se.Error(), "opensearch returned ")
		}
		return
	}
	if NoAnswer(err) {
		rep.Reached, rep.Problem = true, ProblemTimeout
		rep.Message = fmt.Sprintf("OpenSearch at %s took the request but didn't answer within %d seconds. It may be starting, or too busy: test again in a minute. %s",
			host, int(CheckTimeout.Seconds()), BusyFix)
		return
	}
	var (
		dnsErr   *net.DNSError
		unknown  x509.UnknownAuthorityError
		hostErr  x509.HostnameError
		invalid  x509.CertificateInvalidError
		verify   *tls.CertificateVerificationError
		header   tls.RecordHeaderError
		netErr   net.Error
		errnoErr syscall.Errno
	)
	switch {
	case errors.As(err, &header) || strings.Contains(err.Error(), "server gave HTTP response to HTTPS client"):
		rep.Reached, rep.Problem = true, "http"
		rep.Message = fmt.Sprintf("%s does not use HTTPS. If OpenSearch runs without TLS, start the address with http:// instead.", host)
	case errors.As(err, &hostErr):
		rep.Reached, rep.Problem = true, "tls"
		rep.Message = fmt.Sprintf("The certificate at %s is for another name (%v). Use the name the certificate was made for in the address.", host, hostErr.Error())
	case errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &verify):
		rep.Reached, rep.Problem = true, "tls"
		rep.Message = fmt.Sprintf("Signalith reached %s but does not trust its certificate (%v). Use a certificate this computer trusts, or turn on Skip certificate check on a test system.", host, certReason(err))
	case errors.As(err, &dnsErr):
		rep.Problem = "unreachable"
		rep.Message = fmt.Sprintf("The name %s could not be found. Check the address.", dnsErr.Name)
	case errors.Is(err, syscall.ECONNREFUSED) || errors.As(err, &errnoErr) && errnoErr == 10061: // WSAECONNREFUSED
		rep.Problem = "unreachable"
		rep.Message = fmt.Sprintf("Nothing answered at %s. Check that OpenSearch is running, and the address and port.", host)
	case errors.As(err, &netErr) && netErr.Timeout(), errors.Is(err, context.DeadlineExceeded):
		rep.Problem = "unreachable"
		rep.Message = fmt.Sprintf("No answer from %s within %d seconds. Check the address, and that a firewall lets this server reach it.", host, int(CheckTimeout.Seconds()))
	case !https && (errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "connection reset")):
		rep.Reached, rep.Problem = true, "http"
		rep.Message = fmt.Sprintf("%s closed the connection. If OpenSearch uses HTTPS, start the address with https:// instead.", host)
	default:
		rep.Problem = "unreachable"
		reason := err.Error()
		var ue *url.Error
		if errors.As(err, &ue) {
			reason = ue.Err.Error()
		}
		rep.Message = fmt.Sprintf("Could not connect to %s: %s.", host, reason)
	}
}

// certReason is the part of a certificate error that says what is wrong.
func certReason(err error) string {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "it is signed by an authority this computer does not know, often a self-signed certificate"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return "it has expired or is not valid yet"
	}
	s := err.Error()
	if i := strings.LastIndex(s, "x509: "); i >= 0 {
		return s[i+len("x509: "):]
	}
	return s
}
