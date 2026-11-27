// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
)

func TestConnectError(t *testing.T) {
	s := &LDAPSettings{ConnectTimeout: 7}
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"dns", &net.DNSError{Name: "dc1.corp.example", Err: "no such host"}, "dc1.corp.example could not be found"},
		{"deadline", context.DeadlineExceeded, "within 7 seconds"},
		{"refused", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), "refused the connection"},
		{"other", errors.New("boom"), "Could not connect to dc1:389: boom"},
	}
	for _, tc := range tests {
		e := connectError("dc1", "dc1:389", tc.err, s)
		if e.Code != "connect" || e.Server != "dc1" || !strings.Contains(e.Message, tc.want) || e.Err != tc.err {
			t.Errorf("%s: %+v", tc.name, e)
		}
	}
}

func TestTLSError(t *testing.T) {
	withNames := &x509.Certificate{DNSNames: []string{"dc1.corp.example"}}
	cnOnly := &x509.Certificate{Subject: pkix.Name{CommonName: "dc-cn"}}
	tests := []struct {
		name   string
		err    error
		scheme string
		ca     string
		code   string
		want   string
	}{
		{"untrusted", x509.UnknownAuthorityError{}, "ldaps", "", "tls_untrusted", "Paste the certificate"},
		{"untrusted with CA", x509.UnknownAuthorityError{}, "ldaps", "pem", "tls_untrusted", "not signed by the CA certificate you gave"},
		{"hostname", x509.HostnameError{Certificate: withNames, Host: "dc2"}, "ldaps", "", "tls_hostname", "for dc1.corp.example, not dc2"},
		{"hostname cn", x509.HostnameError{Certificate: cnOnly, Host: "dc2"}, "ldaps", "", "tls_hostname", "for dc-cn, not dc2"},
		{"expired", x509.CertificateInvalidError{Reason: x509.Expired}, "ldaps", "", "tls_expired", "expired"},
		{"plain port", tls.RecordHeaderError{Msg: "not TLS"}, "ldaps", "", "tls_handshake", "use ldap:// with StartTLS"},
		{"starttls eof", io.EOF, "ldap", "", "tls_handshake", "did not start TLS"},
		{"reset", errors.New("connection reset by peer"), "ldaps", "", "tls_handshake", "did not answer with TLS"},
		{"old tls", errors.New("tls: protocol version not supported"), "ldaps", "", "tls_handshake", "older than 1.2"},
		{"other", errors.New("boom"), "ldaps", "", "tls_handshake", "handshake with dc2 failed: boom"},
	}
	for _, tc := range tests {
		e := tlsError("dc1", "dc2", tc.scheme, tc.err, &LDAPSettings{CACert: tc.ca})
		if e.Code != tc.code || !strings.Contains(e.Message, tc.want) || e.Server != "dc1" {
			t.Errorf("%s: %s %q", tc.name, e.Code, e.Message)
		}
	}
}
