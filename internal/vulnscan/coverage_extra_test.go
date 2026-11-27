// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
)

func TestOpenVASDialTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(notPEM, []byte("no certificate here"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addr := srv.Listener.Addr().String()

	c, err := (&OpenVAS{Address: addr, CAFile: ca}).dial(ctx)
	if err != nil {
		t.Fatalf("dial with the server's CA: %v", err)
	}
	c.Close()

	tests := []struct {
		name string
		o    *OpenVAS
		want string
	}{
		{"not host:port", &OpenVAS{Address: "gvmd"}, "neither a socket path nor host:port"},
		{"missing CA file", &OpenVAS{Address: addr, CAFile: filepath.Join(dir, "missing.pem")}, "OpenVAS CA file"},
		{"CA file without a certificate", &OpenVAS{Address: addr, CAFile: notPEM}, "has no certificate"},
		{"untrusted certificate", &OpenVAS{Address: addr}, "certificate"},
		{"socket missing", &OpenVAS{Address: "unix:" + filepath.Join(dir, "gvmd.sock")}, ""},
	}
	for _, tc := range tests {
		c, err := tc.o.dial(ctx)
		if err == nil {
			c.Close()
			t.Errorf("%s: dialled", tc.name)
			continue
		}
		if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	// open says where it could not reach.
	if _, err := (&OpenVAS{Address: "gvmd", Username: "u"}).open(ctx); err == nil || !strings.Contains(err.Error(), "could not reach OpenVAS at gvmd") {
		t.Errorf("open: %v", err)
	}
}

func TestLoginWordAndSeverity(t *testing.T) {
	for kind, want := range map[string]string{LoginSMB: "Windows", LoginESXi: "ESXi", LoginSNMP: "SNMP", "ssh": "SSH", "": "SSH"} {
		if got := loginWord(kind); got != want {
			t.Errorf("loginWord(%q) = %q, want %q", kind, got, want)
		}
	}
	for score, want := range map[float64]string{10: "critical", 9: "critical", 8.9: "high", 7: "high", 5: "medium", 4: "medium", 3.9: "low", 0: "low"} {
		if got := severityOf(score); got != want {
			t.Errorf("severityOf(%v) = %q, want %q", score, got, want)
		}
	}
}

func TestHostAddress(t *testing.T) {
	tests := []struct {
		hp   endpoint.HostPackages
		want string
	}{
		{endpoint.HostPackages{Hostname: "web", IPs: []string{"fe80::1", "10.0.0.5"}}, "10.0.0.5"},
		{endpoint.HostPackages{Hostname: "web", IPs: []string{"::ffff:10.0.0.6"}}, "10.0.0.6"},
		{endpoint.HostPackages{Hostname: "web", IPs: []string{"fe80::1", "2001:db8::1"}}, "fe80::1"},
		{endpoint.HostPackages{Hostname: "web", IPs: []string{"not-an-ip"}}, "not-an-ip"},
		{endpoint.HostPackages{Hostname: "web"}, "web"},
	}
	for _, tc := range tests {
		if got := hostAddress(&tc.hp); got != tc.want {
			t.Errorf("hostAddress(%v) = %q, want %q", tc.hp.IPs, got, tc.want)
		}
	}
}

func TestFirstLine(t *testing.T) {
	if firstLine([]byte("Starting Nmap 7.94\n\n  "+strings.Repeat("x", 400)+"\n")) != strings.Repeat("x", 300)+"…" {
		t.Error("firstLine does not cut a long line")
	}
	if firstLine([]byte("\nStarting Nmap\n")) != "" {
		t.Error("firstLine of a banner")
	}
}
