package httpserver

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/proxyproto"
)

func TestProxyHeaderBeforeTLSAndPlainHTTP(t *testing.T) {
	cert := testCertificate(t)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.RemoteAddr) })
	lim := Limits{Proxy: &proxyproto.Config{Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}}
	hs := New(echo, lim, nil)
	hs.TLSConfig.Certificates = []tls.Certificate{cert}
	plain := New(echo, lim, nil)
	ln, err := Listen("127.0.0.1:0", lim, nil)
	if err != nil {
		t.Fatal(err)
	}
	go ServeBoth(hs, plain, ln)
	t.Cleanup(func() { hs.Close(); plain.Close() })
	addr := ln.Addr().String()

	header := proxyproto.AppendV2(nil, proxyproto.Header{
		Src: netip.MustParseAddrPort("203.0.113.9:40000"), Dst: netip.MustParseAddrPort("192.0.2.1:8443")})
	dial := func(t *testing.T) net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write(header); err != nil {
			t.Fatal(err)
		}
		return c
	}
	read := func(t *testing.T, c net.Conn) string {
		t.Helper()
		io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	c := dial(t)
	defer c.Close()
	if got := read(t, c); got != "203.0.113.9:40000" {
		t.Errorf("plain HTTP after a header: RemoteAddr %q", got)
	}
	tc := tls.Client(dial(t), &tls.Config{InsecureSkipVerify: true})
	defer tc.Close()
	if got := read(t, tc); got != "203.0.113.9:40000" {
		t.Errorf("HTTPS after a header: RemoteAddr %q", got)
	}
	// The balancer's own health check, with no header.
	hc, _ := net.Dial("tcp", addr)
	defer hc.Close()
	if got := read(t, hc); !strings.HasPrefix(got, "127.0.0.1:") {
		t.Errorf("no header: RemoteAddr %q", got)
	}
}

func TestTrustedProxyIsShared(t *testing.T) {
	lb := netip.MustParseAddr("10.0.0.5")
	without := Limits{}
	if _, limited := without.client(lb); !limited {
		t.Fatal("an ordinary address is not limited")
	}
	with := Limits{Proxy: &proxyproto.Config{Trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32")}}}
	if _, limited := with.client(lb); limited {
		t.Error("a trusted proxy sending PROXY headers is limited as one client")
	}
	if _, limited := with.client(netip.MustParseAddr("203.0.113.9")); !limited {
		t.Error("a client behind the proxy is not limited")
	}
}
