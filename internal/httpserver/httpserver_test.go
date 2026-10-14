package httpserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// startServer runs New(handler) on a loopback listener with the given
// timeouts shortened, and returns its address.
func startServer(t *testing.T, handler http.Handler, change func(*http.Server)) string {
	t.Helper()
	hs := New(handler, Limits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if change != nil {
		change(hs)
	}
	ln, err := Listen("127.0.0.1:0", Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go Serve(hs, ln, "", "")
	t.Cleanup(func() { hs.Close() })
	return ln.Addr().String()
}

// closedWithin reports whether the server closes c within d.
func closedWithin(c net.Conn, d time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, c)
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

func TestServerSettings(t *testing.T) {
	hs := New(http.NotFoundHandler(), Limits{}, nil)
	if hs.ReadHeaderTimeout != ReadHeaderTimeout || hs.IdleTimeout != IdleTimeout || hs.WriteTimeout != WriteTimeout ||
		hs.MaxHeaderBytes != MaxHeaderBytes || hs.TLSConfig.MinVersion < 0x0303 {
		t.Errorf("server settings: %+v", hs)
	}
	if hs.ReadTimeout != 0 {
		t.Error("ReadTimeout would cancel long searches; request bodies have their own deadline")
	}
	if hs.HTTP2 == nil || hs.HTTP2.MaxConcurrentStreams != MaxStreamsPerConnection {
		t.Errorf("HTTP/2 settings: %+v", hs.HTTP2)
	}
}

func TestSlowHeadersAndIdleConnectionsAreClosed(t *testing.T) {
	addr := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), func(hs *http.Server) {
		hs.ReadHeaderTimeout = 300 * time.Millisecond
		hs.IdleTimeout = 300 * time.Millisecond
	})
	// Headers that never finish.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n")
	if !closedWithin(c, 3*time.Second) {
		t.Error("a connection that never finished its headers was kept open")
	}
	// A kept-alive connection that goes quiet after one request.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	io.WriteString(c2, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c2), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("first request: %v %v", resp, err)
	}
	resp.Body.Close()
	if !closedWithin(c2, 3*time.Second) {
		t.Error("an idle kept-alive connection was kept open")
	}
}

func TestOversizedHeadersRefused(t *testing.T) {
	addr := startServer(t, http.NotFoundHandler(), nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nX-Big: "+strings.Repeat("a", 2*MaxHeaderBytes)+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized headers: %v %v", resp, err)
	}
}

// fakeListener hands out in-memory connections from chosen addresses.
type fakeListener struct {
	conns chan net.Conn
	done  chan struct{}
}

type addrConn struct {
	net.Conn
	addr net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.addr }

func (f *fakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-f.conns:
		return c, nil
	case <-f.done:
		return nil, net.ErrClosed
	}
}
func (f *fakeListener) Close() error   { close(f.done); return nil }
func (f *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

func (f *fakeListener) dial(ip string) net.Conn {
	a, b := net.Pipe()
	f.conns <- addrConn{Conn: a, addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}
	return b
}

func TestPerClientLimit(t *testing.T) {
	fl := &fakeListener{conns: make(chan net.Conn, 10), done: make(chan struct{})}
	var logs bytes.Buffer
	ln := Limit(fl, Limits{Max: 10, PerClient: 2}, slog.New(slog.NewTextHandler(&logs, nil)))
	defer ln.Close()
	accept := func() net.Conn {
		t.Helper()
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	fl.dial("203.0.113.9")
	fl.dial("203.0.113.9")
	a1, a2 := accept(), accept()
	// The third from the same address is closed at once; another address
	// and this machine still get in.
	third := fl.dial("203.0.113.9")
	fl.dial("198.51.100.7")
	if c := accept(); c.RemoteAddr().String() != "198.51.100.7:40000" {
		t.Fatalf("accepted %v", c.RemoteAddr())
	}
	third.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := third.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("third connection from one address: %v, want it closed", err)
	}
	if !strings.Contains(logs.String(), "too many connections") || strings.Count(logs.String(), "\n") != 1 {
		t.Errorf("log: %s", logs.String())
	}
	for i := 0; i < 3; i++ {
		fl.dial("127.0.0.1")
		accept()
	}
	// Closing one frees its place.
	a1.Close()
	a1.Close() // twice is harmless
	fl.dial("203.0.113.9")
	accept()
	a2.Close()
}

func TestTotalLimitWaits(t *testing.T) {
	fl := &fakeListener{conns: make(chan net.Conn, 10), done: make(chan struct{})}
	ln := Limit(fl, Limits{Max: 2}, nil)
	fl.dial("203.0.113.1")
	fl.dial("203.0.113.2")
	fl.dial("203.0.113.3")
	c1, _ := ln.Accept()
	ln.Accept()
	got := make(chan net.Conn)
	go func() {
		c, _ := ln.Accept()
		got <- c
	}()
	select {
	case <-got:
		t.Fatal("a third connection was accepted while two were open")
	case <-time.After(100 * time.Millisecond):
	}
	c1.Close()
	select {
	case c := <-got:
		if c == nil {
			t.Fatal("no connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closing a connection did not let the next one in")
	}
	ln.Close()
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("accept after close: %v", err)
	}
}

func TestLimitDefaults(t *testing.T) {
	if l := (Limits{}).withDefaults(); l.Max != DefaultMaxConnections || l.PerClient != DefaultMaxConnections/10 {
		t.Errorf("defaults %+v", l)
	}
	if l := (Limits{Max: 50}).withDefaults(); l.PerClient != 16 {
		t.Errorf("small max %+v", l)
	}
}

func TestErrorLogIsThrottled(t *testing.T) {
	var buf syncBuffer
	l := errorLog(slog.New(slog.NewTextHandler(&buf, nil)))
	for i := 0; i < 100; i++ {
		l.Printf("http: TLS handshake error from 203.0.113.9:%d: EOF", i)
	}
	if n := strings.Count(buf.String(), "\n"); n != errorLogBurst {
		t.Errorf("%d lines logged, want %d:\n%s", n, errorLogBurst, buf.String())
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestIPv6ClientsCountedByNetwork reproduces the IPv6 part of dos-2: one
// host picking a new address from its /64 for every connection must not
// get a new budget each time.
func TestIPv6ClientsCountedByNetwork(t *testing.T) {
	fl := &fakeListener{conns: make(chan net.Conn, 100), done: make(chan struct{})}
	var logs syncBuffer
	ln := Limit(fl, Limits{Max: 1000, PerClient: 3}, slog.New(slog.NewTextHandler(&logs, nil)))
	defer ln.Close()
	var others []net.Conn
	for i := range 50 {
		others = append(others, fl.dial(fmt.Sprintf("2001:db8:7:9::%x", i+1)))
	}
	for range 3 {
		if _, err := ln.Accept(); err != nil {
			t.Fatal(err)
		}
	}
	// The rest of that /64 is refused; a client in the next /64, and an
	// IPv4 client reaching a dual-stack listener, still get in.
	fl.dial("2001:db8:7:a::1")
	fl.dial("::ffff:198.51.100.7")
	for _, want := range []string{"[2001:db8:7:a::1]:40000", "198.51.100.7:40000"} {
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if got := clientaddrOf(c); got != want {
			t.Errorf("accepted %s, want %s", got, want)
		}
	}
	for _, c := range others[3:] {
		c.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("connection from the same /64: %v, want it closed", err)
		}
	}
	if !strings.Contains(logs.String(), "counted_as=2001:db8:7:9::/64") || !strings.Contains(logs.String(), "server.shared_addresses") {
		t.Errorf("log: %s", logs.String())
	}
}

func clientaddrOf(c net.Conn) string {
	a := c.RemoteAddr().(*net.TCPAddr)
	return netip.AddrPortFrom(a.AddrPort().Addr().Unmap(), a.AddrPort().Port()).String()
}

// TestSharedAddressesAreNotLimitedPerClient: a proxy, load balancer or
// NAT listed in Shared is not held to one client's share.
func TestSharedAddressesAreNotLimitedPerClient(t *testing.T) {
	fl := &fakeListener{conns: make(chan net.Conn, 10), done: make(chan struct{})}
	ln := Limit(fl, Limits{Max: 10, PerClient: 2, Shared: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/28")}}, nil)
	defer ln.Close()
	for range 5 {
		fl.dial("192.0.2.2")
	}
	for range 5 {
		if _, err := ln.Accept(); err != nil {
			t.Fatal(err)
		}
	}
	// Outside the listed network the share still applies.
	fl.dial("192.0.2.200")
	fl.dial("192.0.2.200")
	fl.dial("192.0.2.200")
	fl.dial("192.0.2.3")
	ln.Accept()
	ln.Accept()
	if c, _ := ln.Accept(); clientaddrOf(c) != "192.0.2.3:40000" {
		t.Errorf("third connection from 192.0.2.200 was accepted")
	}
}

// TestRequestsInProgressAreLimited: requests in progress are capped per
// client and in total, and refused ones get 503 with Retry-After at once.
func TestRequestsInProgressAreLimited(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 10)
	h := limitRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
	}), Limits{Max: 4, PerClient: 2, Shared: []netip.Prefix{netip.MustParsePrefix("192.0.2.9/32")}}, nil)
	send := func(remote string) chan *httptest.ResponseRecorder {
		out := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = remote
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			out <- w
		}()
		return out
	}
	refused := func(what string, ch chan *httptest.ResponseRecorder, msg string) {
		t.Helper()
		select {
		case w := <-ch:
			if w.Code != 503 || w.Header().Get("Retry-After") == "" || !strings.Contains(w.Body.String(), msg) {
				t.Errorf("%s: %d %v %s", what, w.Code, w.Header(), w.Body.String())
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s was let in", what)
		}
	}
	var held []chan *httptest.ResponseRecorder
	for _, from := range []string{"[2001:db8::1]:1", "[2001:db8::2]:2"} {
		held = append(held, send(from))
		<-started
	}
	// A third request from the same /64 waits for nothing: 503 at once.
	refused("third request from one client", send("[2001:db8::3]:3"), "this client has too many requests")
	// Shared addresses only count towards the total.
	for range 2 {
		held = append(held, send("192.0.2.9:4"))
		<-started
	}
	refused("request over the total", send("198.51.100.1:5"), "Signalith has too many requests")
	close(release)
	for _, ch := range held {
		if w := <-ch; w.Code != 200 {
			t.Errorf("held request: %d", w.Code)
		}
	}
	// Finished requests free their places.
	for range 2 {
		if w := <-send("[2001:db8::4]:6"); w.Code != 200 {
			t.Errorf("after the others finished: %d", w.Code)
		}
	}
}

// TestHTTP2StreamsCountAgainstTheClient reproduces the HTTP/2 part of
// dos-2: over HTTPS one connection carries many requests, and each must
// count against its client's budget, not just the connection.
func TestHTTP2StreamsCountAgainstTheClient(t *testing.T) {
	release := make(chan struct{})
	var running atomic.Int32
	hs := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("request over %s", r.Proto)
		}
		if r.URL.Path == "/first" {
			return
		}
		running.Add(1)
		<-release
	}), Limits{Max: 100, PerClient: 4}, nil)
	hs.TLSConfig.Certificates = []tls.Certificate{testCertificate(t)}
	fl := &fakeListener{conns: make(chan net.Conn, 10), done: make(chan struct{})}
	go hs.ServeTLS(Limit(fl, Limits{Max: 100, PerClient: 4}, nil), "", "")
	defer hs.Close()
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c := tls.Client(fl.dial("203.0.113.50"), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
			return c, c.HandshakeContext(ctx)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	// One request first, so the rest share its connection, as a browser's
	// would.
	if resp, err := client.Get("https://signalith.test/first"); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	codes := make(chan string, 10)
	for range 10 {
		go func() {
			resp, err := client.Get("https://signalith.test/")
			if err != nil {
				codes <- err.Error()
				return
			}
			resp.Body.Close()
			codes <- resp.Status
		}()
	}
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	refused := 0
	for range 6 {
		select {
		case c := <-codes:
			if !strings.HasPrefix(c, "503") {
				t.Fatalf("%s while 4 requests were held", c)
			}
			refused++
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of the extra requests were refused; %d running", refused, running.Load())
		}
	}
	// The refusals can arrive before the last admitted handler has
	// started, so give it a moment.
	for deadline := time.Now().Add(5 * time.Second); running.Load() < 4 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if n := running.Load(); n != 4 {
		t.Errorf("%d requests running, want 4", n)
	}
	close(release)
	released = true
	for range 4 {
		if c := <-codes; !strings.HasPrefix(c, "200") {
			t.Errorf("held request: %s", c)
		}
	}
}

// testCertificate returns a self-signed certificate for signalith.test.
func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "signalith.test"},
		DNSNames:     []string{"signalith.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestParseRefusal(t *testing.T) {
	for line, want := range map[string]string{
		"http: TLS handshake error from 203.0.113.9:51234: remote error: tls: unknown certificate authority\n": "203.0.113.9:51234",
		"http: TLS handshake error from [2001:db8::1]:443: remote error: tls: bad certificate":                 "[2001:db8::1]:443",
		"http: TLS handshake error from 10.0.0.5:1: remote error: tls: certificate unknown":                    "10.0.0.5:1",
		"http: TLS handshake error from 10.0.0.5:1: EOF":                                                       "",
		"http: TLS handshake error from 10.0.0.6:2: local error: tls: bad record MAC":                          "10.0.0.6:2",
		"http: TLS handshake error from 10.0.0.5:1: remote error: tls: protocol version not supported":         "",
		"http: panic serving 10.0.0.5:1: x":                                                                    "",
	} {
		got, ok := ParseRefusal(line)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", line, got, ok)
		}
	}
}

func TestOnRefusalSeesEveryRefusal(t *testing.T) {
	var buf bytes.Buffer
	hs := New(http.NotFoundHandler(), Limits{}, slog.New(slog.NewTextHandler(&buf, nil)))
	var got []string
	OnRefusal(hs, func(addr string) { got = append(got, addr) })
	for i := range errorLogBurst + 5 {
		hs.ErrorLog.Printf("http: TLS handshake error from 203.0.113.9:%d: remote error: tls: unknown certificate authority", i)
	}
	// Throttling the log does not throttle what is recorded.
	if len(got) != errorLogBurst+5 || got[0] != "203.0.113.9:0" {
		t.Errorf("%d refusals: %v", len(got), got)
	}
}
