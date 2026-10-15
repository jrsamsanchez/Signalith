package proxyproto

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var client = Header{Src: netip.MustParseAddrPort("203.0.113.9:40000"), Dst: netip.MustParseAddrPort("192.0.2.1:8443")}

// listen wraps a loopback listener; trusted says whether loopback (the
// test's own connections) is a trusted proxy.
func listen(t *testing.T, trusted bool, timeout time.Duration) (*Listener, *bytes.Buffer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	cfg := Config{HeaderTimeout: timeout, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	if trusted {
		cfg.Trusted = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	}
	pl := Wrap(ln, cfg)
	t.Cleanup(func() { pl.Close() })
	return pl, &logs
}

// exchange dials l, writes out, and returns the accepted conn's remote
// address and what it read (until the dialer closes its side).
func exchange(t *testing.T, l *Listener, out []byte) (string, string, error) {
	t.Helper()
	d, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	go func() {
		d.Write(out)
		d.(*net.TCPConn).CloseWrite()
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	addr := c.RemoteAddr().String()
	got, err := io.ReadAll(c)
	return addr, string(got), err
}

func TestTrustedPeer(t *testing.T) {
	l, _ := listen(t, true, time.Second)
	addr, got, err := exchange(t, l, append(AppendV2(nil, client), "hello"...))
	if err != nil || addr != "203.0.113.9:40000" || got != "hello" {
		t.Errorf("v2: addr %s got %q err %v", addr, got, err)
	}
	addr, got, err = exchange(t, l, []byte("PROXY TCP4 198.51.100.4 192.0.2.1 1234 514\r\n<13>hi\n"))
	if err != nil || addr != "198.51.100.4:1234" || got != "<13>hi\n" {
		t.Errorf("v1: addr %s got %q err %v", addr, got, err)
	}
	// No header, or LOCAL: the balancer itself (a health check).
	for _, in := range [][]byte{[]byte("GET /readyz HTTP/1.1\r\n\r\n"), append(AppendV2(nil, Header{Local: true}), "GET"...)} {
		addr, got, err = exchange(t, l, in)
		if err != nil || !strings.HasPrefix(addr, "127.0.0.1:") || !strings.HasPrefix(got, "GET") {
			t.Errorf("%q: addr %s got %q err %v", in, addr, got, err)
		}
	}
	// A malformed header closes the connection.
	if _, _, err = exchange(t, l, []byte("PROXY TCP4 nonsense\r\nhello")); !errors.Is(err, ErrBadHeader) {
		t.Errorf("malformed: err %v", err)
	}
}

func TestTrustedPeerSlowHeader(t *testing.T) {
	l, _ := listen(t, true, 200*time.Millisecond)
	d, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.Write(sigV2[:5]) // and then nothing
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_ = c.RemoteAddr()
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("RemoteAddr waited %v", el)
	}
	var ne net.Error
	if _, err := c.Read(make([]byte, 10)); !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("read after a slow header: %v", err)
	}
}

func TestAcceptDoesNotWaitForHeader(t *testing.T) {
	l, _ := listen(t, true, 5*time.Second)
	slow, _ := net.Dial("tcp", l.Addr().String())
	defer slow.Close()
	c1, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	fast, _ := net.Dial("tcp", l.Addr().String())
	defer fast.Close()
	fast.Write(AppendV2(nil, client))
	done := make(chan string)
	go func() {
		c2, err := l.Accept()
		if err != nil {
			done <- err.Error()
			return
		}
		defer c2.Close()
		done <- c2.RemoteAddr().String()
	}()
	select {
	case got := <-done:
		if got != "203.0.113.9:40000" {
			t.Errorf("second connection: %s", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a peer that sends nothing held up the next connection")
	}
}

func TestUntrustedPeer(t *testing.T) {
	l, logs := listen(t, false, time.Second)
	if _, _, err := exchange(t, l, append(AppendV2(nil, client), "x"...)); !errors.Is(err, ErrUntrusted) {
		t.Errorf("v2 from untrusted: %v", err)
	}
	if _, _, err := exchange(t, l, []byte("PROXY TCP4 198.51.100.4 192.0.2.1 1234 514\r\n")); !errors.Is(err, ErrUntrusted) {
		t.Errorf("v1 from untrusted: %v", err)
	}
	if n := l.Untrusted(); n != 2 {
		t.Errorf("Untrusted() = %d, want 2", n)
	}
	if !strings.Contains(logs.String(), "server.trusted_proxies") || strings.Count(logs.String(), "level=WARN") != 1 {
		t.Errorf("log: %s", logs)
	}
	for _, in := range []string{"POST /api/ingest HTTP/1.1\r\n\r\n", "\x16\x03\x01\x00", "\r\n<13>hi\n", "P"} {
		addr, got, err := exchange(t, l, []byte(in))
		if err != nil || got != in || !strings.HasPrefix(addr, "127.0.0.1:") {
			t.Errorf("%q from untrusted: addr %s got %q err %v", in, addr, got, err)
		}
	}
}
