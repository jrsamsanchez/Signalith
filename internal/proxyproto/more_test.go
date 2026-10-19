// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package proxyproto

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestHeaderString(t *testing.T) {
	v6 := Header{Src: netip.MustParseAddrPort("[2001:db8::7]:4000"), Dst: netip.MustParseAddrPort("[2001:db8::1]:6514")}
	for h, want := range map[Header]string{
		{Local: true}: "PROXY UNKNOWN",
		client:        "PROXY TCP4 203.0.113.9 192.0.2.1 40000 8443",
		v6:            "PROXY TCP6 2001:db8::7 2001:db8::1 4000 6514",
	} {
		if got := h.String(); got != want {
			t.Errorf("String = %q, want %q", got, want)
		}
	}
	short := append([]byte(nil), sigV2...)
	short = append(short, 0x21, 0x21, 0, 12)
	short = append(short, make([]byte, 12)...)
	if _, _, err := parseString(t, string(short)); err != ErrBadHeader {
		t.Errorf("short IPv6 block = %v", err)
	}
}

func TestWrapDefaultsAndTrustedNow(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	trusted := []netip.Prefix{}
	l := Wrap(ln, Config{TrustedNow: func() []netip.Prefix { return trusted }})
	if l.cfg.HeaderTimeout != DefaultHeaderTimeout || l.cfg.Setting != "server.trusted_proxies" {
		t.Errorf("defaults = %+v", l.cfg)
	}
	if l.cfg.Trusts(netip.MustParseAddr("::ffff:127.0.0.1")) {
		t.Error("trusted with an empty list")
	}
	trusted = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	if !l.cfg.Trusts(netip.MustParseAddr("::ffff:127.0.0.1")) {
		t.Error("the new list was not used")
	}
	var none *Listener
	if none.Untrusted() != 0 {
		t.Error("a nil listener counted")
	}
	l.Close()
	if _, err := l.Accept(); err == nil {
		t.Error("accepted on a closed listener")
	}
}

func TestConnPeerAndProxied(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		l, _ := listen(t, trusted, time.Second)
		d, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			d.Write(append(AppendV2(nil, client), "hi"...))
		}()
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		pc := c.(*Conn)
		if got := pc.Proxied(); got != trusted {
			t.Errorf("trusted %v: Proxied = %v", trusted, got)
		}
		if pc.Peer().String() != d.LocalAddr().String() {
			t.Errorf("Peer = %s, want %s", pc.Peer(), d.LocalAddr())
		}
		if err := pc.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Errorf("SetDeadline = %v", err)
		}
		if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Errorf("SetReadDeadline = %v", err)
		}
		if err := pc.CloseWrite(); err != nil {
			t.Errorf("CloseWrite = %v", err)
		}
		// The dialer sees the half-close.
		d.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := d.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Errorf("after CloseWrite = %d %v", n, err)
		}
		d.Close()
		c.Close()
	}
}

// While the header is read, a deadline the connection's user sets is
// kept for afterwards and only the write side gets it at once.
func TestDeadlinesDuringHeader(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &Conn{Conn: a, l: Wrap(nil, Config{}), trusted: true, inHeader: true}
	when := time.Now().Add(time.Hour)
	if err := c.SetReadDeadline(when); err != nil || !c.readDeadline.Equal(when) {
		t.Errorf("read deadline = %v %v", c.readDeadline, err)
	}
	if err := c.SetDeadline(when.Add(time.Minute)); err != nil || !c.readDeadline.Equal(when.Add(time.Minute)) {
		t.Errorf("deadline = %v %v", c.readDeadline, err)
	}
	// A pipe has no half-close.
	if err := c.CloseWrite(); err != nil {
		t.Errorf("CloseWrite on a pipe = %v", err)
	}
}
