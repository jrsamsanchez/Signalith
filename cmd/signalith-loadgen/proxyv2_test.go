package main

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestProxyV2Header(t *testing.T) {
	h, err := proxyV2Header(false, netip.MustParseAddrPort("10.0.0.1:40000"), netip.MustParseAddrPort("192.168.1.5:6514"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, // signature
		0x21,       // version 2, PROXY
		0x11,       // TCP over IPv4
		0x00, 0x0c, // 12 bytes of addresses
		10, 0, 0, 1, 192, 168, 1, 5,
		0x9c, 0x40, // 40000
		0x19, 0x72, // 6514
	}
	if !bytes.Equal(h, want) {
		t.Errorf("IPv4 TCP header\n got % x\nwant % x", h, want)
	}

	h, err = proxyV2Header(true, netip.MustParseAddrPort("[fd00::1]:514"), netip.MustParseAddrPort("[2001:db8::2]:5514"))
	if err != nil {
		t.Fatal(err)
	}
	if h[13] != 0x22 || h[14] != 0 || h[15] != 36 || len(h) != 16+36 {
		t.Errorf("IPv6 UDP header: family %#x, length %d, total %d", h[13], int(h[14])<<8|int(h[15]), len(h))
	}
	if !bytes.Equal(h[16:32], netip.MustParseAddr("fd00::1").AsSlice()) || h[48] != 0x02 || h[49] != 0x02 {
		t.Errorf("IPv6 addresses or ports wrong: % x", h[16:])
	}

	if _, err := proxyV2Header(false, netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("[::1]:2")); err == nil {
		t.Error("mixed IP versions were accepted")
	}
}

func TestFakeAddresses(t *testing.T) {
	seen := map[netip.Addr]bool{}
	for i := range 1000 {
		a := fakeSource(i, false)
		if !netip.MustParsePrefix("10.0.0.0/8").Contains(a) || seen[a] {
			t.Fatalf("source %d: %v", i, a)
		}
		seen[a] = true
	}
	if !fakeSource(3, true).Is6() || !fakeLoopback(300).IsLoopback() || fakeLoopback(1) == fakeLoopback(2) {
		t.Error("fake addresses")
	}
}
