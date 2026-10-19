// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clientaddr

import (
	"net"
	"net/netip"
	"testing"
)

func TestKey(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"203.0.113.9", "203.0.113.9"},
		{"::ffff:203.0.113.9", "203.0.113.9"},
		{"2001:db8:1:2::1", "2001:db8:1:2::"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::"},
		{"2001:db8:1:3::1", "2001:db8:1:3::"},
		{"fe80::1%eth0", "fe80::"},
	} {
		if got := Key(netip.MustParseAddr(c.in)); got.String() != c.want {
			t.Errorf("Key(%s) = %s, want %s", c.in, got, c.want)
		}
	}
	// Every address of one /64 is one client; the next /64 is another.
	a, b := netip.MustParseAddr("2001:db8:0:1::1"), netip.MustParseAddr("2001:db8:0:1:ffff:ffff:ffff:ffff")
	if Key(a) != Key(b) || Key(a) == Key(netip.MustParseAddr("2001:db8:0:2::1")) {
		t.Error("IPv6 addresses are not grouped by /64")
	}
}

func TestOfAndParse(t *testing.T) {
	if got := Of(&net.TCPAddr{IP: net.ParseIP("::ffff:198.51.100.7"), Port: 1}); got.String() != "198.51.100.7" {
		t.Errorf("Of = %s", got)
	}
	if got := Of(nil); got.IsValid() {
		t.Errorf("Of(nil) = %s", got)
	}
	for in, want := range map[string]string{
		"198.51.100.7:4000":       "198.51.100.7",
		"[2001:db8::5]:443":       "2001:db8::5",
		"[fe80::1%eth0]:443":      "fe80::1",
		"[::ffff:192.0.2.1]:8080": "192.0.2.1",
		"192.0.2.1":               "192.0.2.1",
	} {
		if got := Parse(in); got.String() != want {
			t.Errorf("Parse(%q) = %s, want %s", in, got, want)
		}
	}
	if Parse("@").IsValid() || Parse("").IsValid() {
		t.Error("non-addresses parsed")
	}
}

func TestShared(t *testing.T) {
	shared := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8:aa::/48")}
	for in, want := range map[string]bool{
		"127.0.0.1":          true, // this machine
		"::1":                true,
		"192.0.2.77":         true,
		"2001:db8:aa:5::9":   true,
		"198.51.100.7":       false,
		"2001:db8:bb::1":     false,
		"::ffff:192.0.2.200": true,
	} {
		if got := Shared(netip.MustParseAddr(in), shared); got != want {
			t.Errorf("Shared(%s) = %v, want %v", in, got, want)
		}
	}
	if !Shared(netip.Addr{}, nil) {
		t.Error("an address that is not an IP address is counted as a client")
	}
}
