package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// proxyV2Sig starts every PROXY protocol version 2 header.
var proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

// proxyV2Header is the PROXY protocol v2 header a load balancer such as
// HAProxy (send-proxy-v2) puts before a connection's first byte, or
// before each datagram, to say where it came from. src and dst must both
// be IPv4 or both IPv6.
func proxyV2Header(udp bool, src, dst netip.AddrPort) ([]byte, error) {
	s, d := src.Addr().Unmap(), dst.Addr().Unmap()
	if !s.IsValid() || !d.IsValid() {
		return nil, errors.New("PROXY v2: both addresses are needed")
	}
	if s.Is4() != d.Is4() {
		return nil, errors.New("PROXY v2: source and destination must be the same IP version")
	}
	var fam byte
	var addrs []byte
	if s.Is4() {
		fam = 0x10
		a, b := s.As4(), d.As4()
		addrs = append(append(addrs, a[:]...), b[:]...)
	} else {
		fam = 0x20
		a, b := s.As16(), d.As16()
		addrs = append(append(addrs, a[:]...), b[:]...)
	}
	if udp {
		fam |= 0x02
	} else {
		fam |= 0x01
	}
	addrs = binary.BigEndian.AppendUint16(addrs, src.Port())
	addrs = binary.BigEndian.AppendUint16(addrs, dst.Port())
	h := make([]byte, 0, 16+len(addrs))
	h = append(h, proxyV2Sig...)
	h = append(h, 0x21, fam) // version 2, PROXY command
	h = binary.BigEndian.AppendUint16(h, uint16(len(addrs)))
	return append(h, addrs...), nil
}

// fakeSource is the n-th made-up source address, in 10.0.0.0/8 (or
// fd00::/8 when the destination is IPv6), for simulated devices behind a
// load balancer.
func fakeSource(n int, v6 bool) netip.Addr {
	if v6 {
		var b [16]byte
		b[0] = 0xfd
		binary.BigEndian.PutUint32(b[12:], uint32(n+1))
		return netip.AddrFrom16(b)
	}
	v := uint32(10)<<24 | uint32(n+1)&0xffffff
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
