// Package proxyproto reads the PROXY protocol header (versions 1 and 2)
// that a load balancer passing TCP connections on writes before the
// client's own bytes, so Signalith sees the address of the browser, agent
// or device that really connected instead of the balancer's.
//
// Only peers listed as trusted may send the header. A header from any
// other peer would let a client pick the address it is counted and logged
// under, so such connections are closed.
package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Signatures that start each version of the header.
var (
	sigV1 = []byte("PROXY ")
	sigV2 = []byte("\r\n\r\n\x00\r\nQUIT\n")
)

const (
	// maxV1 is the longest version 1 header, "\r\n" included.
	maxV1 = 107
	// v2Fixed is the fixed part of a version 2 header: the signature,
	// version and command, family and protocol, and length.
	v2Fixed = 16
	// maxV2Body caps the address block and TLVs of a version 2 header.
	// The addresses take at most 216 bytes; the rest leaves room for the
	// TLVs that cloud balancers add (such as an AWS endpoint ID).
	maxV2Body = 536
	// MaxHeader is the most bytes a header may take.
	MaxHeader = v2Fixed + maxV2Body
)

// Errors Parse returns.
var (
	// ErrNoHeader means the stream does not start with a PROXY header.
	// Nothing was consumed.
	ErrNoHeader = errors.New("proxyproto: no PROXY header")
	// ErrBadHeader means the stream starts with a PROXY signature that
	// is not followed by a valid header.
	ErrBadHeader = errors.New("proxyproto: malformed PROXY header")
)

// Header is what a PROXY header says about a connection.
type Header struct {
	// Src is the client that connected to the balancer, and Dst the
	// address it connected to. Both are zero when Local is set.
	Src, Dst netip.AddrPort
	// Local is set when the header names no client: a version 2 LOCAL
	// command (the balancer's own health check), an UNKNOWN version 1
	// header, or an address family other than IPv4 and IPv6 over TCP.
	// The connection then counts as the balancer's own.
	Local bool
	// Version is 1 or 2.
	Version int
}

// Parse reads one PROXY header from the start of r. When r does not start
// with a header signature it returns ErrNoHeader having consumed nothing,
// so the bytes can still be read as the client's. r must be able to
// buffer MaxHeader bytes (bufio.NewReaderSize(c, MaxHeader) or more).
func Parse(r *bufio.Reader) (Header, error) {
	v, err := detect(r)
	if err != nil {
		return Header{}, err
	}
	if v == 1 {
		return parseV1(r)
	}
	return parseV2(r)
}

// detect peeks at the start of r, a byte more at a time while it still
// matches a signature, so a client that sends something short (and that
// is not a header) is not left waiting for bytes it will never send. It
// returns 1 or 2, or ErrNoHeader.
func detect(r *bufio.Reader) (int, error) {
	v1, v2 := true, true
	for i := 0; ; i++ {
		b, err := r.Peek(i + 1)
		if len(b) <= i {
			// The stream ended (or failed) before a whole signature: a
			// short message that is not a header, or a read error.
			return 0, orNoHeader(err)
		}
		c := b[i]
		v1 = v1 && i < len(sigV1) && sigV1[i] == c
		v2 = v2 && i < len(sigV2) && sigV2[i] == c
		switch {
		case v1 && i == len(sigV1)-1:
			return 1, nil
		case v2 && i == len(sigV2)-1:
			return 2, nil
		case !v1 && !v2:
			return 0, ErrNoHeader
		}
	}
}

func orNoHeader(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return ErrNoHeader
	}
	return err
}

// HasSignature reports whether b starts with a PROXY header signature, or
// with a part of one when b is shorter than it.
func HasSignature(b []byte) bool {
	return len(b) > 0 && (bytes.HasPrefix(sigV1, b[:min(len(b), len(sigV1))]) || bytes.HasPrefix(sigV2, b[:min(len(b), len(sigV2))]))
}

func parseV1(r *bufio.Reader) (Header, error) {
	// Find the end of the line within maxV1 bytes without reading past it.
	var line []byte
	for n := len(sigV1) + 1; ; n++ {
		b, err := r.Peek(n)
		if len(b) < n {
			if err == nil || errors.Is(err, io.EOF) {
				err = ErrBadHeader
			}
			return Header{}, err
		}
		if b[n-1] == '\n' {
			line = b
			break
		}
		if n >= maxV1 {
			return Header{}, ErrBadHeader
		}
	}
	h, err := parseV1Line(string(line))
	if err != nil {
		return Header{}, err
	}
	_, _ = r.Discard(len(line))
	return h, nil
}

func parseV1Line(line string) (Header, error) {
	rest, ok := strings.CutSuffix(line, "\r\n")
	if !ok {
		return Header{}, ErrBadHeader
	}
	f := strings.Split(strings.TrimPrefix(rest, string(sigV1)), " ")
	if len(f) > 0 && f[0] == "UNKNOWN" {
		// "PROXY UNKNOWN" may carry anything after it; it names no client.
		return Header{Local: true, Version: 1}, nil
	}
	if len(f) != 5 || (f[0] != "TCP4" && f[0] != "TCP6") {
		return Header{}, ErrBadHeader
	}
	src, err1 := netip.ParseAddr(f[1])
	dst, err2 := netip.ParseAddr(f[2])
	sport, err3 := parsePort(f[3])
	dport, err4 := parsePort(f[4])
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return Header{}, ErrBadHeader
	}
	want4 := f[0] == "TCP4"
	if src.Zone() != "" || dst.Zone() != "" || src.Is4() != want4 || dst.Is4() != want4 {
		return Header{}, ErrBadHeader
	}
	return Header{Src: netip.AddrPortFrom(src, sport), Dst: netip.AddrPortFrom(dst, dport), Version: 1}, nil
}

func parsePort(s string) (uint16, error) {
	if s == "" || len(s) > 5 || (len(s) > 1 && s[0] == '0') {
		return 0, ErrBadHeader
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, ErrBadHeader
	}
	return uint16(n), nil
}

// Version 2 commands, address families and transport protocols.
const (
	cmdLocal = 0x0
	cmdProxy = 0x1
	famInet  = 0x1
	famInet6 = 0x2
	protoTCP = 0x1
	lenInet  = 12
	lenInet6 = 36
)

func parseV2(r *bufio.Reader) (Header, error) {
	fixed, err := r.Peek(v2Fixed)
	if len(fixed) < v2Fixed {
		if err == nil || errors.Is(err, io.EOF) {
			err = ErrBadHeader
		}
		return Header{}, err
	}
	verCmd, famProto := fixed[12], fixed[13]
	n := int(binary.BigEndian.Uint16(fixed[14:16]))
	if verCmd>>4 != 2 || n > maxV2Body {
		return Header{}, ErrBadHeader
	}
	cmd := verCmd & 0x0f
	if cmd != cmdLocal && cmd != cmdProxy {
		return Header{}, ErrBadHeader
	}
	all, err := r.Peek(v2Fixed + n)
	if len(all) < v2Fixed+n {
		if err == nil || errors.Is(err, io.EOF) {
			err = ErrBadHeader
		}
		return Header{}, err
	}
	body := all[v2Fixed:]
	h := Header{Version: 2}
	fam, proto := famProto>>4, famProto&0x0f
	switch {
	case cmd == cmdLocal:
		h.Local = true
	case fam == famInet && proto == protoTCP:
		if n < lenInet {
			return Header{}, ErrBadHeader
		}
		h.Src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[0:4])), binary.BigEndian.Uint16(body[8:10]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[4:8])), binary.BigEndian.Uint16(body[10:12]))
	case fam == famInet6 && proto == protoTCP:
		if n < lenInet6 {
			return Header{}, ErrBadHeader
		}
		h.Src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[0:16])), binary.BigEndian.Uint16(body[32:34]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[16:32])), binary.BigEndian.Uint16(body[34:36]))
	default:
		// UNSPEC, UNIX sockets or datagrams: no TCP client to name.
		h.Local = true
	}
	_, _ = r.Discard(v2Fixed + n)
	return h, nil
}

// String writes h as a version 1 header line, for logs and tests.
func (h Header) String() string {
	if h.Local {
		return "PROXY UNKNOWN"
	}
	fam := "TCP4"
	if h.Src.Addr().Is6() {
		fam = "TCP6"
	}
	return fmt.Sprintf("PROXY %s %s %s %d %d", fam, h.Src.Addr(), h.Dst.Addr(), h.Src.Port(), h.Dst.Port())
}

// AppendV2 appends h as a version 2 header to b, as a load balancer would
// write it: a PROXY command for a client, LOCAL when h.Local is set.
// Src and Dst must both be IPv4 or both IPv6.
func AppendV2(b []byte, h Header) []byte {
	b = append(b, sigV2...)
	if h.Local {
		return append(b, 0x20|cmdLocal, 0x00, 0, 0)
	}
	src, dst := h.Src.Addr().Unmap(), h.Dst.Addr().Unmap()
	if src.Is4() && dst.Is4() {
		b = append(b, 0x20|cmdProxy, famInet<<4|protoTCP, 0, lenInet)
		b = append(b, src.AsSlice()...)
		b = append(b, dst.AsSlice()...)
	} else {
		s16, d16 := h.Src.Addr().As16(), h.Dst.Addr().As16()
		b = append(b, 0x20|cmdProxy, famInet6<<4|protoTCP, 0, lenInet6)
		b = append(b, s16[:]...)
		b = append(b, d16[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, h.Src.Port())
	return binary.BigEndian.AppendUint16(b, h.Dst.Port())
}
