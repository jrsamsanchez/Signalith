package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
)

func parseString(t *testing.T, s string) (Header, string, error) {
	t.Helper()
	r := bufio.NewReaderSize(strings.NewReader(s), MaxHeader)
	h, err := Parse(r)
	rest, _ := io.ReadAll(r)
	return h, string(rest), err
}

func TestParseV1(t *testing.T) {
	for _, tc := range []struct {
		in, src, rest string
		local         bool
		err           error
	}{
		{in: "PROXY TCP4 192.0.2.10 198.51.100.1 51234 8443\r\nGET / HTTP/1.1\r\n", src: "192.0.2.10:51234", rest: "GET / HTTP/1.1\r\n"},
		{in: "PROXY TCP6 2001:db8::7 2001:db8::1 4000 6514\r\n\x16\x03", src: "[2001:db8::7]:4000", rest: "\x16\x03"},
		{in: "PROXY UNKNOWN\r\nhello", local: true, rest: "hello"},
		{in: "PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n", local: true},
		{in: "PROXY TCP4 2001:db8::7 192.0.2.1 1 2\r\n", err: ErrBadHeader},
		{in: "PROXY TCP6 192.0.2.7 192.0.2.1 1 2\r\n", err: ErrBadHeader},
		{in: "PROXY TCP4 192.0.2.7 192.0.2.1 01 2\r\n", err: ErrBadHeader},
		{in: "PROXY TCP4 192.0.2.7 192.0.2.1 70000 2\r\n", err: ErrBadHeader},
		{in: "PROXY TCP4 192.0.2.7 192.0.2.1 1\r\n", err: ErrBadHeader},
		{in: "PROXY TCP4 192.0.2.7 192.0.2.1 1 2\n", err: ErrBadHeader},
		{in: "PROXY TCP4 192.0.2.7 192.0.2.1 1 2", err: ErrBadHeader},
		{in: "PROXY " + strings.Repeat("x", 200) + "\r\n", err: ErrBadHeader},
		{in: "POST /api/ingest HTTP/1.1\r\n", err: ErrNoHeader, rest: "POST /api/ingest HTTP/1.1\r\n"},
		{in: "<13>Oct 14 host app: hi\n", err: ErrNoHeader, rest: "<13>Oct 14 host app: hi\n"},
		{in: "PRO", err: ErrNoHeader, rest: "PRO"},
		{in: "", err: ErrNoHeader},
	} {
		h, rest, err := parseString(t, tc.in)
		if !errors.Is(err, tc.err) {
			t.Errorf("%q: err %v, want %v", tc.in, err, tc.err)
			continue
		}
		if err != nil && !errors.Is(err, ErrNoHeader) {
			continue
		}
		if err == nil {
			if h.Local != tc.local || (!tc.local && h.Src.String() != tc.src) || h.Version != 1 {
				t.Errorf("%q: header %+v, want src %s local %v", tc.in, h, tc.src, tc.local)
			}
		}
		if rest != tc.rest {
			t.Errorf("%q: rest %q, want %q", tc.in, rest, tc.rest)
		}
	}
}

func TestParseV2(t *testing.T) {
	v4 := Header{Src: netip.MustParseAddrPort("192.0.2.10:51234"), Dst: netip.MustParseAddrPort("198.51.100.1:8443")}
	v6 := Header{Src: netip.MustParseAddrPort("[2001:db8::7]:4000"), Dst: netip.MustParseAddrPort("[2001:db8::1]:6514")}
	for _, want := range []Header{v4, v6} {
		in := string(AppendV2(nil, want)) + "payload"
		h, rest, err := parseString(t, in)
		if err != nil || h.Src != want.Src || h.Dst != want.Dst || h.Local || h.Version != 2 || rest != "payload" {
			t.Errorf("%v: got %+v rest %q err %v", want, h, rest, err)
		}
	}

	local := string(AppendV2(nil, Header{Local: true})) + "x"
	if h, rest, err := parseString(t, local); err != nil || !h.Local || rest != "x" {
		t.Errorf("LOCAL: %+v %q %v", h, rest, err)
	}

	// TLVs after the addresses are skipped.
	b := AppendV2(nil, v4)
	tlv := []byte{0xEA, 0x00, 0x03, 'a', 'b', 'c'}
	b[15] += byte(len(tlv))
	b = append(b, tlv...)
	if h, rest, err := parseString(t, string(b)+"z"); err != nil || h.Src != v4.Src || rest != "z" {
		t.Errorf("TLV: %+v %q %v", h, rest, err)
	}

	// UNSPEC family and UNIX sockets name no TCP client.
	for _, fam := range []byte{0x00, 0x31, 0x12} {
		b := append([]byte(nil), sigV2...)
		b = append(b, 0x21, fam, 0, 0)
		if h, _, err := parseString(t, string(b)); err != nil || !h.Local {
			t.Errorf("family %#x: %+v %v", fam, h, err)
		}
	}

	bad := func(name string, b []byte) {
		t.Helper()
		if _, _, err := parseString(t, string(b)); !errors.Is(err, ErrBadHeader) {
			t.Errorf("%s: err %v, want ErrBadHeader", name, err)
		}
	}
	trunc := AppendV2(nil, v4)
	bad("truncated", trunc[:len(trunc)-3])
	bad("fixed part truncated", trunc[:14])
	ver := append([]byte(nil), trunc...)
	ver[12] = 0x11
	bad("version 1 byte", ver)
	cmd := append([]byte(nil), trunc...)
	cmd[12] = 0x2F
	bad("unknown command", cmd)
	short := append([]byte(nil), trunc[:16]...)
	short[15] = 4
	bad("address block too short", append(short, 1, 2, 3, 4))
	big := append(append([]byte(nil), sigV2...), 0x21, 0x11, 0x02, 0x19) // 537
	bad("oversize", append(big, make([]byte, 537)...))
}

func TestHasSignature(t *testing.T) {
	for in, want := range map[string]bool{
		"":                       false,
		"P":                      true,
		"PROXY TCP4":             true,
		"POST":                   false,
		"\r\n\r\n":               true,
		"\r\n\r\n\x00\r\nQUIT\n": true,
		"\r\nX":                  false,
		"\x16\x03\x01":           false,
	} {
		if got := HasSignature([]byte(in)); got != want {
			t.Errorf("HasSignature(%q) = %v", in, got)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("PROXY TCP4 192.0.2.10 198.51.100.1 51234 8443\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add(AppendV2(nil, Header{Src: netip.MustParseAddrPort("[2001:db8::7]:4000"), Dst: netip.MustParseAddrPort("[2001:db8::1]:6514")}))
	f.Add(AppendV2(nil, Header{Local: true}))
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		r := bufio.NewReaderSize(bytes.NewReader(in), MaxHeader)
		h, err := Parse(r)
		rest, _ := io.ReadAll(r)
		switch {
		case errors.Is(err, ErrNoHeader):
			if !bytes.Equal(rest, in) {
				t.Fatalf("no header but %d bytes consumed", len(in)-len(rest))
			}
		case err == nil:
			if used := len(in) - len(rest); used > MaxHeader || !bytes.Equal(in[used:], rest) {
				t.Fatalf("header used %d bytes", used)
			}
			if !h.Local && (!h.Src.IsValid() || !h.Dst.IsValid()) {
				t.Fatalf("header without addresses: %+v", h)
			}
		}
	})
}
