package ingest

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"
	"testing/iotest"
)

// FuzzReadBody: whatever a sender announces and however its body arrives,
// ReadBody returns exactly the bytes sent, takes memory from the budget
// only as they arrive, and gives all of it back.
func FuzzReadBody(f *testing.F) {
	for _, c := range []struct {
		body string
		hint int64
		mode byte
	}{
		{`[{"log":"x"}]`, -1, 0},
		{`[{"log":"x"}]`, 13, 1},
		{`[{"log":"x"}]`, 0, 2},
		{`[{"log":"x"}]`, 15 << 20, 3},
		{"", -1, 0},
		{"", 0, 1},
		{"x", MaxBodyBytes, 4 << 2},
		{"0123456789abcdef", 1 << 40, 7 << 2},
		{"0123456789abcdef", -5, 255},
	} {
		f.Add([]byte(c.body), c.hint, c.mode)
	}
	sender := netip.MustParseAddr("203.0.113.9")
	f.Fuzz(func(t *testing.T, chunk []byte, hint int64, mode byte) {
		// The body is the chunk repeated, so it can cross the points
		// where the buffer grows: up to 63 times 8 KB.
		body := chunk
		if n := int(mode>>2) * 8 << 10; len(chunk) > 0 && n > len(chunk) {
			body = bytes.Repeat(chunk, n/len(chunk))
		}
		var r io.Reader = bytes.NewReader(body)
		switch mode & 3 {
		case 1:
			r = iotest.OneByteReader(r)
		case 2:
			r = iotest.HalfReader(r)
		case 3:
			r = iotest.DataErrReader(r)
		}
		// With the top bit set, the body breaks off part way, as from a sender
		// that goes away.
		broken := mode&0x80 != 0 && len(body) > 0
		if broken {
			r = io.MultiReader(io.LimitReader(r, int64(len(body)/2)), iotest.ErrReader(io.ErrUnexpectedEOF))
		}
		p := &Pipeline{}
		got, release, err := p.ReadBody(r, sender, hint)
		total, _ := p.receiving()
		switch {
		case broken:
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("broken body: err = %v", err)
			}
		case err != nil:
			t.Fatalf("%d bytes, hint %d: %v", len(body), hint, err)
		case !bytes.Equal(got, body):
			t.Fatalf("%d bytes, hint %d: got %d bytes back", len(body), hint, len(got))
		case total < int64(len(body)) || total > 2*int64(len(body))+receiveStep+1:
			t.Fatalf("%d bytes, hint %d: %d held", len(body), hint, total)
		}
		release()
		if total, by := p.receiving(); total != 0 || len(by) != 0 {
			t.Fatalf("after release: %d held (%v)", total, by)
		}
	})
}
