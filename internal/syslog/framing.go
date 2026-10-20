// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package syslog

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
)

var (
	// errTooLarge reports a message over the size limit. The framer has
	// skipped it and the stream can continue.
	errTooLarge = errors.New("syslog message too large")
	// errFraming reports an octet count no sender would use; the stream
	// cannot be trusted after it.
	errFraming = errors.New("bad syslog octet-counted framing")
)

// maxOctetDigits is the longest octet count accepted (up to 9,999,999
// bytes). Counts over the message size limit are skipped; longer counts
// mean the stream is not syslog.
const maxOctetDigits = 7

// framer splits a TCP stream into syslog messages. Each message may use
// either RFC 6587 framing: octet counting ("123 <34>1 ...", always followed
// by '<' as every octet-counted sender includes the PRI) or a trailing
// newline (LF, also accepting NUL). Senders can mix them.
type framer struct {
	r   *bufio.Reader
	max int
	buf []byte
	err error
	// mark, when set, is told when a message begins (its first byte is
	// in) and when Next returns, so the reader can time the message.
	mark func(inMessage bool)
}

func newFramer(r io.Reader, max int) *framer {
	size := max + 32
	if size < 4096 {
		size = 4096
	}
	if size > 64<<10 {
		size = 64 << 10
	}
	return &framer{r: bufio.NewReaderSize(r, size), max: max}
}

// Next returns the next message, valid until the following call. It
// returns errTooLarge for a skipped oversized message (call Next again),
// errFraming when the stream cannot continue, and the reader's error (such
// as io.EOF) at the end, after any last message that had no newline.
func (f *framer) Next() ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	// Skip blank lines and stray delimiters between messages.
	for {
		b, err := f.r.Peek(1)
		if err != nil {
			f.err = err
			return nil, err
		}
		if c := b[0]; c != '\n' && c != '\r' && c != 0 && c != ' ' && c != '\t' {
			break
		}
		f.r.Discard(1)
	}
	if f.mark != nil {
		f.mark(true)
		defer f.mark(false)
	}
	n, counted, err := f.octetCount()
	if err != nil {
		f.err = err
		return nil, err
	}
	if counted {
		return f.counted(n)
	}
	return f.line()
}

// octetCount reads "NNN " when it is followed by '<'. It does not consume
// anything otherwise, so the bytes are read again as a line.
func (f *framer) octetCount() (int, bool, error) {
	for i := 0; ; i++ {
		b, err := f.r.Peek(i + 1)
		if err != nil {
			return 0, false, nil // too short to be a count; read it as a line
		}
		switch c := b[i]; {
		case isDigit(c) && i <= maxOctetDigits+3:
			if i == 0 && c == '0' {
				return 0, false, nil
			}
		case c == ' ' && i > 0:
			b, err := f.r.Peek(i + 2)
			if err != nil || b[i+1] != '<' {
				return 0, false, nil
			}
			if i > maxOctetDigits {
				return 0, false, errFraming
			}
			n, _ := strconv.Atoi(string(b[:i]))
			f.r.Discard(i + 1)
			return n, true, nil
		default:
			return 0, false, nil
		}
	}
}

func (f *framer) counted(n int) ([]byte, error) {
	if n > f.max {
		if _, err := io.CopyN(io.Discard, f.r, int64(n)); err != nil {
			f.err = err
			return nil, err
		}
		return nil, errTooLarge
	}
	if cap(f.buf) < n {
		f.buf = make([]byte, n)
	}
	buf := f.buf[:n]
	if _, err := io.ReadFull(f.r, buf); err != nil {
		// The stream ended inside the frame: the message is incomplete.
		if err == io.ErrUnexpectedEOF {
			err = io.EOF
		}
		f.err = err
		return nil, err
	}
	return buf, nil
}

// line reads up to the next LF or NUL. A line over the limit is skipped up
// to its end and reported as errTooLarge.
func (f *framer) line() ([]byte, error) {
	f.buf = f.buf[:0]
	tooLarge := false
	for {
		if f.r.Buffered() == 0 {
			if _, err := f.r.Peek(1); err != nil {
				f.err = err
				switch {
				case tooLarge:
					return nil, errTooLarge
				case len(f.buf) > 0:
					return f.buf, nil // last message, without a newline
				}
				return nil, err
			}
		}
		b, _ := f.r.Peek(f.r.Buffered())
		i := bytes.IndexAny(b, "\n\x00")
		chunk := b
		if i >= 0 {
			chunk = b[:i]
		}
		if !tooLarge {
			if len(f.buf)+len(chunk) > f.max {
				tooLarge = true
				f.buf = f.buf[:0]
			} else {
				f.buf = append(f.buf, chunk...)
			}
		}
		if i >= 0 {
			f.r.Discard(i + 1)
			if tooLarge {
				return nil, errTooLarge
			}
			return bytes.TrimSuffix(f.buf, []byte("\r")), nil
		}
		f.r.Discard(len(b))
	}
}
