// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package syslog

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// frames reads every message from a stream, recording errTooLarge as
// "<too large>" and stopping at any other error.
func frames(r io.Reader, max int) ([]string, error) {
	f := newFramer(r, max)
	var out []string
	for {
		msg, err := f.Next()
		switch {
		case err == nil:
			out = append(out, string(msg))
		case errors.Is(err, errTooLarge):
			out = append(out, "<too large>")
		case err == io.EOF:
			return out, nil
		default:
			return out, err
		}
	}
}

func TestFraming(t *testing.T) {
	cases := []struct {
		name, in string
		max      int
		want     []string
		err      error
	}{
		{"newline", "<13>a\n<13>b\n", 100, []string{"<13>a", "<13>b"}, nil},
		{"CRLF and blank lines", "<13>a\r\n\r\n\n<13>b\r\n", 100, []string{"<13>a", "<13>b"}, nil},
		{"NUL delimiter", "<13>a\x00<13>b\x00", 100, []string{"<13>a", "<13>b"}, nil},
		{"no newline at the end", "<13>a\n<13>b", 100, []string{"<13>a", "<13>b"}, nil},
		{"octet counting", "6 <13>hi6 <13>yo", 100, []string{"<13>hi", "<13>yo"}, nil},
		{"octet counting keeps newlines inside", "13 <13>two\nlines", 100, []string{"<13>two\nlines"}, nil},
		{"mixed", "6 <13>hi\n<13>line\n6 <13>yo<13>last\n", 100, []string{"<13>hi", "<13>line", "<13>yo", "<13>last"}, nil},
		{"digits that are not a count", "12 errors today\n0 <13>x\n", 100, []string{"12 errors today", "0 <13>x"}, nil},
		{"oversized line is skipped", "<13>0123456789abc\n<13>ok\n", 10, []string{"<too large>", "<13>ok"}, nil},
		{"oversized last line", "<13>0123456789abc", 10, []string{"<too large>"}, nil},
		{"oversized octet frame is skipped", "16 <13>0123456789ab6 <13>ok", 10, []string{"<too large>", "<13>ok"}, nil},
		{"impossible octet count", "123456789 <13>x", 100, nil, errFraming},
		{"frame cut short", "20 <13>short", 100, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, mode := range []string{"whole", "one byte at a time", "half"} {
				var r io.Reader = strings.NewReader(c.in)
				switch mode {
				case "one byte at a time":
					r = iotest.OneByteReader(r)
				case "half":
					r = iotest.HalfReader(r)
				}
				got, err := frames(r, c.max)
				if !errors.Is(err, c.err) && !(c.err == nil && err == nil) {
					t.Errorf("%s: err = %v, want %v", mode, err, c.err)
				}
				if strings.Join(got, "|") != strings.Join(c.want, "|") {
					t.Errorf("%s: got %q, want %q", mode, got, c.want)
				}
			}
		})
	}
}

func TestFramingReturnsMessageBeforeError(t *testing.T) {
	r := io.MultiReader(strings.NewReader("<13>partial"), iotest.ErrReader(errors.New("idle")))
	f := newFramer(r, 100)
	if msg, err := f.Next(); err != nil || string(msg) != "<13>partial" {
		t.Fatalf("got %q, %v", msg, err)
	}
	if _, err := f.Next(); err == nil || err.Error() != "idle" {
		t.Errorf("second call: %v", err)
	}
	if _, err := f.Next(); err == nil {
		t.Error("error should stick")
	}
}
