// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Sed is a rex mode=sed expression: s/regex/replacement/flags replaces
// matches (the first, the Nth with a number flag, or all with g), and
// y/abc/xyz/ replaces each character of the first set with the one in
// the same place in the second.
type Sed struct {
	Y       bool
	Find    string // the regular expression, or y's first set
	Replace string // the replacement as written (\1 and & refer to the match), or y's second set
	Global  bool
	Nth     int // replace only the Nth match; 0 means the first, or all with Global
}

// MaxSedRefs caps the \1 and & references in a sed replacement, each of
// which can copy a whole match.
const MaxSedRefs = 10

// ParseSed reads a sed expression.
func ParseSed(expr string) (*Sed, error) {
	if len(expr) < 4 || (expr[0] != 's' && expr[0] != 'y') {
		return nil, fmt.Errorf(`expected s/regex/replacement/ or y/abc/xyz/`)
	}
	delim, size := utf8.DecodeRuneInString(expr[1:])
	if delim == utf8.RuneError || delim == '\\' || delim == ' ' || ('a' <= delim && delim <= 'z') || ('A' <= delim && delim <= 'Z') || ('0' <= delim && delim <= '9') {
		return nil, fmt.Errorf(`the character after %c must be a separator such as /`, expr[0])
	}
	// Split at unescaped separators; \<separator> stands for the separator.
	var parts []string
	var cur strings.Builder
	rest := expr[1+size:]
	for i := 0; i < len(rest); {
		r, n := utf8.DecodeRuneInString(rest[i:])
		switch {
		case r == '\\' && i+n < len(rest):
			r2, n2 := utf8.DecodeRuneInString(rest[i+n:])
			if r2 == delim {
				cur.WriteRune(delim)
			} else {
				cur.WriteRune('\\')
				cur.WriteRune(r2)
			}
			i += n + n2
			continue
		case r == delim && len(parts) < 2:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
		i += n
	}
	if len(parts) != 2 {
		return nil, fmt.Errorf(`expected %c%cfind%creplacement%c`, expr[0], delim, delim, delim)
	}
	s := &Sed{Y: expr[0] == 'y', Find: parts[0], Replace: parts[1]}
	flags := cur.String()
	if s.Y {
		if flags != "" {
			return nil, fmt.Errorf("y takes no flags")
		}
		if utf8.RuneCountInString(s.Find) != utf8.RuneCountInString(s.Replace) {
			return nil, fmt.Errorf("y needs as many characters in each set")
		}
		return s, nil
	}
	switch {
	case flags == "":
	case flags == "g":
		s.Global = true
	default:
		n, err := strconv.Atoi(flags)
		if err != nil || n < 1 || n > 10000 {
			return nil, fmt.Errorf("unknown flags %q; use g for every match or a number from 1 to 10000 for one match", flags)
		}
		if n > 1 {
			s.Nth = n
		}
	}
	if s.Find == "" {
		return nil, fmt.Errorf("the regular expression is empty")
	}
	if _, err := regexp.Compile(s.Find); err != nil {
		return nil, err
	}
	refs := strings.Count(s.Replace, "&") - strings.Count(s.Replace, `\&`)
	for i := 0; i+1 < len(s.Replace); i++ {
		if s.Replace[i] == '\\' {
			if c := s.Replace[i+1]; c >= '0' && c <= '9' {
				refs++
			}
			i++
		}
	}
	if refs > MaxSedRefs {
		return nil, fmt.Errorf("the replacement refers to the match more than %d times", MaxSedRefs)
	}
	return s, nil
}

// GoTemplate is the replacement as a template for regexp's Expand: \N is
// group N, & the whole match, \& and \\ an & and a backslash.
func (s *Sed) GoTemplate() string {
	var b strings.Builder
	r := s.Replace
	for i := 0; i < len(r); i++ {
		switch c := r[i]; {
		case c == '\\' && i+1 < len(r):
			n := r[i+1]
			switch {
			case n >= '0' && n <= '9':
				b.WriteString("${" + string(n) + "}")
			case n == '&' || n == '\\':
				b.WriteByte(n)
			case n == 'n':
				b.WriteByte('\n')
			case n == 't':
				b.WriteByte('\t')
			default:
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			i++
		case c == '&':
			b.WriteString("${0}")
		case c == '$':
			b.WriteString("$$")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
