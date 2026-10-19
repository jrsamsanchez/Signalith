// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// ShowHidden returns s with each character that hides or disguises text
// written as a visible marker such as ⟨U+202E⟩, the same way the web UI
// shows them. U+202E (right-to-left override), for example, makes
// "invoice\u202efdp.exe" look like "invoiceexe.pdf", and a zero-width space
// makes "adm\u200bin" look like "admin". Finding titles carry values from
// events, which anyone who can get a line into a log controls, and they
// travel beyond the UI (new case titles, exports, the API), so they are
// made safe where they are written.
func ShowHidden(s string) string {
	if !strings.ContainsFunc(s, hiddenRune) {
		return s
	}
	var b strings.Builder
	prev := rune(-1)
	for i, r := range s {
		next := rune(-1)
		if j := i + utf8.RuneLen(r); j < len(s) {
			next, _ = utf8.DecodeRuneInString(s[j:])
		}
		if hiddenRune(r) && !partOfScript(r, prev, next) {
			fmt.Fprintf(&b, "⟨U+%04X⟩", r)
		} else {
			b.WriteRune(r)
		}
		prev = r
	}
	return b.String()
}

// partOfScript reports whether a joiner or variation selector is doing
// its real job in emoji or in Persian, Arabic or Indic writing, where it
// is left alone; next to plain ASCII it has no business.
func partOfScript(r, prev, next rune) bool {
	switch {
	case r == 0x200c || r == 0x200d:
		return prev > 0x7f && next > 0x7f
	case r >= 0xfe00 && r <= 0xfe0f:
		return prev > 0x7f
	}
	return false
}

// hiddenRune reports whether r is invisible or changes how the text
// around it is laid out: control characters (other than tab and line
// breaks), bidi controls, zero-width and filler characters, and tag and
// variation characters. Keep in step with HIDDEN_CHAR in web/static/app.js.
func hiddenRune(r rune) bool {
	switch {
	case r < 0x20:
		return r != '\t' && r != '\n' && r != '\r'
	case r >= 0x7f && r <= 0x9f,
		r == 0xad, r == 0x34f, r == 0x61c, r == 0x115f, r == 0x1160, r == 0x17b4, r == 0x17b5,
		r >= 0x180b && r <= 0x180f,
		r >= 0x200b && r <= 0x200f,
		r >= 0x2028 && r <= 0x202e,
		r >= 0x2060 && r <= 0x2064,
		r >= 0x2066 && r <= 0x206f,
		r == 0x2800, r == 0x3164,
		r >= 0xfe00 && r <= 0xfe0f,
		r == 0xfeff, r == 0xffa0,
		r >= 0xfff9 && r <= 0xfffb,
		r >= 0x1d173 && r <= 0x1d17a,
		r >= 0xe0000 && r <= 0xe007f,
		r >= 0xe0100 && r <= 0xe01ef:
		return true
	}
	return false
}
