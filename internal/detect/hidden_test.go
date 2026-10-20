// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import "testing"

// TestRenderTitleShowsHiddenCharacters reproduces xss-bidi-spoof's finding
// title: a value from an event with U+202E made "bob\u202egnp.exe" read as
// "bobexe.png" in the findings queue and in the title of a case opened
// from it.
func TestRenderTitleShowsHiddenCharacters(t *testing.T) {
	row := map[string]any{
		"user": "bob\u202egnp.exe",
		"src":  "\u202e10.0.0.5",
		"host": "adm\u200bin-pc",
	}
	got := RenderTitle("Failed logons for $user$ from $src$ on $host$", row)
	want := "Failed logons for bob⟨U+202E⟩gnp.exe from ⟨U+202E⟩10.0.0.5 on adm⟨U+200B⟩in-pc"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestShowHidden(t *testing.T) {
	for in, want := range map[string]string{
		"plain text, tabs\tand\nlines": "plain text, tabs\tand\nlines",
		"x\u2066y\u2069":               "x⟨U+2066⟩y⟨U+2069⟩",
		"\ufeffBOM":                    "⟨U+FEFF⟩BOM",
		"bell\x07 and esc\x1b[31m":     "bell⟨U+0007⟩ and esc⟨U+001B⟩[31m",
		"tag\U000E0041":                "tag⟨U+E0041⟩",
		"\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645": "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", // Persian keeps its joiner
		"\U0001F469\u200d\U0001F4BB":                       "\U0001F469\u200d\U0001F4BB",                       // an emoji sequence
		"\u2764\ufe0f":                                     "\u2764\ufe0f",                                     // emoji presentation
		"ad\u200dmin":                                      "ad⟨U+200D⟩min",                                    // between ASCII letters
		"a\ufe0f":                                          "a⟨U+FE0F⟩",
		"\u65e5\u672c\u8a9e\u306e\u30c6\u30ad\u30b9\u30c8": "\u65e5\u672c\u8a9e\u306e\u30c6\u30ad\u30b9\u30c8",
	} {
		if got := ShowHidden(in); got != want {
			t.Errorf("ShowHidden(%q) = %q, want %q", in, got, want)
		}
	}
}
