// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Notice is the sign-in notice (a system use notification, NIST SP 800-53
// AC-8): words an admin sets on the Sign-in notice tab of Settings, or in
// signalith.yaml (auth.notice), shown on the sign-in page before anyone
// signs in. It is plain text: the page shows it as typed, never as HTML.
// With Agree on, nobody signs in on the sign-in page (with a password, a
// passkey or single sign-on) without ticking that they agree to it. It is
// off while Text is empty. See docs/sign-in-notice.md.
type Notice struct {
	// Title is the notice's heading; empty is "Notice".
	Title string `yaml:"title,omitempty"`
	// Text is the notice. Line breaks are kept.
	Text string `yaml:"text,omitempty"`
	// Agree asks everyone to tick "I agree" before they sign in.
	Agree bool `yaml:"agree,omitempty"`
}

// The longest notice and title, in characters.
const (
	NoticeTextMax  = 4000
	NoticeTitleMax = 80
)

// NoticeOn reports whether the sign-in page shows a notice.
func (c *Config) NoticeOn() bool { return strings.TrimSpace(c.Auth.Notice.Text) != "" }

// NoticeAgree reports whether signing in on the sign-in page needs the
// notice agreed to.
func (c *Config) NoticeAgree() bool { return c.NoticeOn() && c.Auth.Notice.Agree }

// NoticeTitle is the notice's heading.
func (c *Config) NoticeTitle() string {
	if t := strings.TrimSpace(c.Auth.Notice.Title); t != "" {
		return t
	}
	return "Notice"
}

// NoticeText is the notice, with Windows line breaks made plain ones.
func (c *Config) NoticeText() string { return normalizeLines(c.Auth.Notice.Text) }

func normalizeLines(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n"))
}

// noticeChars refuses what would let a notice look like something else
// or hide words: control characters but line breaks and tabs (multiline),
// the invisible characters that reorder text (bidi controls), and other
// invisible ones, such as zero-width spaces.
func noticeChars(s string, multiline bool) error {
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			return errors.New("remove the character that isn't valid text")
		case multiline && (r == '\n' || r == '\t'):
		case unicode.IsControl(r):
			if multiline {
				return errors.New("remove the control character: only line breaks and tabs can be in the notice")
			}
			return errors.New("remove the line break, tab or other control character")
		case unicode.Is(unicode.Bidi_Control, r):
			return fmt.Errorf("remove the invisible character that changes the direction of the text (U+%04X)", r)
		case r == '\u200c' || r == '\u200d':
			// Joiners are part of emoji and of Persian and Indic writing.
		case unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp):
			return fmt.Errorf("remove the invisible character U+%04X", r)
		}
	}
	return nil
}

// checkNoticeText checks auth.notice.text from the page.
func checkNoticeText(v any) error {
	s := normalizeLines(v.(string))
	if n := utf8.RuneCountInString(s); n > NoticeTextMax {
		return fmt.Errorf("keep the notice to %d characters (it has %d)", NoticeTextMax, n)
	}
	return noticeChars(s, true)
}

// checkNoticeTitle checks auth.notice.title from the page.
func checkNoticeTitle(v any) error {
	s := v.(string)
	if n := utf8.RuneCountInString(s); n > NoticeTitleMax {
		return fmt.Errorf("keep the title to %d characters (it has %d)", NoticeTitleMax, n)
	}
	return noticeChars(s, false)
}

// noticeProblems checks auth.notice, as set in signalith.yaml too.
func (c *Config) noticeProblems() []string {
	n := c.Auth.Notice
	var p []string
	if err := checkNoticeText(n.Text); err != nil {
		p = append(p, "auth.notice.text: "+err.Error())
	}
	if err := checkNoticeTitle(strings.TrimSpace(n.Title)); err != nil {
		p = append(p, "auth.notice.title: "+err.Error())
	}
	if n.Agree && !c.NoticeOn() {
		p = append(p, "auth.notice.agree: write the notice people agree to first")
	}
	return p
}
