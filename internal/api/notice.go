// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// The sign-in notice (config.Notice, docs/sign-in-notice.md): a system use
// notification an admin sets on the Sign-in notice tab of Settings, shown
// on the sign-in page as plain text. With auth.notice.agree on, each way
// in from the sign-in page (a password, a passkey, single sign-on and the
// public demo's button) is refused until the person ticks I agree, here on
// the server as well as on the page, and the sign-in is logged with
// notice=agreed. Single sign-on starts with a link rather than a form, so
// its start counts the tick only from a page of this site
// (ssoNoticeAgreed). API tokens and HTTP Basic auth are for scripts, which
// read no page, and are not asked.

const noticeViewRoute = "GET /api/auth/notice"

// errNoticeNotAgreed is the answer to a sign-in sent without agreeing to
// the notice. It is no guess at a password, so it counts toward no limit.
var errNoticeNotAgreed = &signInError{status: http.StatusBadRequest, code: "notice_not_agreed",
	msg: "Read the notice and tick I agree to sign in."}

func (s *Server) routeNotice(api *router) {
	// The Sign-in notice tab of Settings.
	api.admin(noticeViewRoute, s.handleNoticeView)
}

// noticeRefused reports whether a sign-in from the sign-in page must be
// refused because the notice was not agreed to, and answers it.
func (s *Server) noticeRefused(w http.ResponseWriter, agreed bool) bool {
	if agreed || !s.conf().NoticeAgree() {
		return false
	}
	writeSignInError(w, errNoticeNotAgreed)
	return true
}

// noticeLog is what a sign-in from the sign-in page adds to its "signed
// in" line: that the person agreed to the notice, when it asks them to.
func (s *Server) noticeLog() []any {
	if s.conf().NoticeAgree() {
		return []any{"notice", "agreed"}
	}
	return nil
}

// ssoNoticeLog is noticeLog for a single sign-on, which ends on another
// request than the one that checked the notice: agreed comes from the
// sign-in under way, not from the setting now.
func ssoNoticeLog(agreed bool) []any {
	if agreed {
		return []any{"notice", "agreed"}
	}
	return nil
}

// noticeHopPurpose keys the mark that a single sign-on start passes on
// through the hop to the public address: the notice was agreed to.
const noticeHopPurpose = "sign-in notice hop"

// noticeHopWait is how long that mark is good for.
const noticeHopWait = 2 * time.Minute

// ssoNoticeAgreed reports whether a single sign-on start comes with the
// notice agreed to. The sign-in page's link carries agreed=1 once I agree
// is ticked, but a link is easy to copy: an identity provider's tile, a
// bookmark or a link someone sent would sign in without the notice
// shown. So agreed=1 counts only when the browser says the link was
// followed from a page of this same site (Sec-Fetch-Site; a browser too
// old to send it is taken at its word), or, after the hop to the public
// address, with the signed mark the first start gave it.
func (s *Server) ssoNoticeAgreed(r *http.Request) bool {
	q := r.URL.Query()
	if q.Get("agreed") != "1" {
		return false
	}
	if q.Get("hop") != "" {
		return s.noticeHopOK(q.Get("notice"), time.Now())
	}
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin"
}

// noticeHop is the mark for the hop to the public address, good until
// noticeHopWait from now.
func (s *Server) noticeHop(now time.Time) string {
	exp := strconv.FormatInt(now.Add(noticeHopWait).Unix(), 10)
	return exp + "." + base64.RawURLEncoding.EncodeToString(s.browserKey().MAC(noticeHopPurpose, []byte(exp)))
}

// noticeHopOK checks a mark noticeHop made.
func (s *Server) noticeHopOK(v string, now time.Time) bool {
	exp, mac, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(mac)
	if err != nil || !hmac.Equal(got, s.browserKey().MAC(noticeHopPurpose, []byte(exp))) {
		return false
	}
	t, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && now.Unix() <= t
}

// noticePage fills the sign-in page's notice, hidden while there is none.
// The title and text are escaped, so they show as typed and nothing in
// them is read as HTML.
func noticePage(page []byte, c *config.Config) []byte {
	if !c.NoticeOn() {
		return page
	}
	page = bytes.Replace(page, []byte(`id="notice" hidden`), []byte(`id="notice"`), 1)
	page = bytes.Replace(page, []byte(`<h2 class="auth__notice-title" id="notice-title">Notice</h2>`),
		[]byte(`<h2 class="auth__notice-title" id="notice-title">`+html.EscapeString(c.NoticeTitle())+`</h2>`), 1)
	page = bytes.Replace(page, []byte(`<div class="auth__notice-text" id="notice-text" tabindex="0"></div>`),
		[]byte(`<div class="auth__notice-text" id="notice-text" tabindex="0">`+html.EscapeString(c.NoticeText())+`</div>`), 1)
	if c.NoticeAgree() {
		page = bytes.Replace(page, []byte(`id="notice-agree" hidden`), []byte(`id="notice-agree"`), 1)
	}
	return page
}

// handleNoticeView is what the Sign-in notice tab shows: the saved notice
// and whether the page can change it.
func (s *Server) handleNoticeView(w http.ResponseWriter, r *http.Request) {
	saved, err := s.savedSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	n := saved.Config.Auth.Notice
	writeJSON(w, http.StatusOK, map[string]any{
		"title":     n.Title,
		"text":      saved.Config.NoticeText(),
		"agree":     n.Agree,
		"on":        s.conf().NoticeOn(),
		"text_max":  config.NoticeTextMax,
		"title_max": config.NoticeTitleMax,
		"editable":  s.Config.Path() != "",
	})
}
