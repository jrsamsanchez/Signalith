// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"html"
	"net/http"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// The sign-in notice (config.Notice, docs/sign-in-notice.md): a system use
// notification an admin sets on the Sign-in notice tab of Settings, shown
// on the sign-in page as plain text. With auth.notice.agree on, each way
// in from the sign-in page (a password, a passkey, single sign-on and the
// public demo's button) is refused until the person ticks I agree, here on
// the server as well as on the page, and the sign-in is logged with
// notice=agreed. API tokens and HTTP Basic auth are for scripts, which
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
