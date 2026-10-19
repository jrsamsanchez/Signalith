// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Sensitive changes (making tokens, changing users and roles, turning
// protections off) ask a user signed in with a session to enter their
// password or two-step code again when they have not in the last
// auth.RecheckAge: someone at an unlocked computer, or holding a stolen
// session cookie, cannot make them. Signing in counts; so does
// POST /api/me/recheck, which sets a cookie bound to the session.

// The cookie that says the password or code was entered again, like the
// session cookie: __Host- over HTTPS.
const (
	recheckCookie       = "signalith_recheck"
	secureRecheckCookie = "__Host-signalith_recheck"
)

func (s *Server) recheckCookieName(r *http.Request) string {
	if s.secureCookie(r) {
		return secureRecheckCookie
	}
	return recheckCookie
}

// sensitive registers an admin route that asks for the password or code
// again (see recheckNeeded).
func (rt *router) sensitive(pattern string, h http.HandlerFunc) {
	rt.add(route{Pattern: pattern, Role: users.Admin, Recheck: true}, h)
}

// selfSensitive registers a route about the signed-in user that asks for
// the password or code again, like sensitive.
func (rt *router) selfSensitive(pattern string, h http.HandlerFunc) {
	rt.add(route{Pattern: pattern, Role: users.Viewer, Anytime: true, Recheck: true}, h)
}

// viewerSensitive registers a route every signed-in user may use that
// asks for the password or code again, like sensitive.
func (rt *router) viewerSensitive(pattern string, h http.HandlerFunc) {
	rt.add(route{Pattern: pattern, Role: users.Viewer, Recheck: true}, h)
}

func (s *Server) routeRecheck(api *router) {
	api.self("POST /api/me/recheck", s.handleRecheck)
}

// rechecked reports whether p entered their password or code in the last
// auth.RecheckAge. Requests that sent the password themselves (HTTP
// Basic) count as rechecked; API tokens only read.
func (s *Server) rechecked(r *http.Request, p *principal) bool {
	if p.Method != "session" {
		return true
	}
	now := time.Now()
	if !p.signedIn.IsZero() && now.Sub(p.signedIn) < auth.RecheckAge {
		return true
	}
	c, err := r.Cookie(s.recheckCookieName(r))
	return err == nil && s.browserKey().CheckRecheck(p.Username, p.token, c.Value, now)
}

// recheckNeeded answers 403 recheck_required and returns true when p
// must enter their password or code again first.
func (s *Server) recheckNeeded(w http.ResponseWriter, r *http.Request, p *principal) bool {
	if s.rechecked(r, p) {
		return false
	}
	v := map[string]any{"code": "recheck_required", "minutes": int(auth.RecheckAge.Minutes())}
	switch {
	case !mfaSource(p.Source):
		v["error"] = "Sign in again to make this change."
		v["with"] = "sign_in"
	case s.userStore().MFAOn(p.Username):
		v["error"] = "Enter your password or a code from your authenticator app to make this change."
		v["with"] = "password_or_code"
		m, _ := s.userStore().MFA(p.Username)
		if !m.AppOn() {
			v["error"] = "Enter your password or a recovery code to make this change."
		}
		if len(m.Passkeys) > 0 {
			if here, why := s.passkeyPlace(r); why == "" && len(passkeyUserOf(p.Username, m, here).keys) > 0 {
				v["error"] = "Use your passkey, or enter your password, to make this change."
				v["passkey"] = true
			}
		}
	default:
		v["error"] = "Enter your password to make this change."
		v["with"] = "password"
	}
	writeJSON(w, http.StatusForbidden, v)
	return true
}

// handleRecheck takes the password, a two-step code or a passkey again.
// Wrong ones count toward the sign-in limits.
func (s *Server) handleRecheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := principalOf(r)
	var req struct {
		Password string         `json:"password"`
		Code     string         `json:"code"`
		Passkey  *passkeyAnswer `json:"passkey"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if p.Method != "session" {
		writeJSON(w, http.StatusOK, map[string]any{"minutes": int(auth.RecheckAge.Minutes())})
		return
	}
	if !mfaSource(p.Source) {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "recheck_sign_in",
			"error": "Signalith does not check your password, so sign out and sign in again instead."})
		return
	}
	code := strings.TrimSpace(req.Code)
	if code == "" && req.Password == "" && req.Passkey == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "wrong_password", "field": "password",
			"error": "Enter your password."})
		return
	}
	from := s.client(r)
	attempt, err := s.beginAttempt(r, from, p.Username, sessionBrowser(p))
	if err != nil {
		writeSignInError(w, err)
		return
	}
	with := "password"
	if req.Passkey != nil {
		_, err := s.checkPasskey(r, ceremonyCheck, p.Username, p.token, req.Passkey)
		var se *signInError
		switch {
		case errors.Is(err, errPasskeyWrong), errors.Is(err, errPasskeyCloned):
			f := attempt.Fail()
			s.Log.Warn("recheck refused", slices.Concat([]any{"audit", true, "user", p.Username}, from.logAttrs(),
				[]any{"reason", "passkey not accepted", "locked_out", f.LockedOut()})...)
			s.noteFailure(from, f)
			writeSignInError(w, err)
			return
		case errors.As(err, &se):
			attempt.Done()
			writeSignInError(w, err)
			return
		case err != nil:
			attempt.Done()
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		with = string(users.CodePasskey)
	} else if code != "" {
		res, err := s.userStore().UseMFACode(changeContext(r), p.Username, code)
		switch {
		case errors.Is(err, users.ErrWrongCode), errors.Is(err, users.ErrMFAOff):
			f := attempt.Fail()
			s.Log.Warn("recheck refused", slices.Concat([]any{"audit", true, "user", p.Username}, from.logAttrs(),
				[]any{"reason", "wrong two-step code", "locked_out", f.LockedOut()})...)
			s.noteFailure(from, f)
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": "mfa_wrong", "field": "code",
				"error": "That code isn't right, or was used already. Wait for a new code in your authenticator app."})
			return
		case err != nil:
			attempt.Done()
			s.writeMFAError(w, err)
			return
		}
		with = string(res.Kind)
	} else {
		q, reason, err := s.checkCredentials(changeContext(r), p.Username, req.Password)
		if err == nil && !strings.EqualFold(q.Username, p.Username) {
			reason, err = "the password is another account's", errWrongCredentials
		}
		if err != nil {
			if !errors.Is(err, errWrongCredentials) {
				// An unreachable directory, or an account that may no
				// longer sign in: no guess was refused.
				attempt.Done()
				writeSignInError(w, err)
				return
			}
			f := attempt.Fail()
			s.Log.Warn("recheck refused", slices.Concat([]any{"audit", true, "user", p.Username}, from.logAttrs(),
				[]any{"reason", reason, "locked_out", f.LockedOut()})...)
			s.noteFailure(from, f)
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": "wrong_password", "field": "password",
				"error": "That password isn't right."})
			return
		}
	}
	attempt.Succeed()
	http.SetCookie(w, &http.Cookie{Name: s.recheckCookieName(r), Value: s.browserKey().IssueRecheck(p.Username, p.token, time.Now()),
		Path: "/", MaxAge: int(auth.RecheckAge.Seconds()), HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.secureCookie(r)})
	s.audit(r, "password or code entered again", "user", p.Username, "with", with)
	writeJSON(w, http.StatusOK, map[string]any{"minutes": int(auth.RecheckAge.Minutes())})
}

// protectedSettings are the settings whose change can weaken how people
// sign in, how traffic is protected, or where events and secrets go;
// saving one asks for the password or code again. syslog.udp and
// syslog.tcp are here because plain syslog takes unencrypted events that
// can be forged. Each covers the setting
// of that name and those under it (auth covers auth.oidc.issuer, and
// server.tls covers server.tls_cert).
var protectedSettings = []string{"auth", "server.tls", "server.listen", "server.trusted_proxies", "server.client_header",
	"server.shared_addresses", "server.proxy_protocol", "opensearch", "cluster.opensearch_url", "syslog.allow",
	"syslog.tls", "syslog.udp", "syslog.tcp", "syslog.proxy_protocol", "intel.allow_loopback_feeds", "assistant.url", "assistant.mask_fields", "okta", "m365"}

func protectedSetting(key string) bool {
	for _, p := range protectedSettings {
		if rest, ok := strings.CutPrefix(key, p); ok && (rest == "" || rest[0] == '.' || rest[0] == '_') {
			return true
		}
	}
	return false
}

// settingsSaveRecheck reports whether a Settings page save (body raw)
// changes a protected setting, or puts every setting back.
func settingsSaveRecheck(raw json.RawMessage) bool {
	var b settingsRequest
	if json.Unmarshal(raw, &b) != nil {
		// Asked for whatever it holds; the save refuses it anyway.
		return true
	}
	if b.CheckOnly {
		return false
	}
	if b.ResetAll {
		return true
	}
	for k := range b.Values {
		if protectedSetting(k) {
			return true
		}
	}
	return slices.ContainsFunc(b.Clear, protectedSetting) || slices.ContainsFunc(b.Reset, protectedSetting) ||
		slices.ContainsFunc(b.Retry, protectedSetting)
}
