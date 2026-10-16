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
	default:
		v["error"] = "Enter your password to make this change."
		v["with"] = "password"
	}
	writeJSON(w, http.StatusForbidden, v)
	return true
}

// handleRecheck takes the password, or a two-step code, again. Wrong
// ones count toward the sign-in limits.
func (s *Server) handleRecheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := principalOf(r)
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
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
	if code == "" && req.Password == "" {
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
	if code != "" {
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
// sign in or how traffic is protected; saving one asks for the password
// or code again. A name ending in . covers every setting under it.
var protectedSettings = []string{"auth.", "server.tls.", "server.trusted_proxies", "server.client_header",
	"server.shared_addresses", "server.proxy_protocol", "syslog.allow"}

func protectedSetting(key string) bool {
	for _, p := range protectedSettings {
		if key == p || (strings.HasSuffix(p, ".") && strings.HasPrefix(key, p)) {
			return true
		}
	}
	return false
}

// settingsSaveRecheck reports whether a Settings page save (body raw)
// changes a protected setting, or puts every setting back.
func settingsSaveRecheck(raw json.RawMessage) bool {
	var b settingsRequest
	if json.Unmarshal(raw, &b) != nil || b.CheckOnly {
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
