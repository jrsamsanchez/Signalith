package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"rsc.io/qr"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// Two-step sign-in (see users.MFA): the routes a user sets it up and
// turns it off with, the admin's reset, and what sign-in asks for.

func (s *Server) routeMFA(api *router) {
	api.self("GET /api/me/mfa", s.handleGetMFA)
	api.self("POST /api/me/mfa/setup", s.handleSetupMFA)
	api.self("POST /api/me/mfa/confirm", s.handleConfirmMFA)
	api.self("POST /api/me/mfa/recovery", s.handleNewRecoveryCodes)
	api.self("POST /api/me/mfa/off", s.handleMFAOff)
	api.sensitive("DELETE /api/users/{username}/mfa", s.handleResetMFA)
}

var (
	errMFANeeded = &signInError{status: http.StatusUnauthorized, code: "mfa_required",
		msg: "Enter the code from your authenticator app."}
	errWrongCode = &signInError{status: http.StatusUnauthorized, code: "mfa_wrong",
		msg: "That code isn't right, or was used already. Wait for a new code in your authenticator app, or use a recovery code."}
	errMFABasic = &signInError{status: http.StatusForbidden, code: "mfa_basic",
		msg: "This account uses two-step sign-in, so it cannot sign in with a password over the API (HTTP Basic). Use an API token, or sign in on the web page."}
	errMFAUnavailable = &signInError{status: http.StatusServiceUnavailable, code: "mfa_unavailable", retryAfter: 30 * time.Second,
		msg: "Signalith could not check the code just now. Try again in a minute."}
)

// mfaSource reports whether users of source can use two-step sign-in
// here: local users, the built-in admin and directory users, whose
// password Signalith checks. Anyone else (single sign-on) gets it from
// where they sign in.
func mfaSource(source string) bool {
	switch source {
	case users.SourceLocal, users.SourceBuiltin, users.SourceDirectory:
		return true
	}
	return false
}

// mfaRequired reports whether auth.mfa_required makes p use two-step
// sign-in.
func (s *Server) mfaRequired(p *principal) bool {
	if !mfaSource(p.Source) {
		return false
	}
	switch s.conf().MFARequiredMode() {
	case "everyone":
		return true
	case "admins":
		return p.Role == users.Admin
	}
	return false
}

// noteMFA sets p's two-step sign-in state: whether it is on, and whether
// p must set it up before anything else.
func (s *Server) noteMFA(p *principal) {
	if !mfaSource(p.Source) {
		return
	}
	p.MFA = s.userStore().MFAOn(p.Username)
	p.MustSetupMFA = !p.MFA && s.mfaRequired(p)
}

// secondStep checks the second step of a sign-in whose password was
// right: the code, when p has two-step sign-in. Signing in with a
// password over the API (Basic) is refused to anyone who has or needs
// it. It returns why it refused, for the log.
func (s *Server) secondStep(ctx context.Context, p *principal, method, code string) (string, error) {
	if p.breakGlass || !mfaSource(p.Source) {
		// The password signalith passwd -local wrote on this server, for
		// when the shared settings, and so the code, cannot be read.
		return "", nil
	}
	store := s.userStore()
	on := store.MFAOn(p.Username)
	if method == "basic" {
		if on {
			return "two-step sign-in is on, and Basic auth has no code", errMFABasic
		}
		if s.mfaRequired(p) {
			return "two-step sign-in is required, and Basic auth has no code", errMFABasic
		}
		return "", nil
	}
	if !on {
		return "", nil
	}
	if strings.TrimSpace(code) == "" {
		return "", errMFANeeded
	}
	res, err := store.UseMFACode(ctx, p.Username, code)
	switch {
	case errors.Is(err, users.ErrWrongCode):
		return "wrong two-step code", errWrongCode
	case err != nil:
		return "the two-step code could not be checked: " + err.Error(), errMFAUnavailable
	}
	p.codeUsed = &res
	return "", nil
}

// basicBlocked reports whether p may not use HTTP Basic auth, for a
// password checked earlier (the credentials cache).
func (s *Server) basicBlocked(p *principal) bool {
	return mfaSource(p.Source) && (s.userStore().MFAOn(p.Username) || s.mfaRequired(p))
}

// mfaWritable reports whether p's two-step sign-in can be changed here,
// answering when not.
func (s *Server) mfaWritable(w http.ResponseWriter, p *principal) bool {
	if !mfaSource(p.Source) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "mfa_elsewhere",
			"error": "Your account signs in through single sign-on, which asks for the second step itself."})
		return false
	}
	return s.usersWritable(w)
}

// mfaView is a user's two-step sign-in for the account menu.
func (s *Server) mfaView(p *principal) map[string]any {
	m, ok := s.userStore().MFA(p.Username)
	v := map[string]any{
		"on":       ok && m.On(),
		"required": s.mfaRequired(p),
		"possible": mfaSource(p.Source),
	}
	if ok && m.On() {
		v["since"] = m.Since
		v["recovery_left"] = len(m.Recovery)
		if m.Problem != "" {
			v["problem"] = "The key of your authenticator app cannot be decrypted here, so codes from the app are refused. " +
				"Sign in with a recovery code, turn two-step sign-in off and set it up again, or ask an admin to reset it."
		}
	}
	return v
}

func (s *Server) handleGetMFA(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mfaView(principalOf(r)))
}

// handleSetupMFA starts setting up two-step sign-in: a new key, as a QR
// code and as text to type, which a code from the app confirms
// (handleConfirmMFA) within users.SetupFor.
func (s *Server) handleSetupMFA(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if !s.mfaWritable(w, p) {
		return
	}
	secret, err := s.userStore().BeginMFA(changeContext(r), p.Username)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	link := users.OTPAuthURL("Signalith", accountLabel(p.Username, r), secret)
	svg, err := qrSVG(link)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		// In groups of four, to type into an app without a camera.
		"secret":     groupKey(secret),
		"otpauth":    link,
		"qr_svg":     svg,
		"expires_in": int(users.SetupFor.Seconds()),
	})
}

// handleConfirmMFA turns two-step sign-in on once a code from the app is
// right, and answers with the recovery codes, shown this once. Every
// other session of the user ends, everywhere.
func (s *Server) handleConfirmMFA(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.mfaWritable(w, p) {
		return
	}
	codes, err := s.userStore().ConfirmMFA(changeContext(r), p.Username, req.Code)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	ended := s.renewSession(w, r, p)
	s.audit(r, "two-step sign-in turned on", "user", p.Username, "other_sessions_ended", ended)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes, "mfa": s.mfaView(p)})
}

// handleNewRecoveryCodes replaces the user's recovery codes, once a code
// shows they still have their app (or a recovery code).
func (s *Server) handleNewRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.mfaWritable(w, p) || !s.checkOwnCode(w, r, p, req.Code) {
		return
	}
	codes, err := s.userStore().NewRecoveryCodes(changeContext(r), p.Username)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	s.audit(r, "new recovery codes made", "user", p.Username)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes, "mfa": s.mfaView(p)})
}

// handleMFAOff turns the user's two-step sign-in off, once a code shows
// they have their app (or a recovery code). Where it is required, they
// are asked to set it up again at once.
func (s *Server) handleMFAOff(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.mfaWritable(w, p) {
		return
	}
	if !s.userStore().MFAOn(p.Username) {
		// Stopping a set-up that was never confirmed needs no code.
		if _, err := s.userStore().RemoveMFA(changeContext(r), p.Username); err != nil {
			s.writeMFAError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"mfa": s.mfaView(p)})
		return
	}
	if !s.checkOwnCode(w, r, p, req.Code) {
		return
	}
	if _, err := s.userStore().RemoveMFA(changeContext(r), p.Username); err != nil {
		s.writeMFAError(w, err)
		return
	}
	s.audit(r, "two-step sign-in turned off", "user", p.Username)
	writeJSON(w, http.StatusOK, map[string]any{"mfa": s.mfaView(p)})
}

// checkOwnCode checks a code the signed-in user p entered to change their
// own two-step sign-in. A wrong one counts toward the sign-in limits,
// like a wrong code at sign-in; it answers and returns false when the
// code is not right.
func (s *Server) checkOwnCode(w http.ResponseWriter, r *http.Request, p *principal, code string) bool {
	from := s.client(r)
	attempt, err := s.beginAttempt(r, from, p.Username, sessionBrowser(p))
	if err != nil {
		writeSignInError(w, err)
		return false
	}
	res, err := s.userStore().UseMFACode(changeContext(r), p.Username, code)
	switch {
	case errors.Is(err, users.ErrWrongCode):
		f := attempt.Fail()
		s.Log.Warn("two-step code refused", append(append([]any{"audit", true, "user", p.Username}, from.logAttrs()...),
			"locked_out", f.LockedOut())...)
		s.noteFailure(from, f)
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "mfa_wrong", "field": "code",
			"error": "That code isn't right, or was used already. Wait for a new code in your authenticator app, or use a recovery code."})
		return false
	case err != nil:
		attempt.Done()
		s.writeMFAError(w, err)
		return false
	}
	attempt.Succeed()
	if res.Kind == users.CodeRecovery {
		s.audit(r, "recovery code used", "user", p.Username, "recovery_codes_left", res.Left)
	}
	return true
}

// handleResetMFA turns another user's two-step sign-in off, for someone
// who lost their phone and their recovery codes. Where it is required,
// they set it up again at their next sign-in. Their sessions are left as
// they are: they signed in with it.
func (s *Server) handleResetMFA(w http.ResponseWriter, r *http.Request) {
	name := targetName(r)
	if !s.usersWritable(w) {
		return
	}
	if strings.EqualFold(name, userOf(r)) {
		writeError(w, http.StatusConflict, errors.New("turn off your own two-step sign-in from the account menu, with a code from your app"))
		return
	}
	if !s.isBuiltin(name) {
		u, ok := s.userStore().Get(name)
		if !ok {
			writeUserError(w, users.ErrNotFound)
			return
		}
		name = u.Username
	} else {
		name = s.builtinName()
	}
	had, err := s.userStore().RemoveMFA(changeContext(r), name)
	if err != nil {
		s.writeMFAError(w, err)
		return
	}
	if had {
		s.audit(r, "two-step sign-in reset", "user", name)
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": name, "mfa": false})
}

// writeMFAError answers a failed change of two-step sign-in.
func (s *Server) writeMFAError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, users.ErrWrongCode):
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "mfa_wrong", "field": "code", "error": "That code isn't right. Check the app shows Signalith, and try the next code."})
	case errors.Is(err, users.ErrNoSetup):
		writeJSON(w, http.StatusConflict, map[string]any{"code": "mfa_no_setup", "error": err.Error()})
	case errors.Is(err, users.ErrMFAOn), errors.Is(err, users.ErrMFAOff):
		writeJSON(w, http.StatusConflict, map[string]any{"code": "mfa_state", "error": err.Error()})
	case errors.Is(err, users.ErrNoBuiltinMFA):
		writeJSON(w, http.StatusConflict, map[string]any{"code": "mfa_unavailable", "error": "Two-step sign-in for the built-in admin cannot be changed on this server now."})
	default:
		writeUserError(w, err)
	}
}

// renewSession ends every other session of p after a change that moved
// their session epoch on (or should end them), and returns how many
// ended. With shared users that ends this one too, so it gets a new
// session in the new epoch.
func (s *Server) renewSession(w http.ResponseWriter, r *http.Request, p *principal) int {
	keep := p.token
	if s.SharedUsers != nil && p.Method == "session" && p.token != "" {
		if np := s.principalFor(p.Username); np != nil {
			token, err := s.startSession(r, np, p.remember)
			if err != nil {
				s.Log.Warn("no new session could be started; sign in again", "user", p.Username, "err", err)
			} else {
				s.setSessionCookie(w, r, token, p.remember)
				s.sessions().Delete(r.Context(), p.token)
				keep = token
			}
		}
	}
	return s.sessions().EndUser(r.Context(), p.Username, keep)
}

// sessionBrowser names the session p signed in with, for the sign-in
// limits: a signed-in session counts as a browser of its own.
func sessionBrowser(p *principal) string {
	if p.token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(p.token))
	return "session:" + hex.EncodeToString(sum[:12])
}

// accountLabel names the account in the authenticator app: the user at
// this server's host, so two servers' entries can be told apart.
func accountLabel(name string, r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return name
	}
	return name + "@" + host
}

// groupKey writes a key in groups of four letters, for typing.
func groupKey(k string) string {
	var sb strings.Builder
	for i, r := range k {
		if i > 0 && i%4 == 0 {
			sb.WriteByte(' ')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// qrSVG draws text as a QR code in SVG, black on white with the quiet
// zone around it, so a phone reads it in a dark theme too.
func qrSVG(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := c.Size + 2*quiet
	var path strings.Builder
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`+
		`<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="%s"/></svg>`, n, n, n, n, path.String()), nil
}
