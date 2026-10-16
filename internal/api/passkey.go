package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Passkeys (see users.Passkey): the routes a user adds and removes them
// with, and the checks behind signing in with one. A passkey is the
// second step after the password for anyone with two-step sign-in, and
// signs local users and the built-in admin in on its own. Directory
// users always give their directory password first, so the directory
// still decides whether they may sign in.

const (
	// passkeyWait is how long the browser and the user have to answer.
	passkeyWait = 5 * time.Minute
	// passkeyAnswerMax is the most a passkey answer may weigh.
	passkeyAnswerMax = 64 << 10
)

func (s *Server) routePasskeys(api *router) {
	// Adding one with a stolen session would let its holder in later:
	// it asks for the password or code again unless they just signed in.
	api.selfSensitive("POST /api/me/passkeys/options", s.handlePasskeyOptions)
	api.selfSensitive("POST /api/me/passkeys", s.handleAddPasskey)
	api.selfSensitive("DELETE /api/me/passkeys/{id}", s.handleRemovePasskey)
	// A challenge to answer with a passkey instead of a code (confirming
	// it's you, new recovery codes, turning the app off).
	api.self("POST /api/me/passkeys/challenge", s.handlePasskeyChallenge)
}

// The routes that sign in with a passkey alone, which work without
// signing in.
const (
	passkeyLoginOptionsRoute = "POST /api/login/passkey/options"
	passkeyLoginRoute        = "POST /api/login/passkey"
)

var passkeyPublicRoutes = []string{passkeyLoginOptionsRoute, passkeyLoginRoute}

func (s *Server) routePasskeyLogin(mux *http.ServeMux) {
	mux.HandleFunc(passkeyLoginOptionsRoute, s.handlePasskeyLoginOptions)
	mux.Handle(passkeyLoginRoute, s.configToken(true, http.HandlerFunc(s.handlePasskeyLogin)))
}

var (
	errPasskeyWrong = &signInError{status: http.StatusUnauthorized, code: "passkey_wrong",
		msg: "That passkey didn't work. Try again, or sign in another way."}
	errPasskeyExpired = &signInError{status: http.StatusUnauthorized, code: "passkey_expired",
		msg: "That took too long. Try the passkey again."}
	errPasskeyCloned = &signInError{status: http.StatusUnauthorized, code: "passkey_cloned",
		msg: "This passkey was refused because it may have been copied. Sign in another way, then remove it from your account."}
	errPasskeyPassword = &signInError{status: http.StatusUnauthorized, code: "passkey_password",
		msg: "Your account signs in with your directory password first. Enter it, then use your passkey."}
)

// passkeyAnswer is what the browser sends back from a passkey ceremony:
// the token the server gave with the challenge, and the credential.
type passkeyAnswer struct {
	Token      string          `json:"token"`
	Credential json.RawMessage `json:"credential"`
}

// secondFactor is the second step sent with a password: a code, or a
// passkey's answer.
type secondFactor struct {
	Code    string
	Passkey *passkeyAnswer
}

// passkeyHere is where passkeys can be used for a request: the host name
// the browser used (the relying party ID) and its origin. Browsers allow
// passkeys only over HTTPS, or on localhost, and never for an IP
// address. The host name comes from the request: a passkey made on one
// host is bound to it, and only offered and accepted there, so a request
// that names another host gets nothing out of it.
type passkeyHere struct {
	rpID, origin string
}

// passkeyPlace returns where passkeys can be used for r, or why not, in
// words for the account menu.
func (s *Server) passkeyPlace(r *http.Request) (passkeyHere, string) {
	host := strings.ToLower(r.Host)
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.TrimSuffix(strings.Trim(name, "[]"), ".")
	local := name == "localhost" || strings.HasSuffix(name, ".localhost")
	switch {
	case name == "" || net.ParseIP(name) != nil:
		return passkeyHere{}, "Passkeys work only when Signalith is opened by its name (such as https://siem.example.com), not by an IP address."
	case !s.overHTTPS(r) && !local:
		return passkeyHere{}, "Passkeys work only over HTTPS."
	}
	scheme := "https"
	if !s.overHTTPS(r) {
		scheme = "http"
	}
	return passkeyHere{rpID: name, origin: scheme + "://" + host}, ""
}

func (h passkeyHere) relyingParty() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID: h.rpID, RPDisplayName: "Signalith", RPOrigins: []string{h.origin},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyWait, TimeoutUVD: passkeyWait},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyWait, TimeoutUVD: passkeyWait},
		},
	})
}

// passkeyUser is a user as the WebAuthn library sees them: their user
// handle and the passkeys they made on this host.
type passkeyUser struct {
	name   string
	handle []byte
	keys   []users.Passkey
}

func passkeyUserOf(name string, m users.MFA, here passkeyHere) passkeyUser {
	u := passkeyUser{name: name, handle: m.Handle}
	for _, k := range m.Passkeys {
		if k.RPID == here.rpID {
			u.keys = append(u.keys, k)
		}
	}
	return u
}

func (u passkeyUser) WebAuthnID() []byte          { return u.handle }
func (u passkeyUser) WebAuthnName() string        { return u.name }
func (u passkeyUser) WebAuthnDisplayName() string { return u.name }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.keys))
	for _, k := range u.keys {
		c := webauthn.Credential{ID: k.ID, PublicKey: k.PublicKey,
			Flags:         webauthn.CredentialFlags{UserPresent: true, UserVerified: k.Verified, BackupEligible: k.BackupEligible, BackupState: k.BackupState},
			Authenticator: webauthn.Authenticator{AAGUID: k.AAGUID, SignCount: k.SignCount}}
		for _, t := range k.Transports {
			c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
		}
		out = append(out, c)
	}
	return out
}

func (u passkeyUser) descriptors() []protocol.CredentialDescriptor {
	var out []protocol.CredentialDescriptor
	for _, c := range u.WebAuthnCredentials() {
		out = append(out, c.Descriptor())
	}
	return out
}

// The kinds of passkey ceremony. Each token is bound to its kind, and to
// the account and session it was made for, so it works for nothing else.
const (
	ceremonyAdd   = "add"   // adding a passkey, in a session
	ceremonyLogin = "login" // signing in with a passkey alone
	ceremonyStep  = "step"  // the second step after a password
	ceremonyCheck = "check" // confirming it's you, in a session
)

func ceremonyPurpose(kind, account, session string) string {
	sum := sha256.Sum256([]byte(session))
	return "passkey\x00" + kind + "\x00" + strings.ToLower(account) + "\x00" + hex.EncodeToString(sum[:])
}

// sealCeremony returns the token that carries sd to the ceremony's end.
func (s *Server) sealCeremony(purpose string, sd *webauthn.SessionData) (string, error) {
	b, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}
	return s.browserKey().SealState(purpose, b, time.Now().Add(passkeyWait)), nil
}

// openCeremony returns what sealCeremony sealed, if the token is good
// for purpose, has not expired, and was made for the host here.
func (s *Server) openCeremony(purpose, token string, here passkeyHere) (webauthn.SessionData, error) {
	var sd webauthn.SessionData
	b, ok := s.browserKey().OpenState(purpose, token, time.Now())
	if !ok {
		return sd, errPasskeyExpired
	}
	if err := json.Unmarshal(b, &sd); err != nil || sd.RelyingPartyID != here.rpID {
		return sd, errPasskeyExpired
	}
	return sd, nil
}

// challengeSet remembers the challenges answered on this server until
// they expire, so an answer seen once is refused after. It is a quick
// first check: the user's record (users.UsePasskey) is what refuses an
// answer on every server, and after a restart.
type challengeSet struct {
	mu     sync.Mutex
	used   map[string]time.Time
	pruned time.Time
}

// spend reports whether challenge was not answered yet, and remembers it
// until until.
func (c *challengeSet) spend(challenge string, until time.Time) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.used == nil {
		c.used = map[string]time.Time{}
	}
	if now.Sub(c.pruned) > time.Minute {
		c.pruned = now
		for k, t := range c.used {
			if now.After(t) {
				delete(c.used, k)
			}
		}
	}
	if _, seen := c.used[challenge]; seen {
		return false
	}
	c.used[challenge] = until
	return true
}

// spentUntil is how long an answered challenge is remembered: past the
// end of any token that can carry it, whenever that was made.
func spentUntil() time.Time { return time.Now().Add(passkeyWait + time.Minute) }

// assertionOptions begins a passkey check for name (one of their
// passkeys made here), for a ceremony of kind in session.
func (s *Server) assertionOptions(here passkeyHere, kind, name, session string, m users.MFA) (map[string]any, error) {
	wa, err := here.relyingParty()
	if err != nil {
		return nil, err
	}
	u := passkeyUserOf(name, m, here)
	if len(u.keys) == 0 {
		return nil, nil
	}
	// Confirming it's you stands in for the password, so the passkey must
	// check who is there, as signing in with one alone does.
	uv := protocol.VerificationPreferred
	if kind == ceremonyCheck {
		uv = protocol.VerificationRequired
	}
	opts, sd, err := wa.BeginLogin(u, webauthn.WithUserVerification(uv))
	if err != nil {
		return nil, err
	}
	token, err := s.sealCeremony(ceremonyPurpose(kind, name, session), sd)
	if err != nil {
		return nil, err
	}
	return map[string]any{"publicKey": opts.Response, "token": token}, nil
}

// checkPasskey checks a's answer for name against a ceremony of kind in
// session, and records the use. It returns the passkey and the
// authenticator's flags.
func (s *Server) checkPasskey(r *http.Request, kind, name, session string, a *passkeyAnswer) (users.Passkey, error) {
	here, why := s.passkeyPlace(r)
	if why != "" || a == nil || len(a.Credential) > passkeyAnswerMax {
		return users.Passkey{}, errPasskeyWrong
	}
	sd, err := s.openCeremony(ceremonyPurpose(kind, name, session), a.Token, here)
	if err != nil {
		return users.Passkey{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(a.Credential)
	if err != nil {
		return users.Passkey{}, errPasskeyWrong
	}
	wa, err := here.relyingParty()
	if err != nil {
		return users.Passkey{}, err
	}
	m, _ := s.userStore().MFA(name)
	u := passkeyUserOf(name, m, here)
	if _, err := wa.ValidateLogin(u, sd, parsed); err != nil {
		return users.Passkey{}, errPasskeyWrong
	}
	return s.usePasskey(r, name, sd, parsed)
}

// usePasskey records a passkey use that checked out: the challenge is
// spent, and the counter moves on.
func (s *Server) usePasskey(r *http.Request, name string, sd webauthn.SessionData, parsed *protocol.ParsedCredentialAssertionData) (users.Passkey, error) {
	if !s.passkeyChallenges.spend(sd.Challenge, spentUntil()) {
		return users.Passkey{}, errPasskeyWrong
	}
	flags := parsed.Response.AuthenticatorData.Flags
	k, err := s.userStore().UsePasskey(changeContext(r), name, parsed.RawID,
		users.PasskeyUse{SignCount: parsed.Response.AuthenticatorData.Counter, BackupState: flags.HasBackupState(),
			Challenge: []byte(sd.Challenge), ChallengeUntil: spentUntil()})
	switch {
	case errors.Is(err, users.ErrPasskeyCloned):
		s.Log.Warn("passkey refused: its counter went backwards, so it may have been copied",
			append([]any{"audit", true, "user", name, "passkey", passkeyID(parsed.RawID)}, s.client(r).logAttrs()...)...)
		return users.Passkey{}, errPasskeyCloned
	case errors.Is(err, users.ErrPasskeyUnknown), errors.Is(err, users.ErrPasskeyReplayed):
		return users.Passkey{}, errPasskeyWrong
	case err != nil:
		return users.Passkey{}, errMFAUnavailable
	}
	return k, nil
}

// passkeyID writes a passkey's credential ID as the API names it.
func passkeyID(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

// passkeyView describes a passkey for the account menu.
func passkeyView(k users.Passkey, here passkeyHere) map[string]any {
	v := map[string]any{"id": passkeyID(k.ID), "name": k.Name, "created": k.Created, "host": k.RPID,
		"here": k.RPID == here.rpID, "synced": k.BackupEligible}
	if !k.LastUsed.IsZero() {
		v["last_used"] = k.LastUsed
	}
	return v
}

// passkeyHosts lists the hosts m's passkeys work on.
func passkeyHosts(m users.MFA) []string {
	var out []string
	for _, k := range m.Passkeys {
		if !slices.Contains(out, k.RPID) {
			out = append(out, k.RPID)
		}
	}
	return out
}

// handlePasskeyOptions begins adding a passkey: the options the browser
// makes it with.
func (s *Server) handlePasskeyOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := principalOf(r)
	if !s.mfaWritable(w, p) {
		return
	}
	here, why := s.passkeyPlace(r)
	if why != "" {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "passkey_unavailable", "error": why})
		return
	}
	wa, err := here.relyingParty()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	store := s.userStore()
	m, _ := store.MFA(p.Username)
	if len(m.Passkeys) >= users.MaxPasskeys {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "passkey_limit", "error": users.ErrTooManyPasskeys.Error()})
		return
	}
	u := passkeyUserOf(p.Username, m, here)
	u.handle = store.PasskeyHandle(p.Username)
	opts, sd, err := wa.BeginRegistration(u,
		webauthn.WithExclusions(u.descriptors()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			// A passkey the browser can find without the username, so it
			// can sign in on its own.
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationPreferred,
		}))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	token, err := s.sealCeremony(ceremonyPurpose(ceremonyAdd, p.Username, p.token), sd)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": opts.Response, "token": token})
}

// handleAddPasskey finishes adding a passkey. The first second step of
// someone without two-step sign-in turns it on: the answer carries the
// recovery codes, shown this once, and every other session of the user
// ends, everywhere.
func (s *Server) handleAddPasskey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := principalOf(r)
	var req struct {
		Name string `json:"name"`
		passkeyAnswer
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.mfaWritable(w, p) {
		return
	}
	here, why := s.passkeyPlace(r)
	if why != "" {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "passkey_unavailable", "error": why})
		return
	}
	refuse := func(msg string) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "passkey_wrong", "error": msg})
	}
	sd, err := s.openCeremony(ceremonyPurpose(ceremonyAdd, p.Username, p.token), req.Token, here)
	if err != nil {
		refuse("That took too long. Add the passkey again.")
		return
	}
	if len(req.Credential) > passkeyAnswerMax {
		refuse("The browser's answer is too large.")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		refuse("The browser's answer could not be read. Add the passkey again.")
		return
	}
	wa, err := here.relyingParty()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	m, _ := s.userStore().MFA(p.Username)
	u := passkeyUserOf(p.Username, m, here)
	u.handle = sd.UserID
	cred, err := wa.CreateCredential(u, sd, parsed)
	if err != nil {
		s.Log.Info("passkey not added", "user", p.Username, "err", err)
		refuse("The passkey could not be checked. Add it again.")
		return
	}
	if !s.passkeyChallenges.spend(sd.Challenge, spentUntil()) {
		refuse("That passkey was added already.")
		return
	}
	k := users.Passkey{ID: cred.ID, PublicKey: cred.PublicKey, RPID: here.rpID, Name: req.Name,
		AAGUID: cred.Authenticator.AAGUID, SignCount: cred.Authenticator.SignCount,
		BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState, Verified: cred.Flags.UserVerified}
	for _, t := range cred.Transport {
		k.Transports = append(k.Transports, string(t))
	}
	codes, err := s.userStore().AddPasskey(changeContext(r), p.Username, sd.UserID, k)
	switch {
	case errors.Is(err, users.ErrPasskeyExists), errors.Is(err, users.ErrTooManyPasskeys), errors.Is(err, users.ErrPasskeyRace):
		writeJSON(w, http.StatusConflict, map[string]any{"code": "passkey_state", "error": err.Error()})
		return
	case err != nil:
		s.writeMFAError(w, err)
		return
	}
	s.audit(r, "passkey added", "user", p.Username, "passkey", users.PasskeyName(req.Name), "host", here.rpID, "synced", k.BackupEligible)
	out := map[string]any{}
	if codes != nil {
		ended := s.renewSession(w, r, p)
		s.audit(r, "two-step sign-in turned on", "user", p.Username, "with", "passkey", "other_sessions_ended", ended)
		out["recovery_codes"] = codes
	}
	out["mfa"] = s.mfaViewAt(p, here)
	writeJSON(w, http.StatusOK, out)
}

// handleRemovePasskey removes one of the user's passkeys. Removing the
// last one of someone without an authenticator app turns two-step
// sign-in off; where it is required, they set it up again at once.
func (s *Server) handleRemovePasskey(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if !s.mfaWritable(w, p) {
		return
	}
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"code": "passkey_unknown", "error": users.ErrPasskeyUnknown.Error()})
		return
	}
	k, err := s.userStore().RemovePasskey(changeContext(r), p.Username, id)
	switch {
	case errors.Is(err, users.ErrPasskeyUnknown):
		writeJSON(w, http.StatusNotFound, map[string]any{"code": "passkey_unknown", "error": err.Error()})
		return
	case err != nil:
		s.writeMFAError(w, err)
		return
	}
	s.audit(r, "passkey removed", "user", p.Username, "passkey", k.Name, "host", k.RPID)
	if !s.userStore().MFAOn(p.Username) {
		s.audit(r, "two-step sign-in turned off", "user", p.Username)
	}
	here, _ := s.passkeyPlace(r)
	writeJSON(w, http.StatusOK, map[string]any{"mfa": s.mfaViewAt(p, here)})
}

// handlePasskeyChallenge begins a passkey check for the signed-in user,
// to answer instead of their password or a code.
func (s *Server) handlePasskeyChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := principalOf(r)
	if p.Method != "session" || !mfaSource(p.Source) {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "passkey_unavailable", "error": "Passkeys cannot be used here."})
		return
	}
	here, why := s.passkeyPlace(r)
	if why != "" {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "passkey_unavailable", "error": why})
		return
	}
	m, _ := s.userStore().MFA(p.Username)
	opts, err := s.assertionOptions(here, ceremonyCheck, p.Username, p.token, m)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if opts == nil {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "passkey_none", "error": "You have no passkey for this address."})
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

// handlePasskeyLoginOptions begins signing in with a passkey alone: a
// challenge any of this host's passkeys can answer, the browser showing
// which accounts it has a passkey for.
func (s *Server) handlePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, errors.New("cross-site request refused"))
		return
	}
	here, why := s.passkeyPlace(r)
	if why != "" {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "passkey_unavailable", "error": why})
		return
	}
	wa, err := here.relyingParty()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// On its own a passkey must check the user too (fingerprint, face or
	// PIN), so it counts as two factors.
	opts, sd, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	token, err := s.sealCeremony(ceremonyPurpose(ceremonyLogin, "", ""), sd)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": opts.Response, "token": token})
}

// handlePasskeyLogin signs in with a passkey alone. Like a password, it
// counts toward the sign-in limits, and every attempt is logged.
func (s *Server) handlePasskeyLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, errors.New("cross-site request refused"))
		return
	}
	var req struct {
		passkeyAnswer
		Remember bool `json:"remember"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	p, err := s.passkeySignIn(r, &req.passkeyAnswer)
	if err != nil {
		writeSignInError(w, err)
		return
	}
	token, err := s.startSession(r, p, req.Remember)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	s.setSessionCookie(w, r, token, req.Remember)
	s.rememberBrowser(w, r, p.Username)
	p.Method = "session"
	s.noteMFA(p)
	writeJSON(w, http.StatusOK, meView(p))
}

// passkeySignIn checks a passkey answer that signs in on its own.
func (s *Server) passkeySignIn(r *http.Request, a *passkeyAnswer) (*principal, error) {
	from := s.client(r)
	here, why := s.passkeyPlace(r)
	if why != "" || len(a.Credential) > passkeyAnswerMax {
		return nil, errPasskeyWrong
	}
	sd, err := s.openCeremony(ceremonyPurpose(ceremonyLogin, "", ""), a.Token, here)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(a.Credential)
	if err != nil {
		return nil, errPasskeyWrong
	}
	store := s.userStore()
	name, known := store.PasskeyOwner(parsed.Response.UserHandle)
	// The account the passkey names counts the attempt; one that names
	// no account counts for its address only.
	account := name
	if !known {
		account = "\x00passkey"
	}
	attempt, err := s.beginAttempt(r, from, account, "")
	if err != nil {
		return nil, err
	}
	fail := func(reason string, err error) (*principal, error) {
		f := attempt.Fail()
		s.Log.Warn("sign-in failed", slices.Concat([]any{"audit", true, "user", name}, from.logAttrs(),
			[]any{"method", "passkey", "reason", reason, "locked_out", f.LockedOut()})...)
		s.noteFailure(from, f)
		return nil, err
	}
	if !known {
		return fail("a passkey of no account", errPasskeyWrong)
	}
	wa, err := here.relyingParty()
	if err != nil {
		attempt.Done()
		return nil, err
	}
	m, _ := store.MFA(name)
	_, _, err = wa.ValidatePasskeyLogin(func(_, handle []byte) (webauthn.User, error) {
		if !bytes.Equal(handle, m.Handle) {
			return nil, errors.New("another account's passkey")
		}
		return passkeyUserOf(name, m, here), nil
	}, sd, parsed)
	if err != nil {
		return fail("passkey not accepted: "+err.Error(), errPasskeyWrong)
	}
	if _, err := s.usePasskey(r, name, sd, parsed); err != nil {
		if errors.Is(err, errMFAUnavailable) {
			attempt.Done()
			return nil, err
		}
		return fail("passkey refused", err)
	}
	var p *principal
	switch {
	case s.isBuiltin(name):
		if !s.builtinReadable() {
			attempt.Done()
			return nil, errDegraded
		}
		store.RecordBuiltinSignIn(clusterauth.WithMethod(r.Context(), "passkey"))
		p = s.builtinPrincipal()
	default:
		u, ok := store.Get(name)
		switch {
		case !ok:
			return fail("a passkey of no account", errPasskeyWrong)
		case u.Source == users.SourceDirectory:
			// The directory decides whether they may sign in, so it gets
			// their password first.
			attempt.Done()
			return nil, errPasskeyPassword
		case u.Source != users.SourceLocal:
			return fail("a passkey of a single sign-on user", errPasskeyWrong)
		case u.Disabled:
			attempt.Done()
			s.Log.Warn("sign-in failed", slices.Concat([]any{"audit", true, "user", name}, from.logAttrs(),
				[]any{"method", "passkey", "reason", "account disabled"})...)
			return nil, errDisabled
		}
		p = principalFromUser(u)
		if err := s.degradedRefusal(p); err != nil {
			attempt.Done()
			return nil, err
		}
		store.RecordSignIn(clusterauth.WithMethod(r.Context(), "passkey"), u.Username)
	}
	attempt.Succeed()
	s.notePlainSignIn(r)
	s.noteName(r)
	p.codeUsed = &users.CodeResult{Kind: users.CodePasskey}
	s.Log.Info("signed in", slices.Concat([]any{"audit", true, "user", p.Username, "role", p.Role, "source", p.Source}, from.logAttrs(),
		[]any{"method", "passkey"})...)
	return p, nil
}
