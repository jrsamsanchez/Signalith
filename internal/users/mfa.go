package users

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Two-step sign-in: after the password, a six-digit code from an
// authenticator app (TOTP, RFC 6238: SHA-1, 30-second steps, the way
// Google Authenticator, Microsoft Authenticator, 1Password and the like
// expect it), a passkey (see Passkey), or one of ten recovery codes that
// each work once.
//
// The app's key is kept encrypted, with the master key in the users file
// and with the cluster key in the shared settings, and is bound to its
// user, so it cannot be copied to another. Recovery codes are kept only as
// SHA-256 digests: each carries about 50 random bits, too many to guess
// before the sign-in limits stop the guessing.

// MFA is a user's two-step sign-in.
type MFA struct {
	// Secret is the authenticator app's key, in base32. It is plain only
	// in memory: the backends keep it encrypted.
	Secret string
	// Sealed is Secret as the backend last stored it, so that it is
	// written back unchanged rather than encrypted again on every write.
	Sealed string
	// Problem says why the stored key could not be decrypted ("" when it
	// could): codes from the app are then refused, recovery codes still
	// work, and an admin can turn it off.
	Problem string
	// Pending is a key being set up and not yet confirmed with a code
	// from the app: sign-in does not ask for it.
	Pending bool
	// NoApp says there is no authenticator app: the user has passkeys
	// only, and Secret only keys the recovery codes. It is never shown.
	NoApp bool
	// Handle is the random user handle the user's passkeys carry (the
	// WebAuthn user ID), which names the account without its username.
	Handle []byte
	// Passkeys are the user's passkeys.
	Passkeys []Passkey
	// Spent are the passkey challenges answered lately, until they
	// expire: an answer is accepted once, on whichever server.
	Spent []SpentChallenge
	// Recovery holds the digest of each recovery code not used yet.
	Recovery []string
	// Since is when it was turned on, or when setting it up began.
	Since time.Time
	// LastStep is the time step of the last code from the app accepted.
	// That code and older ones are refused, so a code someone saw cannot
	// be used again.
	LastStep int64
}

// On reports whether m asks for a second step at sign-in: a code from
// the app, or a passkey.
func (m *MFA) On() bool { return m.AppOn() || m != nil && len(m.Passkeys) > 0 }

// AppOn reports whether codes from an authenticator app are accepted.
func (m *MFA) AppOn() bool { return m != nil && !m.Pending && !m.NoApp }

func (m *MFA) clone() *MFA {
	if m == nil {
		return nil
	}
	c := *m
	c.Recovery = slices.Clone(m.Recovery)
	c.Handle = slices.Clone(m.Handle)
	c.Spent = slices.Clone(m.Spent)
	c.Passkeys = make([]Passkey, len(m.Passkeys))
	for i, k := range m.Passkeys {
		c.Passkeys[i] = k.clone()
	}
	if m.Passkeys == nil {
		c.Passkeys = nil
	}
	return &c
}

// MFAField is the field a user's authenticator key is encrypted for,
// which binds it to that user.
func MFAField(name string) string { return "users." + NormalizeUsername(name) + ".mfa_secret" }

// BuiltinMFAField is the field the built-in admin's authenticator key is
// encrypted for. It does not name the account, so renaming it keeps the
// key.
const BuiltinMFAField = "auth.builtin_mfa_secret"

var (
	// ErrWrongCode refuses a code that is not right, or was used already.
	ErrWrongCode = errors.New("that code isn't right, or was used already")
	// ErrMFAOff says the user has no two-step sign-in to check.
	ErrMFAOff = errors.New("two-step sign-in is not turned on for this account")
	// ErrMFAOn refuses to set up two-step sign-in again while it is on.
	ErrMFAOn = errors.New("an authenticator app is already set up; turn it off first to set up another")
	// ErrNoSetup refuses to confirm a set-up that was never started or
	// took too long.
	ErrNoSetup = errors.New("start setting up two-step sign-in again: the QR code is no longer valid")
	// ErrNoBuiltinMFA says this store keeps no two-step sign-in for the
	// built-in admin.
	ErrNoBuiltinMFA = errors.New("two-step sign-in for the built-in admin is not kept here")
)

const (
	totpStep   = 30 // seconds
	totpDigits = 6
	// totpSkew accepts the code of the step before and after the current
	// one, for a phone whose clock is a little off.
	totpSkew = 1
	// SetupFor is how long a QR code shown for set-up stays valid.
	SetupFor = 15 * time.Minute
	// RecoveryCodes is how many recovery codes a user gets.
	RecoveryCodes = 10
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewMFASecret returns a new authenticator key: 160 random bits, in
// base32.
func NewMFASecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

// totpAt returns the code for secret at time step step.
func totpAt(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, n%1000000), nil
}

// TOTP returns the code for secret at time t, as an authenticator app
// shows it.
func TOTP(secret string, t time.Time) (string, error) {
	return totpAt(secret, t.Unix()/totpStep)
}

// checkTOTP returns the time step code is right for, from the one before
// t to the one after, and later than after; ok is false when there is
// none.
func checkTOTP(secret, code string, t time.Time, after int64) (int64, bool) {
	now := t.Unix() / totpStep
	found, ok := int64(0), false
	for step := now - totpSkew; step <= now+totpSkew; step++ {
		want, err := totpAt(secret, step)
		if err != nil {
			return 0, false
		}
		// Every step is compared, so the time taken does not tell which.
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && step > after && !ok {
			found, ok = step, true
		}
	}
	return found, ok
}

// OTPAuthURL returns the otpauth:// address an authenticator app reads
// from the QR code: issuer and account name the entry in the app.
func OTPAuthURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpStep))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// recoveryAlphabet leaves out letters and digits that are easy to
// confuse (0 and o, 1 and l and i).
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// newRecoveryCodes returns RecoveryCodes new codes such as "k7q2m-x9vtd",
// each 10 characters (about 50 bits), and their digests keyed with the
// authenticator key secret (see recoveryDigest).
func newRecoveryCodes(secret string) (codes, digests []string) {
	for range RecoveryCodes {
		var sb strings.Builder
		for sb.Len() < 11 {
			if sb.Len() == 5 {
				sb.WriteByte('-')
				continue
			}
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				panic(err)
			}
			// Rejection sampling: 248 is the largest multiple of 31 below
			// 256, so every character is as likely.
			if int(b[0]) >= 248 {
				continue
			}
			sb.WriteByte(recoveryAlphabet[int(b[0])%len(recoveryAlphabet)])
		}
		codes = append(codes, sb.String())
		digests = append(digests, recoveryDigest(secret, sb.String()))
	}
	return codes, digests
}

// normalizeCode drops spaces and dashes and lowers the case, so a code
// typed as "K7Q2M X9VTD" or "123 456" counts.
func normalizeCode(code string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '\t':
			return -1
		}
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, code)
}

// recoveryDigest is what is kept of a recovery code: an HMAC keyed with
// the user's authenticator key, which is kept encrypted. Someone with a
// copy of the users file or the shared settings, but not the key that
// decrypts them, cannot try every code (about 50 bits) against it.
func recoveryDigest(secret, code string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("signalith recovery code v2\x00" + normalizeCode(code)))
	return recoveryV2 + hex.EncodeToString(m.Sum(nil))
}

// recoveryV2 starts a digest made by recoveryDigest. Digests without it
// are plain SHA-256 (legacyRecoveryDigest), from the first version.
const recoveryV2 = "2:"

func legacyRecoveryDigest(code string) string {
	sum := sha256.Sum256([]byte("signalith recovery code v1\x00" + normalizeCode(code)))
	return hex.EncodeToString(sum[:])
}

// isAppCode reports whether a normalized code looks like one from an
// authenticator app: six digits.
func isAppCode(code string) bool {
	if len(code) != totpDigits {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// CodeKind says which kind of code was accepted.
type CodeKind string

const (
	CodeApp      CodeKind = "app"
	CodeRecovery CodeKind = "recovery"
	CodePasskey  CodeKind = "passkey"
)

// CodeResult is a code that was accepted: which kind, and how many
// recovery codes are left.
type CodeResult struct {
	Kind CodeKind
	Left int
}

// useCode checks code against m at t and returns m as it is after: the
// app's step remembered, or the recovery code used up.
func useCode(m *MFA, code string, t time.Time) (*MFA, CodeResult, error) {
	if !m.On() {
		return nil, CodeResult{}, ErrMFAOff
	}
	code = normalizeCode(code)
	next := m.clone()
	if isAppCode(code) {
		if !m.AppOn() || m.Secret == "" {
			return nil, CodeResult{}, ErrWrongCode
		}
		step, ok := checkTOTP(m.Secret, code, t, m.LastStep)
		if !ok {
			return nil, CodeResult{}, ErrWrongCode
		}
		next.LastStep = step
		return next, CodeResult{Kind: CodeApp, Left: len(next.Recovery)}, nil
	}
	if code == "" || len(code) > 64 {
		return nil, CodeResult{}, ErrWrongCode
	}
	// Without the key (it cannot be decrypted here), no recovery code
	// can be checked either.
	if m.Secret == "" {
		return nil, CodeResult{}, ErrWrongCode
	}
	d, legacy := recoveryDigest(m.Secret, code), legacyRecoveryDigest(code)
	found := -1
	for i, have := range m.Recovery {
		want := d
		if !strings.HasPrefix(have, recoveryV2) {
			want = legacy
		}
		if subtle.ConstantTimeCompare([]byte(have), []byte(want)) == 1 {
			found = i
		}
	}
	if found < 0 {
		return nil, CodeResult{}, ErrWrongCode
	}
	next.Recovery = slices.Delete(next.Recovery, found, found+1)
	return next, CodeResult{Kind: CodeRecovery, Left: len(next.Recovery)}, nil
}

// MFAChange changes a user's two-step sign-in: it gets the current one
// (nil for none) and returns what to keep (nil for none), and whether
// the user's sessions end everywhere. ErrNoChange writes nothing.
type MFAChange func(cur *MFA) (next *MFA, endSessions bool, err error)

// builtinMFABackend is a Backend that keeps the built-in admin's
// two-step sign-in too.
type builtinMFABackend interface {
	BuiltinMFA() *MFA
	ChangeBuiltinMFA(ctx context.Context, by string, fn MFAChange) error
}

// MFA returns the two-step sign-in of a user or the built-in admin; ok
// is false when there is none, set up or being set up.
func (s *Store) MFA(name string) (MFA, bool) {
	s.fresh()
	if s.reserved(name) {
		b, ok := s.b.(builtinMFABackend)
		if !ok {
			return MFA{}, false
		}
		m := b.BuiltinMFA()
		if m == nil {
			return MFA{}, false
		}
		return *m.clone(), true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.mfa[NormalizeUsername(name)]
	if !ok || m == nil {
		return MFA{}, false
	}
	return *m.clone(), true
}

// MFAOn reports whether sign-in asks name for a code.
func (s *Store) MFAOn(name string) bool {
	m, ok := s.MFA(name)
	return ok && m.On()
}

// changeMFA changes the two-step sign-in of a user or the built-in admin
// with fn.
func (s *Store) changeMFA(ctx context.Context, name string, fn MFAChange) error {
	if s.reserved(name) {
		b, ok := s.b.(builtinMFABackend)
		if !ok {
			return ErrNoBuiltinMFA
		}
		return b.ChangeBuiltinMFA(ctx, Actor(ctx), fn)
	}
	_, err := s.b.Change(ctx, Actor(ctx), NormalizeUsername(name), "", func(r *Record) error {
		next, end, err := fn(r.MFA.clone())
		if err != nil {
			return err
		}
		r.MFA = next
		if end {
			r.Epoch++
		}
		return nil
	})
	return err
}

// BeginMFA starts setting up two-step sign-in for name and returns the
// new key, for the QR code. It is not asked for at sign-in until a code
// from the app confirms it (ConfirmMFA), within SetupFor.
func (s *Store) BeginMFA(ctx context.Context, name string) (string, error) {
	secret := NewMFASecret()
	release, err := s.hold()
	if err != nil {
		return "", err
	}
	defer release()
	err = s.changeMFA(ctx, name, func(cur *MFA) (*MFA, bool, error) {
		if cur.AppOn() {
			return nil, false, ErrMFAOn
		}
		if !cur.On() {
			return &MFA{Secret: secret, Pending: true, Since: s.now()}, false, nil
		}
		// Passkeys stay. Their recovery codes are keyed with the key
		// they keep, so the app gets that key, unless it cannot be
		// decrypted here.
		next := cur.clone()
		if cur.Secret == "" {
			next.Sealed, next.Problem = "", ""
		} else {
			secret = cur.Secret
		}
		next.Secret, next.Pending, next.NoApp, next.Since = secret, true, false, s.now()
		return next, false, nil
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

// ConfirmMFA turns on the two-step sign-in BeginMFA started, once code
// is right for it, and returns the recovery codes, which are shown once.
// Every session of the user ends, everywhere: a server that keeps its
// sessions in memory is left to end them (auth.Sessions.EndUser).
func (s *Store) ConfirmMFA(ctx context.Context, name, code string) ([]string, error) {
	var codes []string
	release, err := s.hold()
	if err != nil {
		return nil, err
	}
	defer release()
	now := s.now()
	err = s.changeMFA(ctx, name, func(cur *MFA) (*MFA, bool, error) {
		switch {
		case cur.AppOn():
			return nil, false, ErrMFAOn
		case cur == nil || !cur.Pending || cur.Secret == "" || now.Sub(cur.Since) > SetupFor:
			return nil, false, ErrNoSetup
		}
		step, ok := checkTOTP(cur.Secret, normalizeCode(code), now, 0)
		if !ok {
			return nil, false, ErrWrongCode
		}
		next := cur.clone()
		codes, next.Recovery = newRecoveryCodes(cur.Secret)
		next.Pending, next.NoApp, next.Since, next.LastStep = false, false, now, step
		return next, true, nil
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// UseMFACode checks a code from the app or a recovery code for name, and
// remembers that it was used: the same code is refused after. Two
// servers that check the same code at once write the same user, and the
// second sees the first's write, so only one accepts it.
func (s *Store) UseMFACode(ctx context.Context, name, code string) (CodeResult, error) {
	var res CodeResult
	now := s.now()
	err := s.changeMFA(ctx, name, func(cur *MFA) (*MFA, bool, error) {
		next, r, err := useCode(cur, code, now)
		if err != nil {
			return nil, false, err
		}
		res = r
		return next, false, nil
	})
	return res, err
}

// NewRecoveryCodes replaces name's recovery codes with new ones, which
// are shown once.
func (s *Store) NewRecoveryCodes(ctx context.Context, name string) ([]string, error) {
	var codes []string
	release, err := s.hold()
	if err != nil {
		return nil, err
	}
	defer release()
	err = s.changeMFA(ctx, name, func(cur *MFA) (*MFA, bool, error) {
		if !cur.On() {
			return nil, false, ErrMFAOff
		}
		if cur.Secret == "" {
			return nil, false, ErrWrongCode
		}
		next := cur.clone()
		codes, next.Recovery = newRecoveryCodes(cur.Secret)
		return next, false, nil
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// RemoveApp turns off name's authenticator app, or stops setting one
// up. Passkeys stay, with the recovery codes; without passkeys it is
// RemoveMFA. It reports whether there was an app, set up or being set up.
func (s *Store) RemoveApp(ctx context.Context, name string) (bool, error) {
	release, err := s.hold()
	if err != nil {
		return false, err
	}
	defer release()
	had := false
	err = s.changeMFA(ctx, name, func(cur *MFA) (*MFA, bool, error) {
		if cur == nil || cur.NoApp {
			return nil, false, ErrNoChange
		}
		had = true
		if len(cur.Passkeys) == 0 {
			return nil, false, nil
		}
		next := cur.clone()
		next.NoApp, next.Pending, next.LastStep = true, false, 0
		return next, false, nil
	})
	if errors.Is(err, ErrNoChange) {
		err = nil
	}
	return had, err
}

// RemoveMFA turns off name's two-step sign-in, passkeys included, or
// stops setting it up. It reports whether there was any.
func (s *Store) RemoveMFA(ctx context.Context, name string) (bool, error) {
	release, err := s.hold()
	if err != nil {
		return false, err
	}
	defer release()
	had := false
	err = s.changeMFA(ctx, name, func(cur *MFA) (*MFA, bool, error) {
		if cur == nil {
			return nil, false, ErrNoChange
		}
		had = true
		return nil, false, nil
	})
	if errors.Is(err, ErrNoChange) {
		err = nil
	}
	return had, err
}
