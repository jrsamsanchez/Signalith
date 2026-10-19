// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package users

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Passkeys (WebAuthn): a key pair the user's phone, computer or security
// key makes for this Signalith, unlocked with a fingerprint, face or PIN.
// Only the public key is kept here, so a copy of the users file or the
// shared settings signs nobody in. A passkey works as the second step
// after the password, and on its own for local users and the built-in
// admin: it is something they have, unlocked by something they know or
// are (NIST SP 800-63B, AAL2).
//
// Each passkey is bound to the address (the WebAuthn relying party ID)
// it was made on: a look-alike site cannot ask for it, which is what
// makes passkeys resistant to phishing.

// Passkey is one passkey of a user.
type Passkey struct {
	// ID is the credential ID the authenticator gave it.
	ID []byte `json:"id"`
	// PublicKey is its public key, COSE-encoded.
	PublicKey []byte `json:"public_key"`
	// RPID is the host name it was made on and works on.
	RPID string `json:"rp_id"`
	// Name is what the user called it.
	Name string `json:"name"`
	// AAGUID names the authenticator's model, when it says.
	AAGUID []byte `json:"aaguid,omitempty"`
	// SignCount is the authenticator's signature counter at its last use.
	// A counter that goes backwards means the key was copied.
	SignCount uint32 `json:"sign_count,omitempty"`
	// Transports are how the browser can reach it (usb, nfc, internal...).
	Transports []string `json:"transports,omitempty"`
	// BackupEligible says it can be synced to the user's other devices
	// (a synced passkey); BackupState says it is.
	BackupEligible bool `json:"backup_eligible,omitempty"`
	BackupState    bool `json:"backup_state,omitempty"`
	// Verified says the authenticator checked the user (fingerprint,
	// face or PIN) when it was made.
	Verified bool      `json:"user_verified,omitempty"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitzero"`
}

func (k Passkey) clone() Passkey {
	k.ID, k.PublicKey, k.AAGUID = slices.Clone(k.ID), slices.Clone(k.PublicKey), slices.Clone(k.AAGUID)
	k.Transports = slices.Clone(k.Transports)
	return k
}

const (
	// MaxPasskeys is how many passkeys a user can have.
	MaxPasskeys = 10
	// passkeyNameMax is the longest name a passkey can have, in
	// characters.
	passkeyNameMax = 64
	handleSize     = 32
)

var (
	// ErrPasskeyUnknown says the user has no such passkey.
	ErrPasskeyUnknown = errors.New("no such passkey")
	// ErrPasskeyExists refuses to add a passkey twice.
	ErrPasskeyExists = errors.New("this passkey is added already")
	// ErrTooManyPasskeys refuses a passkey past MaxPasskeys.
	ErrTooManyPasskeys = errors.New("an account can have at most 10 passkeys; remove one first")
	// ErrPasskeyReplayed refuses an answer to a challenge answered
	// already.
	ErrPasskeyReplayed = errors.New("this passkey answer was used already")
	// ErrPasskeyCloned refuses a passkey whose signature counter went
	// backwards: someone may have copied it.
	ErrPasskeyCloned = errors.New("this passkey's counter went backwards, so it may have been copied")
	// ErrPasskeyRace refuses a passkey made for a user handle that is no
	// longer the user's: start adding it again.
	ErrPasskeyRace = errors.New("start adding the passkey again")
)

// NewPasskeyHandle returns a new random user handle.
func NewPasskeyHandle() []byte {
	b := make([]byte, handleSize)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// PasskeyName tidies a name given to a passkey: trimmed, without control
// or invisible formatting characters (which could make one name look
// like another), at most passkeyNameMax characters, "Passkey" when empty.
func PasskeyName(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.TrimSpace(name))
	if utf8.RuneCountInString(name) > passkeyNameMax {
		name = strings.TrimSpace(string([]rune(name)[:passkeyNameMax]))
	}
	if name == "" {
		return "Passkey"
	}
	return name
}

// PasskeyHandle returns name's user handle for a new passkey: the one
// their passkeys have, or a new one, kept once a passkey is added.
func (s *Store) PasskeyHandle(name string) []byte {
	if m, ok := s.MFA(name); ok && len(m.Handle) > 0 {
		return m.Handle
	}
	return NewPasskeyHandle()
}

// PasskeyOwner returns the user (or the built-in admin) whose passkeys
// carry handle.
func (s *Store) PasskeyOwner(handle []byte) (string, bool) {
	if len(handle) == 0 {
		return "", false
	}
	s.fresh()
	if b := s.builtinName(); b != "" {
		if bb, ok := s.b.(builtinMFABackend); ok {
			if m := bb.BuiltinMFA(); m != nil && bytes.Equal(m.Handle, handle) {
				return b, true
			}
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for name, m := range s.mfa {
		if m != nil && bytes.Equal(m.Handle, handle) {
			if u, ok := s.users[name]; ok {
				return u.Username, true
			}
			return name, true
		}
	}
	return "", false
}

// passkeyTaken reports whether someone other than name has a passkey
// with id. A credential belongs to one account (WebAuthn, step 22 of
// registering one).
func (s *Store) passkeyTaken(name string, id []byte) bool {
	has := func(m *MFA) bool {
		return m != nil && slices.ContainsFunc(m.Passkeys, func(p Passkey) bool { return bytes.Equal(p.ID, id) })
	}
	s.fresh()
	if b := s.builtinName(); b != "" && !strings.EqualFold(b, name) {
		if bb, ok := s.b.(builtinMFABackend); ok && has(bb.BuiltinMFA()) {
			return true
		}
	}
	key := NormalizeUsername(name)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for n, m := range s.mfa {
		if n != key && has(m) {
			return true
		}
	}
	return false
}

// AddPasskey adds k to name's passkeys, made for user handle handle. The
// first passkey of someone without two-step sign-in turns it on: the
// recovery codes it returns are shown once, and every session of the
// user ends, everywhere, as ConfirmMFA does.
func (s *Store) AddPasskey(ctx context.Context, name string, handle []byte, k Passkey) ([]string, error) {
	var codes []string
	release, err := s.hold()
	if err != nil {
		return nil, err
	}
	defer release()
	now := s.now()
	k = k.clone()
	k.Name, k.Created = PasskeyName(k.Name), now
	if s.passkeyTaken(name, k.ID) {
		return nil, ErrPasskeyExists
	}
	err = s.changeMFA(ctx, name, func(cur *MFA) (*MFA, bool, error) {
		if !cur.On() {
			// A first second step. An app being set up is dropped; it can
			// be set up again.
			secret := NewMFASecret()
			var digests []string
			codes, digests = newRecoveryCodes(secret)
			return &MFA{Secret: secret, NoApp: true, Handle: slices.Clone(handle), Passkeys: []Passkey{k},
				Recovery: digests, Since: now}, true, nil
		}
		if len(cur.Handle) > 0 && !bytes.Equal(cur.Handle, handle) {
			return nil, false, ErrPasskeyRace
		}
		if len(cur.Passkeys) >= MaxPasskeys {
			return nil, false, ErrTooManyPasskeys
		}
		if slices.ContainsFunc(cur.Passkeys, func(p Passkey) bool { return bytes.Equal(p.ID, k.ID) }) {
			return nil, false, ErrPasskeyExists
		}
		next := cur.clone()
		next.Handle = slices.Clone(handle)
		next.Passkeys = append(next.Passkeys, k)
		return next, false, nil
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// RemovePasskey removes one of name's passkeys. Without an app or other
// passkeys, that turns two-step sign-in off. It returns the passkey.
func (s *Store) RemovePasskey(ctx context.Context, name string, id []byte) (Passkey, error) {
	var gone Passkey
	release, err := s.hold()
	if err != nil {
		return gone, err
	}
	defer release()
	err = s.changeMFA(ctx, name, func(cur *MFA) (*MFA, bool, error) {
		i := -1
		if cur != nil {
			i = slices.IndexFunc(cur.Passkeys, func(p Passkey) bool { return bytes.Equal(p.ID, id) })
		}
		if i < 0 {
			return nil, false, ErrPasskeyUnknown
		}
		gone = cur.Passkeys[i].clone()
		next := cur.clone()
		next.Passkeys = slices.Delete(next.Passkeys, i, i+1)
		if len(next.Passkeys) == 0 && next.NoApp {
			return nil, false, nil
		}
		return next, false, nil
	})
	return gone, err
}

// RemovePasskeys removes all of name's passkeys, as an admin's password
// reset does: whoever added one must not keep a way in that skips the
// new password. Without an app, that turns two-step sign-in off. It
// returns how many there were.
func (s *Store) RemovePasskeys(ctx context.Context, name string) (int, error) {
	n := 0
	release, err := s.hold()
	if err != nil {
		return 0, err
	}
	defer release()
	err = s.changeMFA(ctx, name, func(cur *MFA) (*MFA, bool, error) {
		if cur == nil || len(cur.Passkeys) == 0 {
			return nil, false, ErrNoChange
		}
		n = len(cur.Passkeys)
		if cur.NoApp {
			return nil, false, nil
		}
		next := cur.clone()
		next.Passkeys, next.Spent = nil, nil
		return next, false, nil
	})
	if errors.Is(err, ErrNoChange) {
		err = nil
	}
	return n, err
}

// PasskeyUse is what an authenticator said when a passkey was used,
// and the challenge it answered.
type PasskeyUse struct {
	SignCount   uint32
	BackupState bool
	// Challenge is the challenge answered, accepted once until
	// ChallengeUntil. Synced passkeys keep no counter, so this is what
	// stops a copied answer being sent again to another server.
	Challenge      []byte
	ChallengeUntil time.Time
}

// SpentChallenge is a passkey challenge answered already: its SHA-256,
// and until when it could be answered.
type SpentChallenge struct {
	Digest []byte    `json:"d"`
	Until  time.Time `json:"u"`
}

// maxSpent bounds the challenges kept per user. Each is answered with a
// real passkey within passkeyWait, and sign-ins are rate limited, so
// reaching it means something is wrong: further uses are refused until
// some expire.
const maxSpent = 256

// UsePasskey records that name's passkey id was just used: its counter,
// which must have moved on unless the authenticator keeps none (zero),
// and when. Two servers that check the same use at once write the same
// user, and the second sees the first's write, so only one accepts it.
func (s *Store) UsePasskey(ctx context.Context, name string, id []byte, use PasskeyUse) (Passkey, error) {
	var used Passkey
	now := s.now()
	err := s.changeMFA(ctx, name, func(cur *MFA) (*MFA, bool, error) {
		i := -1
		if cur != nil {
			i = slices.IndexFunc(cur.Passkeys, func(p Passkey) bool { return bytes.Equal(p.ID, id) })
		}
		if i < 0 {
			return nil, false, ErrPasskeyUnknown
		}
		next := cur.clone()
		next.Spent = slices.DeleteFunc(next.Spent, func(c SpentChallenge) bool { return !now.Before(c.Until) })
		sum := sha256.Sum256(use.Challenge)
		if len(use.Challenge) == 0 || len(next.Spent) >= maxSpent ||
			slices.ContainsFunc(next.Spent, func(c SpentChallenge) bool { return bytes.Equal(c.Digest, sum[:]) }) {
			return nil, false, ErrPasskeyReplayed
		}
		next.Spent = append(next.Spent, SpentChallenge{Digest: sum[:], Until: use.ChallengeUntil.UTC()})
		k := &next.Passkeys[i]
		if (use.SignCount != 0 || k.SignCount != 0) && use.SignCount <= k.SignCount {
			return nil, false, ErrPasskeyCloned
		}
		k.SignCount, k.BackupState, k.LastUsed = use.SignCount, use.BackupState, now
		used = k.clone()
		return next, false, nil
	})
	return used, err
}
