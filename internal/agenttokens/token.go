// Package agenttokens keeps the tokens agents send events with: one per
// agent or group of agents, made on the Add data page or with signalith
// tokens create, shown once and kept only as a SHA-256 fingerprint.
//
// A token is "sgl_" and 52 characters of lowercase base32 (a-z, 2-7): 32
// random bytes, 56 characters in all. The prefix lets secret scanners find
// a leaked one (\bsgl_[a-z2-7]{52}\b). Since a token is 256 random bits,
// nobody can find one from its fingerprint, so a plain SHA-256 is as good
// as a keyed hash here, and every server can check tokens without sharing
// a key.
//
// The tokens are documents in the <prefix>_runtime index, which every
// server that shares the OpenSearch reads, so they are the same on all of
// them. Each server keeps them in memory and watches one small document
// that every change rewrites: a revoked token is refused at once on the
// server that revoked it and within a few seconds on the others, with no
// restart. When OpenSearch can't be reached, a server keeps the tokens it
// last read.
//
// The shared tokens from ingest.tokens and SIGNALITH_INGEST_TOKEN(_FILE)
// still work ("legacy" tokens). An admin can stop accepting one on every
// server at once; it is then listed under agenttokens:legacy. Like agent
// tokens, they are answered "try again" until the tokens were first read,
// so a refused one is never let back in. People often type shared tokens,
// so their IDs are an HMAC under a random key kept in agenttokens:legacy,
// not a plain hash anyone who can read events could test guesses against.
package agenttokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// Prefix starts every agent token.
	Prefix = "sgl_"
	// Length is how long a token is: the prefix and 52 characters.
	Length = len(Prefix) + 52
	// ScannerPattern finds tokens in text, for secret scanners.
	ScannerPattern = `\bsgl_[a-z2-7]{52}\b`
	// MaxActive is how many active tokens there may be, and MaxDocs how
	// many token documents, revoked ones included.
	MaxActive = 1000
	MaxDocs   = 5000
	// MaxNameLen is the longest name, in characters.
	MaxNameLen = 64
)

// Purposes a token may be made for: the agent its configuration is for.
const (
	PurposeLinux   = "linux"
	PurposeWindows = "windows"
	PurposeOTel    = "otel"
	PurposeOsquery = "osquery"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret makes a new token.
func NewSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return Prefix + strings.ToLower(b32.EncodeToString(b)), nil
}

// IsToken reports whether s has the shape of an agent token.
func IsToken(s string) bool {
	if len(s) != Length || !strings.HasPrefix(s, Prefix) {
		return false
	}
	for _, c := range s[len(Prefix):] {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// Fingerprint is the SHA-256 of a token, in lowercase hex: what is stored.
func Fingerprint(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// IDOf is an agent token's ID: the first 12 hex characters of its
// fingerprint. osquery hosts enrolled with a shared token before shared
// tokens had keyed IDs hold this too; it is matched, never shown.
func IDOf(secret string) string { return Fingerprint(secret)[:12] }

// hintOf is the last 4 characters of a token, shown so an admin can match
// a configuration file to its token.
func hintOf(secret string) string {
	if len(secret) < 4 {
		return ""
	}
	return secret[len(secret)-4:]
}

// LegacyName is the name a shared token from the configuration is shown
// and recorded under.
func LegacyName(id string) string {
	if len(id) > 6 {
		id = id[:6]
	}
	return "Shared token " + id
}

// OldExampleName is what events sent with the example token of an older
// Docker quick start record, while it is still accepted.
const OldExampleName = "Old example token"

// ValidPurpose reports whether p is a purpose a token may have.
func ValidPurpose(p string) bool {
	switch p {
	case "", PurposeLinux, PurposeWindows, PurposeOTel, PurposeOsquery:
		return true
	}
	return false
}

// CleanName trims a name and turns each run of spaces inside it into one
// space. ok is false when what is left is empty, longer than MaxNameLen
// characters, or holds anything but letters, digits, spaces and
// . _ - ( ) / : # @.
func CleanName(name string) (string, bool) {
	if !utf8.ValidString(name) {
		return "", false
	}
	var b strings.Builder
	space := false
	for _, r := range strings.TrimSpace(name) {
		switch {
		case r == ' ':
			space = true
			continue
		case unicode.IsLetter(r), unicode.IsDigit(r), strings.ContainsRune("._-()/:#@", r):
		default:
			return "", false
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	out := b.String()
	if n := utf8.RuneCountInString(out); n == 0 || n > MaxNameLen {
		return "", false
	}
	return out, true
}

// Error is a change to the tokens that was refused, with the HTTP status,
// the code the API answers with, and the field at fault ("" for none).
type Error struct {
	Status int
	Code   string
	Field  string
	Msg    string
	// Err is the underlying failure, kept for the log.
	Err error
}

func (e *Error) Error() string { return e.Msg }
func (e *Error) Unwrap() error { return e.Err }

// Error codes.
const (
	CodeNameInvalid      = "name_invalid"
	CodePurposeInvalid   = "purpose_invalid"
	CodeNotFound         = "not_found"
	CodeNameTaken        = "name_taken"
	CodeRevoked          = "revoked"
	CodeTooMany          = "too_many"
	CodeStoreUnavailable = "store_unavailable"
	CodeLoading          = "tokens_loading"
)

func errNameInvalid() *Error {
	return &Error{Status: http.StatusBadRequest, Code: CodeNameInvalid, Field: "name",
		Msg: "Use 1 to 64 letters, digits, spaces or . _ - ( ) / : # @."}
}

func errPurposeInvalid() *Error {
	return &Error{Status: http.StatusBadRequest, Code: CodePurposeInvalid, Field: "purpose",
		Msg: "The purpose must be linux, windows, otel, osquery or empty."}
}

func errNotFound() *Error {
	return &Error{Status: http.StatusNotFound, Code: CodeNotFound, Msg: "There is no agent token with this ID."}
}

func errNameTaken(name string) *Error {
	return &Error{Status: http.StatusConflict, Code: CodeNameTaken, Field: "name",
		Msg: fmt.Sprintf("An active token is already called %s. Choose another name.", name)}
}

func errRevoked() *Error {
	return &Error{Status: http.StatusConflict, Code: CodeRevoked, Msg: "This token was revoked; it can't be renamed."}
}

func errTooMany() *Error {
	return &Error{Status: http.StatusConflict, Code: CodeTooMany,
		Msg: fmt.Sprintf("There are already %s active agent tokens. Revoke ones you no longer use.", "1,000")}
}

func errTooManyDocs() *Error {
	return &Error{Status: http.StatusConflict, Code: CodeTooMany,
		Msg: "There are already 5,000 agent tokens, revoked ones included, which is as many as Signalith keeps."}
}

func errStore(err error) *Error {
	return &Error{Status: http.StatusServiceUnavailable, Code: CodeStoreUnavailable,
		Msg: "OpenSearch can't be reached, so tokens can't be changed right now. Try again when it's back.", Err: err}
}

func errLoading(err error) *Error {
	return &Error{Status: http.StatusServiceUnavailable, Code: CodeLoading,
		Msg: "Agent tokens are still loading. Try again in a few seconds.", Err: err}
}
