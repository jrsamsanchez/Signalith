// Package clusterjoin adds a server to a cluster with a one-use join
// token, or by an admin's approval of its fingerprint.
//
// A token (Token) carries the address of the server that made it, the
// SHA-256 of the certificate authority the new server must find there,
// and a 32-byte secret. The secret never crosses the wire: the new server
// proves it holds it (Proof), bound to its node public key, and the
// answer (a Bundle with the cluster key and the OpenSearch settings) is
// sealed to that node key with the secret mixed into the key derivation
// (Seal), so only the server that holds both can open it.
//
// The token documents, <prefix>_config/jointoken:<id>, keep the secret
// sealed under the cluster key, so only members can check a proof, and
// are used once by compare-and-set (Tokens.Consume).
package clusterjoin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

// TokenPrefix starts every join token: the format's version.
const TokenPrefix = "SJ1."

// SecretSize is the size of a token's secret.
const SecretSize = 32

// IDPrefix starts every token id; 20 base32 letters follow.
const IDPrefix = "jt_"

const idLetters = 20

// maxToken bounds the text Parse reads: a token is a few hundred bytes.
const maxToken = 4096

// idAlphabet is RFC 4648 base32 in lower case.
var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// Token is a join token. Its Secret must never be logged or stored in
// clear: a Token formats (fmt, slog, JSON) as "SJ1.<id>…", and only
// String returns the whole token, for the one answer that shows it.
type Token struct {
	// URL is the address of the server that made the token, https.
	URL string
	// CA is "sha256:" and the lower-case hex SHA-256 of the DER
	// certificate the new server must find at URL (GET
	// /api/cluster/join/ca).
	CA string
	// ID is the token's id, jt_ and 20 base32 letters.
	ID string
	// Secret is 32 random bytes.
	Secret []byte
}

// wire is a token's JSON inside the base64url text.
type wire struct {
	U  string `json:"u"`
	CA string `json:"ca"`
	ID string `json:"id"`
	S  string `json:"s"`
}

// ErrBadToken is text that is not a join token.
var ErrBadToken = errors.New("this is not a Signalith join token (it starts with SJ1.); copy the whole line again from Servers → Add a server")

// NewID makes a token id.
func NewID() (string, error) {
	b := make([]byte, 13)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return IDPrefix + idEncoding.EncodeToString(b)[:idLetters], nil
}

// ValidID reports whether id is a token id.
func ValidID(id string) bool {
	rest, ok := strings.CutPrefix(id, IDPrefix)
	if !ok || len(rest) != idLetters {
		return false
	}
	for _, c := range rest {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// NewSecret makes a token secret.
func NewSecret() ([]byte, error) {
	b := make([]byte, SecretSize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Pin returns the CA value of a token for the DER certificate der.
func Pin(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// validPin reports whether s is "sha256:" and 64 lower-case hex digits.
func validPin(s string) bool {
	h, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// MatchesPin reports, in constant time, whether the DER certificate der
// is the one the token names.
func (t Token) MatchesPin(der []byte) bool {
	return subtle.ConstantTimeCompare([]byte(Pin(der)), []byte(t.CA)) == 1
}

// CheckURL checks the address a token carries: https, a host, no user
// name, query or fragment. It returns it without a trailing slash.
func CheckURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return "", errors.New("the address cannot be read")
	case u.Scheme != "https":
		return "", errors.New("the address must start with https://")
	case u.Host == "" || u.Hostname() == "":
		return "", errors.New("the address has no host name")
	case u.User != nil:
		return "", errors.New("the address must not hold a user name or password")
	case u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.Contains(raw, "#"):
		return "", errors.New("the address must not have a query or fragment")
	case u.Opaque != "":
		return "", errors.New("the address cannot be read")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// Check checks every field of t.
func (t Token) Check() error {
	if _, err := CheckURL(t.URL); err != nil {
		return err
	}
	if !validPin(t.CA) {
		return errors.New("the certificate fingerprint is not sha256: and 64 hex digits")
	}
	if !ValidID(t.ID) {
		return errors.New("the token id is not jt_ and 20 letters")
	}
	if len(t.Secret) != SecretSize {
		return fmt.Errorf("the secret is %d bytes, not %d", len(t.Secret), SecretSize)
	}
	return nil
}

// Parse reads a join token. Spaces and quotes around it, which a copy
// from a terminal or a document may add, are dropped.
func Parse(s string) (Token, error) {
	s = strings.Trim(strings.TrimSpace(s), `'"`)
	if len(s) > maxToken {
		return Token{}, ErrBadToken
	}
	rest, ok := strings.CutPrefix(s, TokenPrefix)
	if !ok {
		return Token{}, ErrBadToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return Token{}, ErrBadToken
	}
	var w wire
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil || dec.More() {
		return Token{}, ErrBadToken
	}
	secret, err := base64.RawURLEncoding.DecodeString(w.S)
	if err != nil {
		return Token{}, ErrBadToken
	}
	t := Token{URL: w.U, CA: w.CA, ID: w.ID, Secret: secret}
	if err := t.Check(); err != nil {
		clear(secret)
		return Token{}, fmt.Errorf("%w: %s", ErrBadToken, err.Error())
	}
	t.URL, _ = CheckURL(t.URL)
	return t, nil
}

// String returns the whole token, secret included, for the one answer
// that shows it (POST /api/cluster/tokens, signalith cluster token).
// Formatting a Token with fmt, slog or JSON shows only its id.
func (t Token) String() string {
	raw, _ := json.Marshal(wire{U: t.URL, CA: t.CA, ID: t.ID, S: base64.RawURLEncoding.EncodeToString(t.Secret)})
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

// Redacted is the token as logs and errors may show it: its id only.
func (t Token) Redacted() string { return TokenPrefix + t.ID + "…" }

// Format shows the token's id only, whatever the verb, so a token passed
// to fmt or a log never shows its secret.
func (t Token) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(t.Redacted())) }

// LogValue shows the token's id only.
func (t Token) LogValue() slog.Value { return slog.StringValue(t.Redacted()) }

// MarshalJSON shows the token's id only.
func (t Token) MarshalJSON() ([]byte, error) { return json.Marshal(t.Redacted()) }

// Clear overwrites the secret.
func (t *Token) Clear() { clear(t.Secret) }

var (
	_ fmt.Formatter  = Token{}
	_ slog.LogValuer = Token{}
	_ json.Marshaler = Token{}
)
