package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"time"
)

// A passkey ceremony (WebAuthn) has two steps: the server hands the
// browser a challenge, and checks what the authenticator signed against
// it. What the second step needs from the first travels with the browser
// in a token this key signs, so any server of a cluster can check it.

const (
	statePrefix = "1."
	// stateMax is the most data a token carries.
	stateMax = 4096
)

// SealState returns a token carrying data for purpose, good until
// expires. Purpose binds it: a token made for one purpose (or account,
// or session, when purpose names them) is refused for any other.
func (k *BrowserKey) SealState(purpose string, data []byte, expires time.Time) string {
	b := make([]byte, 8, 8+len(data)+sha256.Size)
	binary.BigEndian.PutUint64(b, uint64(expires.Unix()))
	b = append(b, data...)
	return statePrefix + base64.RawURLEncoding.EncodeToString(k.signState(b, purpose))
}

// OpenState returns the data of a token SealState made for purpose, if it
// has not expired at now.
func (k *BrowserKey) OpenState(purpose, token string, now time.Time) ([]byte, bool) {
	enc, ok := strings.CutPrefix(token, statePrefix)
	if !ok || len(enc) > base64.RawURLEncoding.EncodedLen(8+stateMax+sha256.Size) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(b) < 8+sha256.Size {
		return nil, false
	}
	body := b[:len(b)-sha256.Size]
	if !hmac.Equal(b, k.signState(append([]byte(nil), body...), purpose)) {
		return nil, false
	}
	if !now.Before(time.Unix(int64(binary.BigEndian.Uint64(body)), 0)) {
		return nil, false
	}
	return body[8:], true
}

// signState appends the MAC of body and purpose to body. Its label keeps
// it apart from the other cookies this key signs.
func (k *BrowserKey) signState(body []byte, purpose string) []byte {
	h := hmac.New(sha256.New, k.mac)
	h.Write([]byte("state\x00"))
	h.Write(binary.AppendUvarint(nil, uint64(len(purpose))))
	h.Write([]byte(purpose))
	h.Write(body)
	return h.Sum(body)
}
