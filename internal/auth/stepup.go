package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"time"
)

// RecheckAge is how long a password or two-step code entered again
// counts before a sensitive change asks for one once more.
const RecheckAge = 15 * time.Minute

const (
	recheckPrefix = "1."
	recheckValue  = 8 + sha256.Size
)

// IssueRecheck returns a cookie value saying account entered their
// password or code again at now, in the sign-in session whose token is
// session. It is good for that session only, for RecheckAge.
func (k *BrowserKey) IssueRecheck(account, session string, now time.Time) string {
	b := make([]byte, 8, recheckValue)
	binary.BigEndian.PutUint64(b, uint64(now.Unix()))
	return recheckPrefix + base64.RawURLEncoding.EncodeToString(k.signRecheck(b, account, session))
}

// CheckRecheck reports whether value is one IssueRecheck made for account
// and session less than RecheckAge before now.
func (k *BrowserKey) CheckRecheck(account, session, value string, now time.Time) bool {
	enc, ok := strings.CutPrefix(value, recheckPrefix)
	if !ok || session == "" || len(enc) != base64.RawURLEncoding.EncodedLen(recheckValue) {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(b) != recheckValue {
		return false
	}
	if !hmac.Equal(b, k.signRecheck(bytes.Clone(b[:8]), account, session)) {
		return false
	}
	age := now.Sub(time.Unix(int64(binary.BigEndian.Uint64(b)), 0))
	return age < RecheckAge && age > -time.Minute
}

// signRecheck appends the MAC of head (the time), account and session to
// head. It is kept apart from the known-browser cookies' MAC by its
// label, so neither cookie passes for the other.
func (k *BrowserKey) signRecheck(head []byte, account, session string) []byte {
	h := hmac.New(sha256.New, k.mac)
	h.Write([]byte("recheck\x00"))
	h.Write(head)
	acct := normAccount(account)
	h.Write(binary.AppendUvarint(nil, uint64(len(acct))))
	h.Write([]byte(acct))
	t := sha256.Sum256([]byte(session))
	h.Write(t[:])
	return h.Sum(head)
}
