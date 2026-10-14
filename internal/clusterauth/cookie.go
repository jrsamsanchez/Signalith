package clusterauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

// A session cookie is s1.<kid>.<random>.<tag>: 32 random bytes and a
// 16-byte tag, HMAC-SHA256 under the cluster key's cookie key of
// "s1|<cluster id>|<random>", both in unpadded base64url, and the id of
// the cluster key that made the tag. A cookie that was not made with a
// cluster key this server has, or for another cluster, is refused before
// anything is read from OpenSearch, so made-up cookies cost nothing.

const cookieVersion = "s1"

// tagSize is the length of a cookie's tag.
const tagSize = 16

var b64 = base64.RawURLEncoding

func cookieTag(k *shared.ClusterKey, clusterID, random string) []byte {
	m := hmac.New(sha256.New, k.CookieKey())
	m.Write([]byte(cookieVersion + "|" + clusterID + "|" + random))
	return m.Sum(nil)[:tagSize]
}

// NewCookie returns a new session cookie made with k for the cluster
// clusterID.
func NewCookie(k *shared.ClusterKey, clusterID string) string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	random := b64.EncodeToString(raw)
	return cookieVersion + "." + k.ID() + "." + random + "." + b64.EncodeToString(cookieTag(k, clusterID, random))
}

// ErrBadCookie is a session cookie this cluster did not make.
var ErrBadCookie = errors.New("not a session cookie of this cluster")

// ParseCookie checks a session cookie: its form, a cluster key this
// server has, and its tag. It reads nothing from OpenSearch.
func ParseCookie(keys *shared.KeySet, clusterID, v string) error {
	if len(v) > 200 || clusterID == "" {
		return ErrBadCookie
	}
	parts := strings.Split(v, ".")
	if len(parts) != 4 || parts[0] != cookieVersion {
		return ErrBadCookie
	}
	k := keys.Get(parts[1])
	if k == nil {
		return ErrBadCookie
	}
	raw, err := b64.DecodeString(parts[2])
	if err != nil || len(raw) != 32 {
		return ErrBadCookie
	}
	tag, err := b64.DecodeString(parts[3])
	if err != nil || !hmac.Equal(tag, cookieTag(k, clusterID, parts[2])) {
		return ErrBadCookie
	}
	return nil
}

// SessionID is the id of a cookie's session document: a hash of the
// cookie, so the documents never hold a cookie that works.
func SessionID(cookie string) string {
	sum := sha256.Sum256([]byte(cookie))
	return b64.EncodeToString(sum[:])
}
