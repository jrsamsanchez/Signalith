package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// KnownBrowserAge is how long a browser stays known for an account after
// it last signed in to it.
const KnownBrowserAge = 365 * 24 * time.Hour

const browserKeySize = 32

// BrowserKey signs the cookie that marks a browser as one that signed in
// to an account before, so the account's slow-down for strangers does not
// apply to it (see Limiter). Each cookie is for one account and is only
// good while the account's password is the one it was signed in with:
// changing or resetting a local password, or the built-in admin's, makes
// every browser a stranger again until it signs in.
type BrowserKey struct {
	name, mac []byte
}

// NewBrowserKey returns a random key kept only in memory: browsers are
// strangers again after the process restarts.
func NewBrowserKey() *BrowserKey {
	raw := make([]byte, browserKeySize)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return browserKeyFrom(raw)
}

func browserKeyFrom(raw []byte) *BrowserKey {
	derive := func(label string) []byte {
		h := hmac.New(sha256.New, raw)
		h.Write([]byte("signalith known browser " + label))
		return h.Sum(nil)
	}
	return &BrowserKey{name: derive("name"), mac: derive("mac")}
}

const browserKeyHeader = `# Signalith sign-in key. It signs the cookie that lets a browser that
# signed in to an account before keep signing in to it while someone else
# is guessing its password. Deleting this file only means every browser
# signs in once more before it is recognized again.
`

// LoadBrowserKey reads the key in path, or makes one there, readable only
// by Signalith's account, when there is none; created reports which.
func LoadBrowserKey(path string) (k *BrowserKey, created bool, err error) {
	for range 2 {
		data, err := os.ReadFile(path)
		if err == nil {
			raw, perr := parseBrowserKey(data)
			if perr != nil {
				return nil, false, fmt.Errorf("%s %v. Delete the file and restart Signalith to make a new one; browsers then sign in once more as strangers", path, perr)
			}
			return browserKeyFrom(raw), false, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, false, err
		}
		raw := make([]byte, browserKeySize)
		if _, err := rand.Read(raw); err != nil {
			return nil, false, err
		}
		text := []byte(browserKeyHeader + base64.StdEncoding.EncodeToString(raw) + "\n")
		p, err := securefile.Prepare(path, text)
		if err == nil {
			err = p.CommitNew()
		}
		if err == nil {
			return browserKeyFrom(raw), true, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, false, fmt.Errorf("could not make %s: %w. Check that the account Signalith runs as can write in that folder", path, err)
		}
		// Another process made it first: read that one.
	}
	return nil, false, fmt.Errorf("could not read or make %s", path)
}

func parseBrowserKey(data []byte) ([]byte, error) {
	var line []byte
	n := 0
	for _, l := range bytes.Split(data, []byte("\n")) {
		l = bytes.TrimSpace(l)
		if len(l) == 0 || l[0] == '#' {
			continue
		}
		line, n = l, n+1
	}
	if n == 1 {
		if raw, err := base64.StdEncoding.DecodeString(string(line)); err == nil && len(raw) == browserKeySize {
			return raw, nil
		}
	}
	return nil, errors.New("does not hold a sign-in key (one line of base64 for 32 random bytes)")
}

// CookieSuffix stands for account in the name of its cookie. It is not the
// name itself, so the cookies do not show which accounts a browser used.
func (k *BrowserKey) CookieSuffix(account string) string {
	h := hmac.New(sha256.New, k.name)
	h.Write([]byte(normAccount(account)))
	return hex.EncodeToString(h.Sum(nil)[:8])
}

const (
	browserIDSize = 16
	browserValue  = 8 + browserIDSize + sha256.Size
	browserPrefix = "1."
)

// Issue returns a cookie value marking a browser as known for account,
// whose password is at version (anything that changes when the password
// does; "" when Signalith cannot tell).
func (k *BrowserKey) Issue(account, version string, now time.Time) string {
	b := make([]byte, 8+browserIDSize, browserValue)
	binary.BigEndian.PutUint64(b, uint64(now.Unix()))
	if _, err := rand.Read(b[8:]); err != nil {
		panic(err)
	}
	b = k.sign(b, account, version)
	return browserPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// Check returns the browser's id from a cookie value Issue made for
// account and version less than KnownBrowserAge ago.
func (k *BrowserKey) Check(account, version, value string, now time.Time) (string, bool) {
	enc, ok := strings.CutPrefix(value, browserPrefix)
	if !ok || len(enc) != base64.RawURLEncoding.EncodedLen(browserValue) {
		return "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(b) != browserValue {
		return "", false
	}
	want := k.sign(bytes.Clone(b[:8+browserIDSize]), account, version)
	if !hmac.Equal(b, want) {
		return "", false
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(b)), 0)
	if age := now.Sub(issued); age >= KnownBrowserAge || age < -24*time.Hour {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(b[8 : 8+browserIDSize]), true
}

// sign appends the MAC of head (issue time and id), account and version.
func (k *BrowserKey) sign(head []byte, account, version string) []byte {
	h := hmac.New(sha256.New, k.mac)
	h.Write(head)
	acct := normAccount(account)
	h.Write(binary.AppendUvarint(nil, uint64(len(acct))))
	h.Write([]byte(acct))
	v := sha256.Sum256([]byte(version))
	h.Write(v[:])
	return h.Sum(head)
}

func normAccount(account string) string { return strings.ToLower(strings.TrimSpace(account)) }
