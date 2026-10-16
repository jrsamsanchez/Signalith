// Package secrets encrypts the passwords and API keys Signalith stores, so
// that a copy of signalith.yaml or of the server's own files (a backup, a
// support ticket, a Git commit) does not give them away.
//
// Each value is encrypted with AES-256-GCM under a key derived (HKDF with
// SHA-256) from a 32-byte master key, and is bound to the setting it
// belongs to, so it cannot be copied into another setting. An encrypted
// value looks like
//
//	enc:v1:<key id>:<nonce and ciphertext, base64url>
//
// where the key id is a short fingerprint of the master key. Plain values
// are accepted everywhere too, so a password can still be pasted into a
// file by hand; Signalith reports them, and "signalith secrets encrypt"
// encrypts them.
//
// Where the master key comes from is described on Keyring. Losing it loses
// only the stored passwords and keys, which can be entered again, never
// events.
//
// Stores adopt this with one call each way, for a named setting:
//
//	stored, err := secrets.Seal("directory.bind_password", password)
//	password, err := secrets.Open("directory.bind_password", stored)
//
// Decrypted values end up in Go strings, which cannot be wiped, so keys
// and decrypted bytes are cleared where practical but copies may stay in
// memory until it is reused.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Prefix starts every encrypted value; the version follows it.
const Prefix = "enc:"

const (
	version = "v1"
	keySize = 32
	// infoKey and infoID separate the encryption key and the key id
	// derived from one master key.
	infoKey = "signalith secrets v1"
	infoID  = "signalith key id v1"
)

// sealedForm matches the start of an encrypted value of any version:
// enc:v1:, enc:v2: and so on.
var sealedForm = regexp.MustCompile(`^enc:v[0-9]+:`)

// IsSealed reports whether v is an encrypted value rather than plain text:
// it starts with enc:v and a version number, as in enc:v1:. Any other
// text, even one starting with enc:, is a plain value.
func IsSealed(v string) bool { return sealedForm.MatchString(v) }

// KeyID returns the id of the master key an encrypted value was made
// with, or "" for plain text or a damaged value.
func KeyID(stored string) string {
	id, _, err := parse(stored)
	if err != nil {
		return ""
	}
	return id
}

// masterKey is a master key ready to use; the key itself is not kept.
type masterKey struct {
	id   string
	aead cipher.AEAD
}

// newMasterKey derives the encryption key and the key id from raw. The
// caller clears raw.
func newMasterKey(raw []byte) (*masterKey, error) {
	if len(raw) != keySize {
		return nil, fmt.Errorf("a master key is %d bytes, not %d", keySize, len(raw))
	}
	dk, err := hkdf.Key(sha256.New, raw, nil, infoKey, 32)
	if err != nil {
		return nil, err
	}
	defer clear(dk)
	idb, err := hkdf.Key(sha256.New, raw, nil, infoID, 4)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &masterKey{id: hex.EncodeToString(idb), aead: aead}, nil
}

// aad binds a value to its key and its setting.
func aad(id, field string) []byte {
	return []byte("signalith:" + version + ":" + id + ":" + field)
}

func (m *masterKey) seal(field, plain string) (string, error) {
	ns := m.aead.NonceSize()
	pt := []byte(plain)
	defer clear(pt)
	buf := make([]byte, ns, ns+len(pt)+m.aead.Overhead())
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := m.aead.Seal(buf, buf[:ns], pt, aad(m.id, field))
	return Prefix + version + ":" + m.id + ":" + base64.RawURLEncoding.EncodeToString(out), nil
}

func (m *masterKey) open(field string, blob []byte) (string, bool) {
	ns := m.aead.NonceSize()
	if len(blob) < ns+m.aead.Overhead() {
		return "", false
	}
	pt, err := m.aead.Open(nil, blob[:ns], blob[ns:], aad(m.id, field))
	if err != nil {
		return "", false
	}
	defer clear(pt)
	return string(pt), true
}

// parse splits an encrypted value into its key id and its bytes.
func parse(stored string) (id string, blob []byte, err error) {
	rest, ok := strings.CutPrefix(stored, Prefix+version+":")
	if !ok {
		if IsSealed(stored) {
			return "", nil, errors.New("it was encrypted by a newer version of Signalith")
		}
		return "", nil, errors.New("it is not encrypted")
	}
	id, data, ok := strings.Cut(rest, ":")
	if !ok || len(id) != 8 {
		return "", nil, errors.New("it is damaged")
	}
	blob, err = base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return "", nil, errors.New("it is damaged")
	}
	return id, blob, nil
}

// OpenError is an encrypted value that cannot be decrypted.
type OpenError struct {
	// Field is the setting the value belongs to.
	Field string
	// KeyID is the master key it was encrypted with; "" when the value is
	// damaged.
	KeyID string
	// Have is the master key in use and Where says where it comes from;
	// both "" when no master key was found.
	Have, Where string
	// Reason is set when the value itself is the problem: damaged,
	// changed, or copied from another setting.
	Reason string
	// Key names the kind of key, such as "cluster key", when it is not
	// the master key (see Key).
	Key string
}

func (e *OpenError) Error() string {
	switch {
	case e.Key != "" && e.Reason == "":
		return fmt.Sprintf("%s is encrypted with %s %s, but the %s here is %s. Enter the value again", e.Field, e.Key, e.KeyID, e.Key, e.Have)
	case e.Reason != "":
		// The master key is there; the value itself is the problem.
		return fmt.Sprintf("%s cannot be decrypted: %s. Enter the value again", e.Field, e.Reason)
	case e.Have == "":
		return fmt.Sprintf("%s is encrypted with master key %s, but no master key was found. %s", e.Field, e.KeyID, restoreKey)
	}
	return fmt.Sprintf("%s is encrypted with master key %s, but the master key here is %s (%s). %s", e.Field, e.KeyID, e.Have, e.Where, restoreKey)
}

// restoreKey says how to fix a value encrypted with a master key that is
// not here.
const restoreKey = "Restore the master key it was encrypted with, or enter the value again; " +
	"without that key only stored passwords and keys are lost, never events"

// State is how a stored value is kept.
type State int

const (
	// Plain is stored as plain text.
	Plain State = iota
	// Current is encrypted with the master key in use.
	Current
	// Previous is encrypted with the previous master key, kept after
	// "signalith secrets rotate-master" until nothing uses it.
	Previous
	// Unreadable is encrypted but cannot be decrypted here.
	Unreadable
)

func (s State) String() string {
	switch s {
	case Plain:
		return "plain text"
	case Current:
		return "encrypted"
	case Previous:
		return "encrypted with the previous master key"
	}
	return "cannot be decrypted"
}

// Stored is one secret value as a file holds it.
type Stored struct {
	// Field is the setting it is encrypted for, such as
	// opensearch.password.
	Field string
	// Label names it for people, such as "header X-OTX-API-KEY of feed otx".
	Label string
	// Value is as stored: plain text or an encrypted value.
	Value string
}

// Reseal returns the value to store instead of s.Value; returning s.Value
// leaves it as it is. Files that hold secrets offer a function that
// rewrites each of them through a Reseal, which is how "signalith secrets"
// encrypts, re-encrypts and lists them.
type Reseal func(s Stored) (string, error)

var (
	defaultMu      sync.RWMutex
	defaultKeyring = NewKeyring()
)

// SetDefault sets the keyring Seal and Open use. The server and the CLI
// set it once the config is loaded; until then only a master key from the
// environment is found.
func SetDefault(k *Keyring) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultKeyring = k
}

// Default returns the keyring Seal and Open use.
func Default() *Keyring {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultKeyring
}

// Seal encrypts plain for the setting field with the default keyring,
// making a master key on first need. Empty and already encrypted values
// are returned as they are (see IsSealed).
func Seal(field, plain string) (string, error) { return Default().Seal(field, plain) }

// Open decrypts a value stored for the setting field with the default
// keyring. Plain text is returned as it is.
func Open(field, stored string) (string, error) { return Default().Open(field, stored) }
